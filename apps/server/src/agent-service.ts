import { randomUUID } from "node:crypto";
import type { AppConfig } from "./config.js";
import { isArkConfigured } from "./config.js";
import { EffectGateway, type StagedRun } from "./effect-gateway.js";
import {
  combineDecision,
  computeRunManifestDigest,
  EXTERNAL_EFFECT_OUTBOX,
  ExternalEffectGateway,
  type ExternalEffectPlan,
} from "./external-effect-gateway.js";
import { HttpError, RunCancelledError } from "./errors.js";
import { redactSecurityText } from "./redaction.js";
import {
  agentPrincipalId,
  issueRunSecurityContext,
  LOCAL_OPERATOR_ID,
} from "./identity-delegation.js";
import {
  createSecurityModuleRegistry,
  SecurityEventBus,
  type SecurityModule,
  type SecurityModuleRegistry,
} from "./security-modules.js";
import type { SecurityEventInput, SecurityEventQuery } from "./security-ledger.js";
import { JsonStore } from "./store.js";
import type {
  Agent,
  AgentRun,
  AgentRunner,
  Approval,
  CreateAgentInput,
  Message,
  UpdateAgentInput,
} from "./types.js";
import { WorkspaceManager } from "./workspace.js";

const now = () => new Date().toISOString();

export class AgentService {
  private readonly activeExecutions = new Map<string, Promise<void>>();
  private readonly cancellationRequests = new Set<string>();
  private readonly modules: SecurityModuleRegistry;
  private readonly events: SecurityEventBus;

  constructor(
    private readonly config: AppConfig,
    private readonly store: JsonStore,
    private readonly workspaces: WorkspaceManager,
    private readonly runner: AgentRunner,
    private readonly security: EffectGateway = new EffectGateway(config),
    private readonly externalSecurity: ExternalEffectGateway = new ExternalEffectGateway(config),
    modules?: SecurityModuleRegistry,
  ) {
    this.modules = modules ?? createSecurityModuleRegistry(config);
    this.events = new SecurityEventBus(this.modules, this.security.ledger);
  }

  async initialize(): Promise<void> {
    await this.store.initialize();
    await this.workspaces.initialize();
    await this.security.initialize();
    await this.security.cleanupAllStaging();
    for (const agent of this.store.snapshot().agents) {
      await this.workspaces.writeInstructions(agent);
    }
    await this.store.mutate((database) => {
      for (const run of database.runs) {
        if (
          [
            "queued",
            "running",
            "reviewing_effects",
            "awaiting_approval",
            "committing",
            "rolling_back",
          ].includes(run.status)
        ) {
          run.status = "rolled_back";
          run.error = "Server restarted while this secured run was active; staging was discarded";
          run.securitySummary = "Recovered safely after restart; no staged effect was committed";
          run.completedAt = now();
        }
      }
      for (const approval of database.approvals) {
        if (approval.status === "pending") {
          approval.status = "expired";
          approval.decidedAt = now();
        }
      }
      for (const agent of database.agents) {
        if (agent.status === "busy") {
          agent.status = "ready";
          agent.updatedAt = now();
        }
      }
    });
    await this.publishSecurityEvent({
      type: "service.initialized",
      moduleId: "runtime-containment",
      stage: "verify",
      severity: "info",
      reason: "Startup recovery completed and orphan staging was removed",
    });
    const identity = this.identityInfo();
    await this.publishSecurityEvent({
      type: "identity.control_plane_ready",
      moduleId: "identity-delegation",
      stage: "identity",
      severity: "info",
      humanId: identity.currentHuman?.id ?? null,
      reason: "Trusted control plane loaded Human and Agent principal attribution",
      payload: {
        human: identity.currentHuman?.displayName ?? null,
        agentPrincipals: identity.agents.length,
      },
    });
    await this.publishSecurityEvent({
      type: "ledger.verified",
      moduleId: "audit-ledger",
      stage: "verify",
      severity: "info",
      reason: "HMAC chain integrity was verified before accepting new Runs",
    });
  }

  registerSecurityModule(module: SecurityModule): this {
    this.modules.register(module);
    return this;
  }

  listAgents(): Agent[] {
    return this.store
      .snapshot()
      .agents.sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  getAgent(id: string): Agent {
    const agent = this.store.snapshot().agents.find((item) => item.id === id);
    if (!agent) {
      throw new HttpError(404, "Agent not found");
    }
    return agent;
  }

  async createAgent(input: CreateAgentInput): Promise<Agent> {
    const timestamp = now();
    const id = randomUUID();
    const agent: Agent = {
      id,
      name: input.name.trim(),
      description: input.description?.trim() ?? "",
      instructions: input.instructions?.trim() ?? "",
      status: "ready",
      ownerHumanId: LOCAL_OPERATOR_ID,
      principalId: agentPrincipalId(id),
      principalStatus: "active",
      workspacePath: this.workspaces.workspacePath(id),
      codexThreadId: null,
      lastError: null,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    await this.workspaces.create(agent);
    await this.store.mutate((database) => database.agents.push(agent));
    await this.publishSecurityEvent({
      type: "identity.agent_provisioned",
      moduleId: "identity-delegation",
      stage: "identity",
      severity: "info",
      humanId: agent.ownerHumanId,
      agentPrincipalId: agent.principalId,
      agentId: agent.id,
      reason: "A distinct Agent principal was linked to its Human owner",
      payload: { principalStatus: agent.principalStatus },
    });
    return agent;
  }

  async updateAgent(id: string, input: UpdateAgentInput): Promise<Agent> {
    const current = this.getAgent(id);
    if (current.status === "busy") {
      throw new HttpError(409, "Stop the active run before editing this Agent");
    }
    const updated = await this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      if (agent.status === "busy") {
        throw new HttpError(409, "Stop the active run before editing this Agent");
      }
      if (input.name !== undefined) agent.name = input.name.trim();
      if (input.description !== undefined) agent.description = input.description.trim();
      if (input.instructions !== undefined) agent.instructions = input.instructions.trim();
      agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
    await this.workspaces.writeInstructions(updated);
    return updated;
  }

  async deleteAgent(id: string): Promise<{ archivedWorkspace: string }> {
    const agent = this.getAgent(id);
    await this.cancelExecution(id);
    await this.cancelPendingApproval(id, "Agent deleted by user");
    const archivedWorkspace = await this.workspaces.archive(agent);
    await this.store.mutate((database) => {
      database.agents = database.agents.filter((item) => item.id !== id);
      database.messages = database.messages.filter((item) => item.agentId !== id);
      database.runs = database.runs.filter((item) => item.agentId !== id);
      database.approvals = database.approvals.filter((item) => item.agentId !== id);
      database.runSecurityContexts = database.runSecurityContexts.filter(
        (item) => item.agentId !== id,
      );
    });
    return { archivedWorkspace };
  }

  async startAgent(id: string): Promise<Agent> {
    const agent = await this.setStatus(id, "ready");
    await this.publishSecurityEvent({
      type: "identity.agent_activated",
      moduleId: "identity-delegation",
      stage: "identity",
      severity: "info",
      humanId: agent.ownerHumanId,
      agentPrincipalId: agent.principalId,
      agentId: agent.id,
      reason: "Human operator activated the Agent principal",
    });
    return agent;
  }

  async stopAgent(id: string): Promise<Agent> {
    this.getAgent(id);
    await this.cancelExecution(id);
    await this.cancelPendingApproval(id, "Agent stopped by user");
    const agent = await this.setStatus(id, "stopped");
    await this.publishSecurityEvent({
      type: "identity.agent_revoked",
      moduleId: "identity-delegation",
      stage: "identity",
      severity: "medium",
      humanId: agent.ownerHumanId,
      agentPrincipalId: agent.principalId,
      agentId: agent.id,
      decision: "revoked",
      reason: "Human operator stopped the Agent and revoked future Run capabilities",
    });
    return agent;
  }

  getMessages(agentId: string): Message[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .messages.filter((message) => message.agentId === agentId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  getRun(runId: string): AgentRun {
    const run = this.store.snapshot().runs.find((item) => item.id === runId);
    if (!run) {
      throw new HttpError(404, "Run not found");
    }
    return run;
  }

  getRuns(agentId: string): AgentRun[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .runs.filter((run) => run.agentId === agentId)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  getApprovals(status?: Approval["status"]): Approval[] {
    return this.store
      .snapshot()
      .approvals.filter((approval) => !status || approval.status === status)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  async getApprovalDetails(approvalId: string) {
    const approval = this.getApproval(approvalId);
    const run = this.getRun(approval.runId);
    const agent = this.getAgent(approval.agentId);
    const staged = this.security.pathsFor(run.id);
    const previews =
      approval.status === "pending"
        ? await this.security.createEffectPreviews(
            agent.workspacePath,
            staged.workspacePath,
            run.effects,
          )
        : [];
    const currentWorkspaceHash = await this.security.workspaceDigest(agent.workspacePath);
    return { approval, run, previews, currentWorkspaceHash };
  }

  async verifyLedger() {
    return this.security.ledger.verify();
  }

  identityInfo() {
    const snapshot = this.store.snapshot();
    return {
      currentHuman: snapshot.humans.find((human) => human.id === LOCAL_OPERATOR_ID) ?? null,
      agents: snapshot.agents.map((agent) => ({
        agentId: agent.id,
        principalId: agent.principalId,
        ownerHumanId: agent.ownerHumanId,
        status: agent.principalStatus,
      })),
    };
  }

  async securityEvents(query: SecurityEventQuery = {}) {
    const snapshot = this.store.snapshot();
    const agents = new Map(snapshot.agents.map((agent) => [agent.id, agent]));
    const runs = new Map(snapshot.runs.map((run) => [run.id, run]));
    const events = await this.security.ledger.list(query);
    return events.map((event) => ({
      ...event,
      agentName: event.agentId ? agents.get(event.agentId)?.name ?? "Deleted Agent" : null,
      runStatus: event.runId ? runs.get(event.runId)?.status ?? null : null,
      runPrompt: event.runId ? runs.get(event.runId)?.prompt ?? null : null,
    }));
  }

  async securityOverview() {
    const snapshot = this.store.snapshot();
    const [verification, recentEvents, allEvents] = await Promise.all([
      this.verifyLedger(),
      this.securityEvents({ limit: 80 }),
      this.security.ledger.list({ limit: 1_000 }),
    ]);
    const effects = snapshot.runs.flatMap((run) => [...run.effects, ...run.externalEffects]);
    const moduleHits = new Map<string, number>();
    for (const event of allEvents) {
      const id = event.moduleId ?? "audit-ledger";
      moduleHits.set(id, (moduleHits.get(id) ?? 0) + 1);
    }
    return {
      generatedAt: now(),
      posture: verification.valid ? "protected" : "degraded",
      scope: "Persistent workspace effects and declared external HTTP actions",
      totals: {
        agents: snapshot.agents.length,
        runs: snapshot.runs.length,
        effects: effects.length,
        blocked: effects.filter((effect) => effect.decision === "deny").length,
        awaitingApproval: snapshot.approvals.filter((item) => item.status === "pending").length,
        rolledBack: snapshot.runs.filter((run) => run.status === "rolled_back").length,
        externalExecuted: snapshot.runs
          .flatMap((run) => run.externalEffects)
          .filter((effect) => effect.status === "executed").length,
      },
      ledger: verification,
      identity: {
        humans: snapshot.humans.length,
        activeAgentPrincipals: snapshot.agents.filter(
          (agent) => agent.principalStatus === "active",
        ).length,
        issuedCapabilities: snapshot.runSecurityContexts.length,
      },
      modules: this.modules.list().map((module) => ({
        ...module,
        events: moduleHits.get(module.id) ?? 0,
      })),
      recentEvents,
    };
  }

  async approveApproval(approvalId: string): Promise<{ approval: Approval; run: AgentRun }> {
    const approval = this.getApproval(approvalId);
    if (approval.status !== "pending") {
      throw new HttpError(409, "Approval is no longer pending");
    }
    if (Date.parse(approval.expiresAt) <= Date.now()) {
      await this.expireApproval(approvalId, "Approval expired before it was used");
      throw new HttpError(409, "Approval expired");
    }
    const run = this.getRun(approval.runId);
    const agent = this.getAgent(approval.agentId);
    const securityContext = this.getRunSecurityContext(run.id);
    if (run.status !== "awaiting_approval") {
      throw new HttpError(409, "Run is not awaiting approval");
    }
    const staged = this.security.pathsFor(run.id);
    const manifest = await this.collectSecuredManifest(
      run.id,
      agent.workspacePath,
      staged.workspacePath,
    );
    if (
      manifest.manifestDigest !== approval.manifestDigest ||
      approval.policyVersion !== this.modules.policyVersion()
    ) {
      await this.expireApproval(
        approvalId,
        "Manifest digest or policy version changed after approval was requested",
      );
      throw new HttpError(409, "Approval binding failed; the staged effects were rolled back");
    }

    await this.store.mutate((database) => {
      const storedApproval = database.approvals.find((item) => item.id === approvalId);
      const storedRun = database.runs.find((item) => item.id === run.id);
      if (!storedApproval || storedApproval.status !== "pending" || !storedRun) {
        throw new HttpError(409, "Approval changed concurrently");
      }
      storedApproval.status = "approved";
      storedApproval.decidedAt = now();
      storedApproval.approvedBy = securityContext.humanId;
      storedRun.status = "committing";
    });
    await this.publishSecurityEvent({
      type: "approval.approved",
      moduleId: "approval-manager",
      stage: "approval",
      severity: "medium",
      agentId: agent.id,
      runId: run.id,
      decision: "approved",
      payload: { approvalId, manifestDigest: approval.manifestDigest },
    });
    try {
      await this.applySecuredManifest(
        run.id,
        agent,
        staged,
        manifest.fileEffects,
        manifest.externalPlan,
        "Approved effects committed",
      );
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      await this.finishRolledBack(run.id, "Commit failed and snapshot was restored: " + reason);
      throw new HttpError(409, "Commit failed; protected state was restored");
    }
    return { approval: this.getApproval(approvalId), run: this.getRun(run.id) };
  }

  async denyApproval(approvalId: string): Promise<{ approval: Approval; run: AgentRun }> {
    const approval = this.getApproval(approvalId);
    if (approval.status !== "pending") {
      throw new HttpError(409, "Approval is no longer pending");
    }
    await this.store.mutate((database) => {
      const storedApproval = database.approvals.find((item) => item.id === approvalId);
      const storedRun = database.runs.find((item) => item.id === approval.runId);
      if (!storedApproval || storedApproval.status !== "pending" || !storedRun) {
        throw new HttpError(409, "Approval changed concurrently");
      }
      storedApproval.status = "denied";
      storedApproval.decidedAt = now();
      storedRun.status = "rolling_back";
    });
    await this.publishSecurityEvent({
      type: "approval.denied",
      moduleId: "approval-manager",
      stage: "approval",
      severity: "high",
      agentId: approval.agentId,
      runId: approval.runId,
      decision: "denied",
      payload: { approvalId },
    });
    await this.finishRolledBack(approval.runId, "Human denied the digest-bound effect manifest");
    return { approval: this.getApproval(approvalId), run: this.getRun(approval.runId) };
  }

  async sendMessage(
    agentId: string,
    prompt: string,
  ): Promise<{ run: AgentRun; message: Message }> {
    if (!isArkConfigured(this.config)) {
      throw new HttpError(
        503,
        "Ark is not configured. Set ARK_API_KEY and ARK_MODEL, then restart.",
      );
    }
    const timestamp = now();
    const runId = randomUUID();
    const safePrompt = redactSecurityText(prompt, this.config);
    const agentForContext = this.getAgent(agentId);
    if (agentForContext.status === "stopped" || agentForContext.principalStatus !== "active") {
      throw new HttpError(409, "Start the Agent before sending a message");
    }
    const securityContext = issueRunSecurityContext(
      agentForContext,
      runId,
      this.config.codexTimeoutMs + 15 * 60_000 + 60_000,
    );
    const run: AgentRun = {
      id: runId,
      agentId,
      status: "queued",
      prompt: safePrompt,
      output: null,
      error: null,
      usage: null,
      effects: [],
      externalEffects: [],
      trace: [],
      manifestDigest: null,
      policyVersion: null,
      approvalId: null,
      securityContextId: securityContext.id,
      securitySummary: null,
      workspaceHashBefore: null,
      workspaceHashAfter: null,
      pendingThreadId: null,
      startedAt: null,
      completedAt: null,
      createdAt: timestamp,
    };
    const message: Message = {
      id: randomUUID(),
      agentId,
      runId,
      role: "user",
      content: safePrompt,
      createdAt: timestamp,
    };
    const agentAtStart = await this.store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agentId);
      if (!storedAgent) {
        throw new HttpError(404, "Agent not found");
      }
      if (storedAgent.status === "stopped") {
        throw new HttpError(409, "Start the Agent before sending a message");
      }
      if (storedAgent.status === "busy") {
        throw new HttpError(409, "This Agent is already running");
      }
      database.runs.push(run);
      database.messages.push(message);
      database.runSecurityContexts.push(securityContext);
      const snapshot = structuredClone(storedAgent);
      storedAgent.status = "busy";
      storedAgent.lastError = null;
      storedAgent.updatedAt = timestamp;
      return snapshot;
    });
    await this.publishSecurityEvent({
      type: "identity.delegation_issued",
      moduleId: "identity-delegation",
      stage: "identity",
      severity: "info",
      humanId: securityContext.humanId,
      agentPrincipalId: securityContext.agentPrincipalId,
      agentId,
      runId,
      decision: "issued",
      reason: "A time-limited Run capability was derived by the control plane",
      payload: {
        contextId: securityContext.id,
        scopes: securityContext.scopes,
        policyProfile: securityContext.policyProfile,
        expiresAt: securityContext.expiresAt,
      },
    });
    const execution = this.executeRun(agentAtStart, { ...run, prompt });
    this.activeExecutions.set(agentId, execution);
    void execution
      .finally(() => {
        if (this.activeExecutions.get(agentId) === execution) {
          this.activeExecutions.delete(agentId);
        }
      })
      .catch(() => undefined);
    return { run, message };
  }

  async systemInfo(): Promise<Record<string, unknown>> {
    return {
      arkConfigured: isArkConfigured(this.config),
      arkBaseUrl: this.config.arkBaseUrl,
      arkModel: this.config.arkModel || null,
      codexAvailable: await this.runner.isAvailable(),
      codexSandboxMode: this.config.codexSandboxMode,
      runtimeProvider: this.config.runtimeProvider,
      containerEngine:
        this.config.runtimeProvider === "container"
          ? this.config.containerEngine
          : null,
      runtime:
        this.config.runtimeProvider === "container"
          ? "Codex CLI in " + this.config.containerEngine + " Runtime"
          : "Codex CLI in application container",
      externalHttpGatewayEnabled: this.config.httpEffectAllowlist.length > 0,
      externalHttpAllowlist: this.config.httpEffectAllowlist,
    };
  }

  private async executeRun(agentAtStart: Agent, run: AgentRun): Promise<void> {
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === run.id);
      if (storedRun) {
        storedRun.status = "running";
        storedRun.startedAt = now();
      }
    });
    let staged: StagedRun | null = null;
    try {
      if (this.cancellationRequests.has(agentAtStart.id)) {
        throw new RunCancelledError();
      }
      const workspaceHashBefore = await this.security.workspaceDigest(
        agentAtStart.workspacePath,
      );
      staged = await this.security.prepareRun(
        run.id,
        agentAtStart.id,
        agentAtStart.workspacePath,
      );
      const stagedBaselineHash = await this.security.workspaceDigest(staged.workspacePath);
      if (workspaceHashBefore !== stagedBaselineHash) {
        throw new Error("Workspace changed while the secured staging copy was created");
      }
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        if (storedRun) storedRun.workspaceHashBefore = workspaceHashBefore;
      });
      await this.publishSecurityEvent({
        type: "run.staged",
        moduleId: "runtime-containment",
        stage: "runtime",
        severity: "info",
        agentId: agentAtStart.id,
        runId: run.id,
        reason: "Runtime received disposable workspace and Codex Home copies",
      });
      const result = await this.runner.run({
        runId: run.id,
        agentId: agentAtStart.id,
        workspacePath: staged.workspacePath,
        codexHomePath: staged.codexHomePath,
        prompt: run.prompt,
        threadId: agentAtStart.codexThreadId,
      });
      const safeOutput = redactSecurityText(result.output, this.config);
      const safeTrace = result.trace.map((event) => ({
        ...event,
        summary: redactSecurityText(event.summary, this.config),
        resources: event.resources.map((resource) =>
          redactSecurityText(resource, this.config),
        ),
      }));
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        if (!storedRun) return;
        storedRun.status = "reviewing_effects";
        storedRun.output = safeOutput;
        storedRun.usage = result.usage;
        storedRun.pendingThreadId = result.threadId;
        storedRun.trace = safeTrace.map((event) => ({
          ...event,
          id: randomUUID(),
          runId: run.id,
          createdAt: now(),
        }));
      });
      for (const event of safeTrace) {
        await this.publishSecurityEvent({
          type: "runtime." + event.type,
          moduleId: "trace-correlation",
          stage: "runtime",
          severity: event.exitCode && event.exitCode !== 0 ? "medium" : "info",
          agentId: agentAtStart.id,
          runId: run.id,
          reason: event.summary,
          payload: {
            traceType: event.type,
            summary: event.summary,
            resources: event.resources,
            exitCode: event.exitCode,
          },
        });
      }
      const manifest = await this.collectSecuredManifest(
        run.id,
        agentAtStart.workspacePath,
        staged.workspacePath,
      );
      const policyVersion = this.modules.policyVersion();
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        if (!storedRun) return;
        storedRun.effects = manifest.fileEffects;
        storedRun.externalEffects = manifest.externalPlan.effects;
        storedRun.manifestDigest = manifest.manifestDigest;
        storedRun.policyVersion = policyVersion;
      });
      const stagingWorkspacePath = staged.workspacePath;
      const tracedResources = new Set(
        safeTrace
          .filter((event) => event.type === "file_change")
          .flatMap((event) => event.resources)
          .map((resource) => this.normalizeTraceResource(resource, stagingWorkspacePath))
          .filter(
            (resource): resource is string =>
              resource !== null && resource !== EXTERNAL_EFFECT_OUTBOX,
          ),
      );
      const measuredResources = new Set(manifest.fileEffects.map((effect) => effect.resource));
      if (
        tracedResources.size > 0 &&
        (tracedResources.size !== measuredResources.size ||
          [...tracedResources].some((resource) => !measuredResources.has(resource)))
      ) {
        await this.publishSecurityEvent({
          type: "trace.mismatch",
          moduleId: "trace-correlation",
          stage: "verify",
          severity: "high",
          agentId: agentAtStart.id,
          runId: run.id,
          reason: "Untrusted Runtime trace did not match the platform-measured workspace diff",
          payload: {
            tracedResources: [...tracedResources].sort(),
            measuredResources: [...measuredResources].sort(),
          },
        });
      }
      for (const effect of manifest.fileEffects) {
        await this.publishSecurityEvent({
          type: "effect.reviewed",
          moduleId: "filesystem-effects",
          stage: "policy",
          severity:
            effect.decision === "deny"
              ? "high"
              : effect.decision === "require_approval"
                ? "medium"
                : "info",
          agentId: agentAtStart.id,
          runId: run.id,
          effectId: effect.id,
          decision: effect.decision,
          ruleId: effect.ruleId,
          reason: effect.reason,
          payload: {
            type: effect.type,
            resource: effect.resource,
            beforeHash: effect.beforeHash,
            afterHash: effect.afterHash,
            size: effect.size,
          },
        });
      }
      for (const effect of manifest.externalPlan.effects) {
        await this.publishSecurityEvent({
          type: "external_effect.reviewed",
          moduleId: "external-http",
          stage: "policy",
          severity:
            effect.decision === "deny"
              ? "high"
              : effect.decision === "require_approval"
                ? "medium"
                : "info",
          agentId: agentAtStart.id,
          runId: run.id,
          effectId: effect.id,
          decision: effect.decision,
          ruleId: effect.ruleId,
          reason: effect.reason,
          payload: {
            method: effect.method,
            url: effect.url,
            requestDigest: effect.requestDigest,
            bodyHash: effect.bodyHash,
          },
        });
      }

      if (manifest.decision === "deny") {
        const deniedResources = [
          ...manifest.fileEffects,
          ...manifest.externalPlan.effects,
        ]
          .filter((effect) => effect.decision === "deny")
          .map((effect) => effect.resource);
        await this.finishRolledBack(
          run.id,
          "Policy denied the manifest: " + deniedResources.join(", "),
        );
        return;
      }
      if (manifest.decision === "require_approval") {
        const approval: Approval = {
          id: randomUUID(),
          agentId: agentAtStart.id,
          runId: run.id,
          status: "pending",
          manifestDigest: manifest.manifestDigest,
          policyVersion,
          expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
          decidedAt: null,
          approvedBy: null,
          createdAt: now(),
        };
        await this.store.mutate((database) => {
          const storedRun = database.runs.find((item) => item.id === run.id);
          if (!storedRun) return;
          storedRun.status = "awaiting_approval";
          storedRun.approvalId = approval.id;
          storedRun.securitySummary = "Effects are staged and bound to a pending approval digest";
          database.approvals.push(approval);
        });
        await this.publishSecurityEvent({
          type: "approval.requested",
          moduleId: "approval-manager",
          stage: "approval",
          severity: "medium",
          agentId: agentAtStart.id,
          runId: run.id,
          decision: "require_approval",
          payload: {
            approvalId: approval.id,
            manifestDigest: approval.manifestDigest,
            expiresAt: approval.expiresAt,
          },
        });
        const timer = setTimeout(
          () => void this.expireApproval(approval.id, "Approval TTL elapsed"),
          15 * 60_000,
        );
        timer.unref();
        return;
      }

      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        if (storedRun) storedRun.status = "committing";
      });
      await this.applySecuredManifest(
        run.id,
        agentAtStart,
        staged,
        manifest.fileEffects,
        manifest.externalPlan,
        "All effects matched deterministic allow rules",
      );
    } catch (error) {
      if (staged) await this.security.rollback(run.id);
      const cancelled = error instanceof RunCancelledError;
      const message = redactSecurityText(
        error instanceof Error ? error.message : String(error),
        this.config,
      );
      if (
        ["reviewing_effects", "committing", "rolling_back"].includes(
          this.getRun(run.id).status,
        )
      ) {
        await this.finishRolledBack(run.id, "Security review or commit failed: " + message);
        return;
      }
      const completedAt = now();
      const workspaceHashAfter = await this.security.workspaceDigest(
        agentAtStart.workspacePath,
      );
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        const agent = database.agents.find((item) => item.id === agentAtStart.id);
        if (storedRun) {
          storedRun.status = cancelled ? "cancelled" : "failed";
          storedRun.error = message;
          storedRun.securitySummary = "Staging was discarded before any protected state changed";
          storedRun.workspaceHashAfter = workspaceHashAfter;
          storedRun.completedAt = completedAt;
        }
        if (agent) {
          if (agent.status !== "stopped") {
            agent.status = cancelled ? "ready" : "error";
          }
          agent.lastError = cancelled ? null : message;
          agent.updatedAt = completedAt;
        }
      });
      await this.publishSecurityEvent({
        type: cancelled ? "run.cancelled" : "run.failed",
        moduleId: "runtime-containment",
        stage: "recover",
        severity: cancelled ? "medium" : "high",
        agentId: agentAtStart.id,
        runId: run.id,
        reason: message,
      });
      await this.revokeRunCapability(run.id, cancelled ? "Run cancelled" : "Run failed");
    }
  }

  private async collectSecuredManifest(
    runId: string,
    workspacePath: string,
    stagedWorkspacePath: string,
  ) {
    const [fileManifest, collectedExternalPlan] = await Promise.all([
      this.security.collectManifest(
        runId,
        workspacePath,
        stagedWorkspacePath,
        [EXTERNAL_EFFECT_OUTBOX],
      ),
      this.externalSecurity.collect(runId, stagedWorkspacePath),
    ]);
    const initialExternalPlan =
      fileManifest.effects.length > 0 && collectedExternalPlan.effects.length > 0
        ? this.externalSecurity.denyMixedDomains(collectedExternalPlan)
        : collectedExternalPlan;
    const context = this.getRunSecurityContext(runId);
    const [fileEffects, externalEffects] = await Promise.all([
      Promise.all(
        fileManifest.effects.map((effect) => this.modules.reviewEffect(effect, context)),
      ),
      Promise.all(
        initialExternalPlan.effects.map((effect) => this.modules.reviewEffect(effect, context)),
      ),
    ]);
    const externalPlan = {
      ...initialExternalPlan,
      effects: externalEffects.map((effect) => ({
        ...effect,
        bodyPreview: effect.bodyPreview
          ? redactSecurityText(effect.bodyPreview, this.config)
          : null,
      })),
    };
    return {
      fileEffects,
      externalPlan,
      decision: combineDecision(fileEffects, externalPlan.effects),
      manifestDigest: computeRunManifestDigest(
        fileEffects,
        externalPlan.effects,
      ),
    };
  }

  private async applySecuredManifest(
    runId: string,
    agent: Agent,
    staged: StagedRun,
    fileEffects: AgentRun["effects"],
    externalPlan: ExternalEffectPlan,
    summary: string,
  ): Promise<void> {
    if (externalPlan.effects.length === 0) {
      await this.security.commit(
        runId,
        agent.id,
        agent.workspacePath,
        staged,
        fileEffects,
        [EXTERNAL_EFFECT_OUTBOX],
      );
      await this.finishCompleted(runId, summary);
      return;
    }

    await this.externalSecurity.removeOutbox(staged.workspacePath);
    await this.security.commit(
      runId,
      agent.id,
      agent.workspacePath,
      staged,
      fileEffects,
      [EXTERNAL_EFFECT_OUTBOX],
    );
    const executed = await this.externalSecurity.execute(externalPlan);
    const safeExecuted = executed.map((effect) => ({
      ...effect,
      error: effect.error ? redactSecurityText(effect.error, this.config) : null,
      receipt: effect.receipt
        ? {
            ...effect.receipt,
            bodyPreview: redactSecurityText(effect.receipt.bodyPreview, this.config),
          }
        : null,
    }));
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === runId);
      if (storedRun) storedRun.externalEffects = safeExecuted;
    });
    for (const effect of safeExecuted) {
      await this.publishSecurityEvent({
        type:
          effect.status === "executed"
            ? "external_effect.executed"
            : "external_effect.execution_uncertain",
        moduleId: "external-http",
        stage: "execute",
        severity: effect.status === "executed" ? "info" : "critical",
        agentId: agent.id,
        runId,
        effectId: effect.id,
        decision: effect.status,
        reason: effect.error ?? effect.reason,
        payload: {
          method: effect.method,
          url: effect.url,
          requestDigest: effect.requestDigest,
          statusCode: effect.receipt?.statusCode ?? null,
          responseHash: effect.receipt?.responseHash ?? null,
          executedAt: effect.receipt?.executedAt ?? null,
        },
      });
    }
    const uncertain = safeExecuted.find((effect) => effect.status === "uncertain");
    if (uncertain) {
      await this.finishExternalUncertain(
        runId,
        "External request outcome is uncertain; do not retry without checking the target service: " +
          (uncertain.error ?? uncertain.resource),
      );
      return;
    }
    await this.finishCompleted(runId, summary + "; external HTTP effect executed by AEG");
  }

  private async finishExternalUncertain(runId: string, summary: string): Promise<void> {
    const completedAt = now();
    const run = this.getRun(runId);
    const agentSnapshot = this.getAgent(run.agentId);
    const workspaceHashAfter = await this.security.workspaceDigest(agentSnapshot.workspacePath);
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === runId);
      const agent = database.agents.find((item) => item.id === run.agentId);
      if (!storedRun || !agent) return;
      storedRun.status = "failed";
      storedRun.error = summary;
      storedRun.securitySummary = summary;
      storedRun.workspaceHashAfter = workspaceHashAfter;
      storedRun.completedAt = completedAt;
      const response = [storedRun.output, "[AEG] " + summary].filter(Boolean).join("\n\n");
      storedRun.output = response;
      if (
        !database.messages.some(
          (message) => message.runId === runId && message.role === "assistant",
        )
      ) {
        database.messages.push({
          id: randomUUID(),
          agentId: agent.id,
          runId,
          role: "assistant",
          content: response,
          createdAt: completedAt,
        });
      }
      agent.status = "ready";
      agent.codexThreadId = storedRun.pendingThreadId;
      agent.lastError = summary;
      agent.updatedAt = completedAt;
    });
    await this.publishSecurityEvent({
      type: "run.external_outcome_uncertain",
      moduleId: "external-http",
      stage: "recover",
      severity: "critical",
      agentId: run.agentId,
      runId,
      decision: "uncertain",
      reason: summary,
      payload: { manifestDigest: run.manifestDigest },
    });
    await this.revokeRunCapability(runId, "Run reached a terminal uncertain state");
  }

  private getApproval(id: string): Approval {
    const approval = this.store.snapshot().approvals.find((item) => item.id === id);
    if (!approval) throw new HttpError(404, "Approval not found");
    return approval;
  }

  private async finishCompleted(runId: string, summary: string): Promise<void> {
    const completedAt = now();
    const run = this.getRun(runId);
    const agentSnapshot = this.getAgent(run.agentId);
    const workspaceHashAfter = await this.security.workspaceDigest(agentSnapshot.workspacePath);
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === runId);
      const agent = database.agents.find((item) => item.id === run.agentId);
      if (!storedRun || !agent) return;
      storedRun.status = "completed";
      storedRun.completedAt = completedAt;
      storedRun.securitySummary = summary;
      storedRun.workspaceHashAfter = workspaceHashAfter;
      if (!database.messages.some((message) => message.runId === runId && message.role === "assistant")) {
        database.messages.push({
          id: randomUUID(),
          agentId: agent.id,
          runId,
          role: "assistant",
          content: storedRun.output ?? "Run completed",
          createdAt: completedAt,
        });
      }
      agent.status = "ready";
      agent.codexThreadId = storedRun.pendingThreadId;
      agent.lastError = null;
      agent.updatedAt = completedAt;
    });
    try {
      await this.publishSecurityEvent({
        type: "run.committed",
        moduleId: "filesystem-effects",
        stage: "verify",
        severity: "info",
        agentId: run.agentId,
        runId,
        decision: "allow",
        reason: summary,
        payload: { manifestDigest: run.manifestDigest },
      });
      await this.revokeRunCapability(runId, "Run completed");
    } catch (error) {
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === runId);
        if (storedRun) {
          storedRun.securitySummary =
            summary + "; audit append failed: " +
            (error instanceof Error ? error.message : String(error));
        }
      });
    }
  }

  private async finishRolledBack(runId: string, summary: string): Promise<void> {
    const run = this.getRun(runId);
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === runId);
      if (storedRun) storedRun.status = "rolling_back";
    });
    await this.security.rollback(runId);
    const completedAt = now();
    const agentSnapshot = this.getAgent(run.agentId);
    const workspaceHashAfter = await this.security.workspaceDigest(agentSnapshot.workspacePath);
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === runId);
      const agent = database.agents.find((item) => item.id === run.agentId);
      if (!storedRun || !agent) return;
      storedRun.status = "rolled_back";
      storedRun.completedAt = completedAt;
      storedRun.error = summary;
      storedRun.securitySummary = summary;
      storedRun.workspaceHashAfter = workspaceHashAfter;
      const response = [storedRun.output, "[AEG] " + summary].filter(Boolean).join("\n\n");
      storedRun.output = response;
      if (!database.messages.some((message) => message.runId === runId && message.role === "assistant")) {
        database.messages.push({
          id: randomUUID(),
          agentId: agent.id,
          runId,
          role: "assistant",
          content: response,
          createdAt: completedAt,
        });
      }
      if (agent.status !== "stopped") agent.status = "ready";
      agent.lastError = null;
      agent.updatedAt = completedAt;
    });
    try {
      await this.publishSecurityEvent({
        type: "run.rolled_back",
        moduleId: "filesystem-effects",
        stage: "recover",
        severity: "high",
        agentId: run.agentId,
        runId,
        decision: "deny",
        reason: summary,
        payload: { manifestDigest: run.manifestDigest },
      });
      await this.revokeRunCapability(runId, "Run rolled back");
    } catch {
      // Protected state is already rolled back; keep the terminal state stable.
    }
  }

  private async expireApproval(approvalId: string, reason: string): Promise<void> {
    const approval = this.getApproval(approvalId);
    if (approval.status !== "pending") return;
    await this.store.mutate((database) => {
      const storedApproval = database.approvals.find((item) => item.id === approvalId);
      if (!storedApproval || storedApproval.status !== "pending") return;
      storedApproval.status = "expired";
      storedApproval.decidedAt = now();
    });
    await this.publishSecurityEvent({
      type: "approval.expired",
      moduleId: "approval-manager",
      stage: "approval",
      severity: "medium",
      agentId: approval.agentId,
      runId: approval.runId,
      decision: "expired",
      reason,
      payload: { approvalId },
    });
    await this.finishRolledBack(approval.runId, reason);
  }

  private async cancelPendingApproval(agentId: string, reason: string): Promise<void> {
    const approval = this.store
      .snapshot()
      .approvals.find((item) => item.agentId === agentId && item.status === "pending");
    if (approval) await this.expireApproval(approval.id, reason);
  }

  private normalizeTraceResource(resource: string, stagedWorkspace: string): string | null {
    let normalized = resource.replaceAll("\\", "/");
    const stagedPrefix = stagedWorkspace.replaceAll("\\", "/") + "/";
    if (normalized.startsWith(stagedPrefix)) normalized = normalized.slice(stagedPrefix.length);
    if (normalized.startsWith("/workspace/")) normalized = normalized.slice("/workspace/".length);
    if (normalized.startsWith("./")) normalized = normalized.slice(2);
    if (!normalized || normalized.startsWith("/") || normalized.split("/").includes("..")) {
      return null;
    }
    return normalized;
  }

  private async setStatus(id: string, status: Agent["status"]): Promise<Agent> {
    return this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      if (status === "ready" && agent.status === "busy") {
        throw new HttpError(409, "Stop the active run before starting this Agent");
      }
      agent.status = status;
      agent.principalStatus = status === "stopped" ? "revoked" : "active";
      if (status === "ready") agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
  }

  private async cancelExecution(agentId: string): Promise<void> {
    this.cancellationRequests.add(agentId);
    try {
      await this.runner.cancel(agentId);
      const execution = this.activeExecutions.get(agentId);
      if (execution) {
        await execution;
      }
    } finally {
      this.cancellationRequests.delete(agentId);
    }
  }

  private getRunSecurityContext(runId: string) {
    const snapshot = this.store.snapshot();
    const run = snapshot.runs.find((item) => item.id === runId);
    const context = snapshot.runSecurityContexts.find(
      (item) => item.id === run?.securityContextId || item.runId === runId,
    );
    if (!context) throw new HttpError(409, "Run security context is unavailable");
    if (context.revokedAt || Date.parse(context.expiresAt) <= Date.now()) {
      throw new HttpError(409, "Run capability is revoked or expired");
    }
    return context;
  }

  private async publishSecurityEvent(input: SecurityEventInput): Promise<void> {
    if (input.runId && (!input.humanId || !input.agentPrincipalId)) {
      const snapshot = this.store.snapshot();
      const run = snapshot.runs.find((item) => item.id === input.runId);
      const context = snapshot.runSecurityContexts.find(
        (item) => item.id === run?.securityContextId || item.runId === input.runId,
      );
      if (context) {
        input = {
          ...input,
          humanId: input.humanId ?? context.humanId,
          agentPrincipalId: input.agentPrincipalId ?? context.agentPrincipalId,
        };
      }
    }
    await this.events.publish(input);
  }

  private async revokeRunCapability(runId: string, reason: string): Promise<void> {
    const revokedAt = now();
    const context = await this.store.mutate((database) => {
      const item = database.runSecurityContexts.find((candidate) => candidate.runId === runId);
      if (!item || item.revokedAt) return null;
      item.revokedAt = revokedAt;
      return structuredClone(item);
    });
    if (!context) return;
    await this.publishSecurityEvent({
      type: "identity.delegation_revoked",
      moduleId: "identity-delegation",
      stage: "identity",
      severity: "info",
      humanId: context.humanId,
      agentPrincipalId: context.agentPrincipalId,
      agentId: context.agentId,
      runId,
      decision: "revoked",
      reason,
      payload: { contextId: context.id, revokedAt },
    });
  }
}
