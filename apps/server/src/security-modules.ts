import { createHash } from "node:crypto";
import type { AppConfig } from "./config.js";
import { simulatePolicy } from "./policy-profile.js";
import type { SecurityEventInput, SecurityLedger } from "./security-ledger.js";
import type {
  EffectDecision,
  ExternalHttpEffect,
  FileEffect,
  PolicyProfile,
  RunSecurityContext,
  SecurityModuleConfiguration,
} from "./types.js";

export type SecurityModuleKind = "policy" | "gateway" | "analyzer" | "approval" | "evidence";
export type SecurityModuleHealth = "active" | "disabled" | "degraded";

export interface JsonSchema {
  type: "object";
  title?: string;
  properties: Record<string, {
    type: "string" | "number" | "boolean" | "array";
    title: string;
    description?: string;
    default?: unknown;
    minimum?: number;
    maximum?: number;
    enum?: string[];
    items?: { type: "string" };
  }>;
}

export interface SecurityModuleManifest {
  id: string;
  name: string;
  version: string;
  kind: SecurityModuleKind;
  description: string;
  capabilities: string[];
  locked: boolean;
  configSchema?: JsonSchema;
}

export interface ModuleContext extends RunSecurityContext {
  profile: PolicyProfile;
}

export interface SecuritySignal {
  decision: EffectDecision;
  ruleId: string;
  reason: string;
  score?: number;
}

export interface SecurityModule {
  readonly manifest: SecurityModuleManifest;
  readonly defaultEnabled: boolean;
  readonly defaultConfig: Record<string, unknown>;
  configure?(config: unknown): void;
  onIntake?(prompt: string, context: ModuleContext): Promise<SecuritySignal | null> | SecuritySignal | null;
  onEvent?(event: SecurityEventInput): Promise<void> | void;
  reviewEffect?(
    effect: FileEffect | ExternalHttpEffect,
    context: ModuleContext,
  ): Promise<PolicyContribution | null> | PolicyContribution | null;
  health(): { status: Exclude<SecurityModuleHealth, "disabled">; reason: string };
}

export interface PolicyContribution {
  decision: EffectDecision;
  ruleId: string;
  reason: string;
}

export interface SecurityModuleView extends SecurityModuleManifest {
  enabled: boolean;
  status: SecurityModuleHealth;
  statusReason: string;
  config: Record<string, unknown>;
  revision: number;
}

interface RegisteredModule {
  module: SecurityModule;
  enabled: boolean;
  config: Record<string, unknown>;
  revision: number;
  updatedAt: string;
}

const cloneRecord = (value: Record<string, unknown>) => structuredClone(value);
const rank: Record<EffectDecision, number> = { allow: 0, require_approval: 1, deny: 2 };

export class SecurityModuleRegistry {
  private readonly modules = new Map<string, RegisteredModule>();

  register(module: SecurityModule): this {
    if (this.modules.has(module.manifest.id)) {
      throw new Error("Security module already registered: " + module.manifest.id);
    }
    this.modules.set(module.manifest.id, {
      module,
      enabled: module.defaultEnabled,
      config: cloneRecord(module.defaultConfig),
      revision: 1,
      updatedAt: new Date().toISOString(),
    });
    module.configure?.(module.defaultConfig);
    return this;
  }

  list(): SecurityModuleView[] {
    return [...this.modules.values()].map((entry) => {
      const health = entry.module.health();
      return {
        ...structuredClone(entry.module.manifest),
        enabled: entry.enabled,
        status: entry.enabled ? health.status : "disabled",
        statusReason: entry.enabled ? health.reason : "Disabled by the security operator.",
        config: cloneRecord(entry.config),
        revision: entry.revision,
      };
    });
  }

  get(id: string): SecurityModuleView {
    const module = this.list().find((item) => item.id === id);
    if (!module) throw new Error("Unknown security module: " + id);
    return module;
  }

  isEnabled(id: string): boolean {
    return this.modules.get(id)?.enabled ?? false;
  }

  configurations(): SecurityModuleConfiguration[] {
    return [...this.modules.entries()].map(([moduleId, entry]) => ({
      moduleId,
      enabled: entry.enabled,
      config: cloneRecord(entry.config),
      revision: entry.revision,
      updatedAt: entry.updatedAt,
    }));
  }

  load(configurations: SecurityModuleConfiguration[]): void {
    for (const configuration of configurations) {
      const entry = this.modules.get(configuration.moduleId);
      if (!entry || (entry.module.manifest.locked && !configuration.enabled)) continue;
      const config = entry.module.manifest.configSchema
        ? cloneRecord(configuration.config)
        : cloneRecord(entry.module.defaultConfig);
      entry.module.configure?.(config);
      entry.enabled = configuration.enabled;
      entry.config = config;
      entry.revision = Math.max(1, configuration.revision);
      entry.updatedAt = configuration.updatedAt;
    }
  }

  configure(id: string, input: { enabled?: boolean; config?: Record<string, unknown> }): SecurityModuleView {
    const entry = this.modules.get(id);
    if (!entry) throw new Error("Unknown security module: " + id);
    if (input.enabled === false && entry.module.manifest.locked) {
      throw new Error("Kernel-bound module cannot be disabled: " + id);
    }
    if (input.config && !entry.module.manifest.configSchema && Object.keys(input.config).length > 0) {
      throw new Error("Security module does not expose configurable settings: " + id);
    }
    const nextConfig = input.config ? cloneRecord(input.config) : entry.config;
    entry.module.configure?.(nextConfig);
    if (input.enabled !== undefined) entry.enabled = input.enabled;
    entry.config = nextConfig;
    entry.revision += 1;
    entry.updatedAt = new Date().toISOString();
    return this.get(id);
  }

  policyVersion(profile: PolicyProfile): string {
    const modules = this.list()
      .filter((module) => module.enabled)
      .map((module) => `${module.id}@${module.version}#${module.revision}`)
      .sort()
      .join("+");
    const digest = createHash("sha256").update(JSON.stringify(profile)).digest("hex").slice(0, 12);
    return `profile-v${profile.version}-${digest}+${modules}`;
  }

  async onIntake(prompt: string, context: ModuleContext): Promise<Array<SecuritySignal & { moduleId: string }>> {
    const signals: Array<SecuritySignal & { moduleId: string }> = [];
    for (const [moduleId, entry] of this.modules) {
      if (!entry.enabled || !entry.module.onIntake) continue;
      const contribution = await entry.module.onIntake(prompt, context);
      if (contribution) signals.push({ ...contribution, moduleId });
    }
    return signals;
  }

  async reviewEffect<T extends FileEffect | ExternalHttpEffect>(effect: T, context: ModuleContext): Promise<T> {
    let result: T = structuredClone(effect);
    if (rank[context.intakeDecision] > rank[result.decision]) {
      result = { ...result, decision: context.intakeDecision, ruleId: "intake-risk-escalation", reason: "Intake analyzers required a stricter effect decision" };
    }
    for (const entry of this.modules.values()) {
      if (!entry.enabled || !entry.module.reviewEffect) continue;
      const contribution = await entry.module.reviewEffect(result, context);
      if (contribution && rank[contribution.decision] > rank[result.decision]) {
        result = { ...result, ...contribution };
        if ("status" in result && contribution.decision === "deny") result = { ...result, status: "denied" };
      }
    }
    return result;
  }

  async notify(event: SecurityEventInput): Promise<void> {
    await Promise.all([...this.modules.values()].filter((entry) => entry.enabled).map((entry) => entry.module.onEvent?.(event)));
  }
}

interface ModuleOptions {
  enabled?: boolean;
  config?: Record<string, unknown>;
  configure?: (config: Record<string, unknown>) => void;
  health?: () => { status: "active" | "degraded"; reason: string };
  onIntake?: SecurityModule["onIntake"];
  reviewEffect?: SecurityModule["reviewEffect"];
  onEvent?: SecurityModule["onEvent"];
}

function module(manifest: Omit<SecurityModuleManifest, "version">, options: ModuleOptions = {}): SecurityModule {
  return {
    manifest: { ...manifest, version: "3.0.0" },
    defaultEnabled: options.enabled ?? true,
    defaultConfig: options.config ?? {},
    ...(options.configure ? { configure: options.configure } : {}),
    ...(options.onIntake ? { onIntake: options.onIntake } : {}),
    ...(options.reviewEffect ? { reviewEffect: options.reviewEffect } : {}),
    ...(options.onEvent ? { onEvent: options.onEvent } : {}),
    health: options.health ?? (() => ({ status: "active", reason: "Module is operational." })),
  };
}

function detectPromptSecret(prompt: string): boolean {
  return [
    /\bsk-[A-Za-z0-9_-]{12,}\b/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bBearer\s+[A-Za-z0-9._~+/-]{16,}/i,
    /\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*["']?[A-Za-z0-9._~+/-]{16,}/i,
  ].some((pattern) => pattern.test(prompt));
}

function outputText(body: Record<string, unknown>): string {
  if (typeof body.output_text === "string") return body.output_text;
  if (!Array.isArray(body.output)) return "";
  return body.output
    .flatMap((item) => typeof item === "object" && item && Array.isArray((item as { content?: unknown }).content) ? (item as { content: unknown[] }).content : [])
    .map((item) => typeof item === "object" && item && typeof (item as { text?: unknown }).text === "string" ? String((item as { text: string }).text) : "")
    .join("");
}

function chatCompletionText(body: Record<string, unknown>): string {
  if (!Array.isArray(body.choices)) return "";
  const choice = body.choices[0];
  if (!choice || typeof choice !== "object") return "";
  const message = (choice as { message?: unknown }).message;
  if (!message || typeof message !== "object") return "";
  const content = (message as { content?: unknown }).content;
  return typeof content === "string" ? content : "";
}

function escapeXml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function singGuardRisks(output: string): string[] | null {
  const match = output.match(/<risks>([\s\S]*?)<\/risks>/i);
  if (!match) return null;
  return (match[1] ?? "")
    .split(/[;,\n]/)
    .map((risk) => risk.trim())
    .filter(Boolean);
}

function guardrailModel(config: AppConfig): SecurityModule {
  let moduleConfig: Record<string, unknown> = {
    provider: "ark",
    endpoint: "",
    model: "",
    riskAction: "deny",
  };
  let lastFailure: string | null = null;
  return {
    manifest: {
      id: "guardrail-model",
      name: "Guardrail Model",
      version: "3.0.0",
      kind: "analyzer",
      description: "Runs Ark scoring or local SingGuard-NSFA before Runtime access.",
      capabilities: ["intake-risk", "singguard-nsfa", "probabilistic-analysis", "fail-safe-degradation"],
      locked: false,
      configSchema: {
        type: "object",
        properties: {
          provider: { type: "string", title: "Provider", enum: ["singguard", "ark"] },
          endpoint: { type: "string", title: "Custom endpoint", description: "Leave empty to use the selected provider's environment default." },
          model: { type: "string", title: "Model", description: "Leave empty to use the selected provider's environment default." },
          riskAction: { type: "string", title: "Detected-risk action", enum: ["deny", "require_approval"] },
        },
      },
    },
    defaultEnabled: true,
    defaultConfig: moduleConfig,
    configure(value) {
      if (!value || typeof value !== "object") throw new Error("Guardrail configuration must be an object");
      const next = { ...moduleConfig, ...(value as Record<string, unknown>) };
      if (!["ark", "singguard"].includes(String(next.provider))) throw new Error("Unknown Guardrail provider");
      if (!["deny", "require_approval"].includes(String(next.riskAction))) throw new Error("Unknown Guardrail risk action");
      moduleConfig = next;
      lastFailure = null;
    },
    async onIntake(prompt, context) {
      if (!context.profile.analyzers["guardrail-model"].enabled) return null;
      const provider = moduleConfig.provider === "singguard" ? "singguard" : "ark";
      const configuredEndpoint = typeof moduleConfig.endpoint === "string" ? moduleConfig.endpoint.trim() : "";
      const configuredModel = typeof moduleConfig.model === "string" ? moduleConfig.model.trim() : "";
      const baseUrl = (configuredEndpoint || (provider === "singguard" ? config.singGuardBaseUrl : config.arkBaseUrl)).replace(/\/+$/, "");
      const modelName = configuredModel || (provider === "singguard" ? config.singGuardModel : config.arkModel);
      if (provider === "singguard") {
        try {
          const response = await fetch(baseUrl + "/chat/completions", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              model: modelName,
              messages: [{
                role: "user",
                content: `<untrusted_input>\n${escapeXml(prompt)}\n</untrusted_input>`,
              }],
              temperature: 0.1,
              max_tokens: 512,
            }),
            signal: AbortSignal.timeout(Math.min(config.httpEffectTimeoutMs, 15_000)),
          });
          if (!response.ok) throw new Error("SingGuard-NSFA returned HTTP " + response.status);
          const output = chatCompletionText(await response.json() as Record<string, unknown>);
          const risks = singGuardRisks(output);
          if (!risks) throw new Error("SingGuard-NSFA response did not contain a risks tag");
          lastFailure = null;
          if (risks.length === 0 || risks.every((risk) => risk.toLowerCase() === "no_risk")) {
            return {
              decision: "allow",
              ruleId: "singguard-nsfa-no-risk",
              reason: "SingGuard-NSFA found no Intake risk",
              score: 0,
            };
          }
          const decision = moduleConfig.riskAction === "require_approval" ? "require_approval" : "deny";
          return {
            decision,
            ruleId: decision === "deny" ? "singguard-nsfa-deny" : "singguard-nsfa-review",
            reason: "SingGuard-NSFA classified Intake as " + risks.join(", ").slice(0, 200),
            score: 1,
          };
        } catch (error) {
          lastFailure = error instanceof Error ? error.message : String(error);
          return {
            decision: "allow",
            ruleId: "singguard-nsfa-degraded",
            reason: "SingGuard-NSFA is unavailable; deterministic controls remain active",
          };
        }
      }
      if (!config.arkApiKey || !baseUrl || !modelName) {
        lastFailure = "Ark endpoint or credentials are unavailable.";
        return {
          decision: "allow",
          ruleId: "guardrail-model-degraded",
          reason: "Ark classifier is unavailable; deterministic controls remain active",
        };
      }
      try {
        const response = await fetch(baseUrl + "/responses", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: "Bearer " + config.arkApiKey },
          body: JSON.stringify({
            model: modelName,
            instructions: "Classify Agent security risk. Return JSON only: {\"risk\": number from 0 to 1, \"reason\": short string}. Do not repeat secrets.",
            input: prompt,
            max_output_tokens: 80,
          }),
          signal: AbortSignal.timeout(Math.min(config.httpEffectTimeoutMs, 8_000)),
        });
        if (!response.ok) throw new Error("Classifier returned HTTP " + response.status);
        const text = outputText(await response.json() as Record<string, unknown>);
        const match = text.match(/\{[\s\S]*\}/);
        if (!match) throw new Error("Classifier response did not contain JSON");
        const parsed = JSON.parse(match[0]) as { risk?: unknown; reason?: unknown };
        const score = Math.max(0, Math.min(1, Number(parsed.risk)));
        if (!Number.isFinite(score)) throw new Error("Classifier risk score is invalid");
        lastFailure = null;
        const thresholds = context.profile.analyzers["guardrail-model"];
        const reason = typeof parsed.reason === "string" ? parsed.reason.slice(0, 240) : "Guardrail model classified the prompt";
        if (score >= thresholds.denyThreshold) return { decision: "deny", ruleId: "guardrail-model-deny", reason, score };
        if (score >= thresholds.reviewThreshold) return { decision: "require_approval", ruleId: "guardrail-model-review", reason, score };
        return { decision: "allow", ruleId: "guardrail-model-no-risk", reason, score };
      } catch (error) {
        lastFailure = error instanceof Error ? error.message : String(error);
        return {
          decision: "allow",
          ruleId: "guardrail-model-degraded",
          reason: "Ark classifier is unavailable; deterministic controls remain active",
        };
      }
    },
    health() {
      if (lastFailure) return { status: "degraded", reason: "Classifier unavailable. Deterministic kernel remains active: " + lastFailure };
      if (moduleConfig.provider === "singguard") {
        return { status: "active", reason: "Local SingGuard-NSFA is configured and probed when Intake analysis runs." };
      }
      return config.arkApiKey && config.arkModel
        ? { status: "active", reason: "Ark-backed classifier is ready when enabled by an Agent profile." }
        : { status: "degraded", reason: "Ark is unavailable. Deterministic kernel remains active." };
    },
  };
}

export function createSecurityModuleRegistry(config: AppConfig): SecurityModuleRegistry {
  const externalEnabled = config.httpEffectAllowlist.length > 0;
  return new SecurityModuleRegistry()
    .register(module({
      id: "identity-delegation", name: "Identity & Delegation", kind: "policy",
      description: "Binds a Human, Agent principal and time-limited capability to every Run.",
      capabilities: ["principal-attribution", "run-capability", "scope-enforcement", "revocation"], locked: true,
    }, { reviewEffect: (effect, context) => {
      const requiredScope = effect.type === "http.request" ? "external:http:declared" : "workspace:**";
      return context.revokedAt || Date.parse(context.expiresAt) <= Date.now() || !context.scopes.includes(requiredScope)
        ? { decision: "deny", ruleId: "deny-missing-run-capability", reason: "Run capability is revoked, expired, or missing the required scope" }
        : null;
    } }))
    .register(module({
      id: "runtime-containment", name: "Runtime Containment", kind: "gateway",
      description: "Runs Codex against disposable workspace and session copies.",
      capabilities: ["staging", "container-boundary", "cleanup"], locked: true,
    }, { health: () => ({ status: "active", reason: config.runtimeProvider + " Runtime is configured." }) }))
    .register(module({
      id: "filesystem-effects", name: "Filesystem Effect Kernel", kind: "gateway",
      description: "Measures persistent file effects and owns atomic commit and rollback.",
      capabilities: ["diff", "hard-deny", "atomic-commit", "rollback"], locked: true,
    }))
    .register(module({
      id: "policy-profile", name: "Policy Profile", kind: "policy",
      description: "Applies versioned per-Agent file, HTTP, egress and approval policy.",
      capabilities: ["per-agent-policy", "templates", "glob-rules", "simulation"], locked: true,
    }, { reviewEffect: (effect, context) => {
      if (effect.type !== "http.request") return null;
      const result = simulatePolicy(context.profile, { kind: "http", resource: effect.url, method: effect.method });
      return { decision: result.decision, ruleId: result.ruleId, reason: result.reason };
    } }))
    .register(module({
      id: "egress-firewall", name: "Egress Firewall", kind: "gateway",
      description: "Defines default-deny domain, method and path rules for Runtime network access.",
      capabilities: ["domain-rules", "method-rules", "default-deny", "egress-events"], locked: false,
      configSchema: { type: "object", properties: {
        mode: { type: "string", title: "Enforcement", enum: ["cooperative", "l3"] },
        allow: { type: "array", title: "Allow rules", items: { type: "string" }, description: "Boundary-style domain/method/path rules." },
      } },
    }, {
      enabled: false, config: { mode: "cooperative", allow: ["domain=ark.cn-beijing.volces.com"] },
      configure: (value) => {
        if (!Array.isArray(value.allow)) throw new Error("Egress allow rules must be an array");
        if (!["cooperative", "l3"].includes(String(value.mode))) throw new Error("Unknown egress enforcement mode");
      },
      health: () => ({ status: "degraded", reason: "Policy is configured. L3 proxy attachment is not active in this Runtime profile." }),
    }))
    .register(module({
      id: "secret-scanner", name: "Secret Scanner", kind: "analyzer",
      description: "Detects credential-shaped values at Intake without recording them.",
      capabilities: ["prompt-scan", "secret-patterns", "redacted-evidence"], locked: false,
    }, { onIntake: (prompt, context) => {
      const settings = context.profile.analyzers["secret-scanner"];
      return settings.enabled && detectPromptSecret(prompt)
        ? { decision: settings.action, ruleId: "intake-secret-detected", reason: "Credential-shaped input was detected and redacted from evidence", score: 1 }
        : null;
    } }))
    .register(guardrailModel(config))
    .register(module({
      id: "external-http", name: "External HTTP Gateway", kind: "gateway",
      description: "Mediates declared HTTP actions with SSRF, DLP and approval controls.",
      capabilities: ["allowlist", "ssrf", "dlp", "idempotency", "receipt"], locked: false,
    }, {
      enabled: externalEnabled,
      health: () => externalEnabled
        ? { status: "active", reason: "Allowlisted hosts: " + config.httpEffectAllowlist.join(", ") }
        : { status: "degraded", reason: "No AEG_HTTP_ALLOWLIST is configured." },
    }))
    .register(module({
      id: "approval-manager", name: "Digest-bound Approval", kind: "approval",
      description: "Binds human approval to exact effects, policy version and expiry.",
      capabilities: ["human-approval", "digest-binding", "profile-ttl"], locked: true,
    }))
    .register(module({
      id: "trace-correlation", name: "Trace Correlation", kind: "evidence",
      description: "Correlates untrusted Runtime trace with platform-measured effects.",
      capabilities: ["trace", "diff-correlation", "mismatch-detection"], locked: false,
    }))
    .register(module({
      id: "audit-ledger", name: "Tamper-evident Ledger", kind: "evidence",
      description: "Stores redacted security events in an HMAC-chained append-only ledger.",
      capabilities: ["event-integrity", "verification", "query"], locked: true,
    }));
}

export class SecurityEventBus {
  constructor(private readonly registry: SecurityModuleRegistry, private readonly ledger: SecurityLedger) {}

  async publish(input: SecurityEventInput): Promise<void> {
    this.registry.get(input.moduleId ?? "audit-ledger");
    await this.registry.notify(input);
    await this.ledger.append(input);
  }
}
