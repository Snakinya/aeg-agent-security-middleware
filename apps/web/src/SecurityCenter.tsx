import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import type {
  Agent,
  AgentRun,
  Approval,
  EffectPreview,
  SecurityEvent,
  SecurityStage,
} from "./types";
import type { SecurityOverview } from "./types";

/* ---------- Presentation helpers ---------- */

const stageLanes: Array<{ id: string; label: string; glyph: string; stages: SecurityStage[] }> = [
  { id: "identity", label: "Identity", glyph: "◉", stages: ["identity"] },
  { id: "runtime", label: "Runtime", glyph: "▣", stages: ["runtime"] },
  { id: "policy", label: "Policy", glyph: "◆", stages: ["observe", "policy"] },
  { id: "approval", label: "Approval", glyph: "❖", stages: ["approval"] },
  { id: "effect", label: "Effect", glyph: "▶", stages: ["execute"] },
  { id: "evidence", label: "Evidence", glyph: "✓", stages: ["recover", "verify"] },
];

const eventTitles: Record<string, string> = {
  "identity.control_plane_ready": "Identity plane ready",
  "identity.agent_provisioned": "Agent principal provisioned",
  "identity.agent_activated": "Agent principal activated",
  "identity.agent_revoked": "Agent principal revoked",
  "identity.delegation_issued": "Run capability issued",
  "identity.delegation_revoked": "Run capability revoked",
  "run.staged": "Workspace staged for run",
  "runtime.command_execution": "Command executed in runtime",
  "runtime.file_change": "File change reported by runtime",
  "runtime.mcp_tool_call": "Tool call reported by runtime",
  "effect.reviewed": "File effect reviewed",
  "external_effect.reviewed": "External request reviewed",
  "external_effect.executed": "External request executed",
  "external_effect.execution_uncertain": "External outcome uncertain",
  "approval.requested": "Human approval requested",
  "approval.approved": "Approval granted",
  "approval.denied": "Approval denied",
  "approval.expired": "Approval expired",
  "run.committed": "Manifest committed to workspace",
  "run.rolled_back": "Run rolled back",
  "run.failed": "Run failed safely",
  "run.cancelled": "Run cancelled",
  "run.external_outcome_uncertain": "External outcome uncertain",
  "trace.mismatch": "Trace does not match measured diff",
  "ledger.verified": "Audit ledger verified",
  "service.initialized": "Control plane recovered",
};

type Tone = "deny" | "warn" | "ok" | "info";

function eventTitle(event: SecurityEvent): string {
  return eventTitles[event.type] ?? event.type.replaceAll("_", " ").replaceAll(".", " · ");
}

function eventTone(event: SecurityEvent): Tone {
  if (event.severity === "critical" || event.decision === "deny" || event.decision === "denied") {
    return "deny";
  }
  if (
    event.severity === "high" ||
    event.decision === "require_approval" ||
    event.decision === "expired" ||
    event.decision === "uncertain" ||
    event.decision === "revoked"
  ) {
    return "warn";
  }
  if (["allow", "approved", "issued"].includes(event.decision ?? "")) return "ok";
  return "info";
}

function eventResource(event: SecurityEvent): string | null {
  const payload = event.payload ?? {};
  const candidate = payload.resource ?? payload.url ?? payload.summary ?? null;
  return typeof candidate === "string" ? candidate : null;
}

function decisionLabel(value: string | null | undefined): string {
  if (!value) return "observed";
  if (value === "require_approval") return "review";
  return value.replaceAll("_", " ");
}

function short(value: string | null | undefined, length = 12): string {
  if (!value) return "—";
  return value.length > length ? value.slice(0, length) + "…" : value;
}

function fullTime(value: string | null | undefined): string {
  if (!value) return "not recorded";
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function relativeTime(value: string | null | undefined): string {
  if (!value) return "—";
  const delta = Date.now() - Date.parse(value);
  if (delta < 60_000) return Math.max(1, Math.round(delta / 1_000)) + "s ago";
  if (delta < 3_600_000) return Math.round(delta / 60_000) + "m ago";
  if (delta < 86_400_000) return Math.round(delta / 3_600_000) + "h ago";
  return fullTime(value);
}

function expiresIn(value: string): string {
  const delta = Date.parse(value) - Date.now();
  if (delta <= 0) return "expired";
  if (delta < 60_000) return Math.round(delta / 1_000) + "s";
  return Math.floor(delta / 60_000) + "m " + Math.round((delta % 60_000) / 1_000) + "s";
}

function runTone(status: AgentRun["status"]): Tone {
  if (["failed", "rolled_back", "cancelled"].includes(status)) return "deny";
  if (["awaiting_approval", "reviewing_effects", "rolling_back"].includes(status)) return "warn";
  if (status === "completed") return "ok";
  return "info";
}

function CopyChip({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className={"sc-copy" + (copied ? " copied" : "")}
      title={copied ? "Copied" : "Copy " + label}
      onClick={(event) => {
        event.stopPropagation();
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1_400);
        });
      }}
    >
      {copied ? "✓" : "⧉"}
    </button>
  );
}

/* ---------- Scope model ---------- */

type Scope =
  | { kind: "all" }
  | { kind: "platform" }
  | { kind: "agent"; agentId: string }
  | { kind: "run"; agentId: string; runId: string };

type Drawer =
  | { kind: "event"; event: SecurityEvent }
  | { kind: "approval"; approvalId: string }
  | null;

type Tab = "activity" | "approvals" | "modules";

interface SecurityCenterProps {
  initialAgentId: string | null;
  initialRunId?: string | null;
  onOpenRun: (agentId: string, run: AgentRun) => void;
}

interface ApprovalDetail {
  approval: Approval;
  run: AgentRun;
  previews: EffectPreview[];
  currentWorkspaceHash: string;
}

export function SecurityCenter({ initialAgentId, initialRunId, onOpenRun }: SecurityCenterProps) {
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [runsByAgent, setRunsByAgent] = useState<Record<string, AgentRun[]>>({});
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [tab, setTab] = useState<Tab>("activity");
  const [scope, setScope] = useState<Scope>(
    initialRunId && initialAgentId
      ? { kind: "run", agentId: initialAgentId, runId: initialRunId }
      : initialAgentId
        ? { kind: "agent", agentId: initialAgentId }
        : { kind: "all" },
  );
  const [stageFilter, setStageFilter] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [drawer, setDrawer] = useState<Drawer>(null);
  const [approvalDetail, setApprovalDetail] = useState<ApprovalDetail | null>(null);
  const [ledgerCheck, setLedgerCheck] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scopeRef = useRef(scope);
  scopeRef.current = scope;

  /* ----- data loading ----- */

  const refreshStructure = useCallback(async () => {
    try {
      const [nextOverview, agentResponse, approvalResponse] = await Promise.all([
        api.securityOverview(),
        api.listAgents(),
        api.approvals(),
      ]);
      const runEntries = await Promise.all(
        agentResponse.agents.map(async (agent) => {
          const response = await api.runs(agent.id);
          return [agent.id, response.runs] as const;
        }),
      );
      setOverview(nextOverview);
      setAgents(agentResponse.agents);
      setRunsByAgent(Object.fromEntries(runEntries));
      setApprovals(approvalResponse.approvals);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  }, []);

  useEffect(() => {
    let active = true;
    const tick = async () => {
      if (active) await refreshStructure();
    };
    void tick();
    const timer = window.setInterval(() => void tick(), 5_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [refreshStructure]);

  useEffect(() => {
    let active = true;
    const refreshEvents = async () => {
      try {
        const current = scopeRef.current;
        const query = new URLSearchParams({ limit: "500" });
        if (current.kind === "agent" || current.kind === "run") {
          query.set("agentId", current.agentId);
        }
        if (current.kind === "run") query.set("runId", current.runId);
        const response = await api.securityEvents(query.toString());
        if (!active) return;
        setEvents(
          current.kind === "platform"
            ? response.events.filter((event) => !event.agentId)
            : response.events,
        );
      } catch (reason) {
        if (active) setError(reason instanceof Error ? reason.message : String(reason));
      }
    };
    void refreshEvents();
    const timer = window.setInterval(() => void refreshEvents(), 2_500);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [scope]);

  useEffect(() => {
    if (drawer?.kind !== "approval") {
      setApprovalDetail(null);
      return;
    }
    let active = true;
    api
      .approval(drawer.approvalId)
      .then((detail) => {
        if (active) setApprovalDetail(detail);
      })
      .catch((reason) => {
        if (active) setError(reason instanceof Error ? reason.message : String(reason));
      });
    return () => {
      active = false;
    };
  }, [drawer]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setDrawer(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  /* ----- derived data ----- */

  const agentById = useMemo(() => new Map(agents.map((agent) => [agent.id, agent])), [agents]);

  const scopedEvents = events;
  const laneCounts = useMemo(() => {
    const counts = new Map<string, { total: number; tone: Tone }>();
    for (const lane of stageLanes) counts.set(lane.id, { total: 0, tone: "info" });
    const rank: Record<Tone, number> = { info: 0, ok: 1, warn: 2, deny: 3 };
    for (const event of scopedEvents) {
      const lane = stageLanes.find((item) => event.stage && item.stages.includes(event.stage));
      if (!lane) continue;
      const entry = counts.get(lane.id)!;
      entry.total += 1;
      const tone = eventTone(event);
      if (rank[tone] > rank[entry.tone]) entry.tone = tone;
    }
    return counts;
  }, [scopedEvents]);

  const decisionMix = useMemo(() => {
    let allow = 0;
    let review = 0;
    let deny = 0;
    for (const event of scopedEvents) {
      if (event.decision === "allow" || event.decision === "approved") allow += 1;
      else if (event.decision === "require_approval") review += 1;
      else if (event.decision === "deny" || event.decision === "denied") deny += 1;
    }
    return { allow, review, deny, total: allow + review + deny };
  }, [scopedEvents]);

  const visibleEvents = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const lane = stageFilter ? stageLanes.find((item) => item.id === stageFilter) : null;
    return scopedEvents.filter((event) => {
      if (lane && !(event.stage && lane.stages.includes(event.stage))) return false;
      if (decisionFilter !== "all") {
        if (decisionFilter === "deny" && !["deny", "denied"].includes(event.decision ?? "")) {
          return false;
        }
        if (decisionFilter === "review" && event.decision !== "require_approval") return false;
        if (decisionFilter === "allow" && !["allow", "approved"].includes(event.decision ?? "")) {
          return false;
        }
      }
      if (!needle) return true;
      return [
        event.type,
        eventTitle(event),
        event.reason,
        event.ruleId,
        event.agentName,
        event.runPrompt,
        event.moduleId,
        eventResource(event),
      ].some((value) => value?.toLowerCase().includes(needle));
    });
  }, [decisionFilter, scopedEvents, search, stageFilter]);

  const pendingApprovals = approvals.filter((approval) => approval.status === "pending");
  const decidedApprovals = approvals.filter((approval) => approval.status !== "pending");

  const scopeAgent =
    scope.kind === "agent" || scope.kind === "run" ? agentById.get(scope.agentId) ?? null : null;
  const scopeRun =
    scope.kind === "run"
      ? (runsByAgent[scope.agentId] ?? []).find((run) => run.id === scope.runId) ?? null
      : null;

  /* ----- actions ----- */

  const verifyLedger = async () => {
    setLedgerCheck("checking…");
    try {
      const result = await api.verifyLedger();
      setLedgerCheck(
        result.valid
          ? "chain intact · " + result.events + " events"
          : "BROKEN at event " + (result.brokenAt ?? "?"),
      );
      window.setTimeout(() => setLedgerCheck(null), 6_000);
    } catch (reason) {
      setLedgerCheck(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const decideApproval = async (approvalId: string, decision: "approve" | "deny") => {
    setBusy(true);
    setError(null);
    try {
      await (decision === "approve" ? api.approve(approvalId) : api.deny(approvalId));
      setDrawer(null);
      await refreshStructure();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      await refreshStructure();
    } finally {
      setBusy(false);
    }
  };

  const scopeLabel =
    scope.kind === "all"
      ? "All activity"
      : scope.kind === "platform"
        ? "Platform"
        : scope.kind === "agent"
          ? scopeAgent?.name ?? "Agent"
          : (scopeAgent?.name ?? "Agent") + " · run " + short(scope.runId, 8);

  if (!overview) {
    return (
      <section className="sc-root sc-loading" aria-live="polite">
        <span className="sc-pulse" />
        {error ?? "Connecting to the security plane…"}
      </section>
    );
  }

  /* ----- render ----- */

  return (
    <section className="sc-root">
      {/* Top bar */}
      <header className="sc-topbar">
        <div className="sc-topbar-title">
          <span className="sc-shield">⛨</span>
          <div>
            <h1>Security Center</h1>
            <p>Agent Effect Gateway · zero-trust arbitration evidence</p>
          </div>
        </div>
        <div className="sc-topbar-actions">
          <span className={"sc-posture sc-posture-" + overview.posture}>
            <span className="sc-pulse" />
            {overview.posture === "protected" ? "Protected" : "Degraded"}
          </span>
          <button className="sc-ledger-chip" onClick={() => void verifyLedger()} title="Re-verify the HMAC event chain">
            <span className={overview.ledger.valid ? "sc-dot-ok" : "sc-dot-deny"} />
            {ledgerCheck ?? "Ledger · " + overview.ledger.events + " signed events"}
          </button>
        </div>
      </header>

      {error && <div className="sc-error">{error}</div>}

      {/* KPI strip */}
      <div className="sc-kpis">
        {[
          { label: "Agent runs", value: overview.totals.runs, sub: overview.totals.agents + " agents", tone: "info" },
          { label: "Effects reviewed", value: overview.totals.effects, sub: "complete mediation", tone: "info" },
          { label: "Blocked", value: overview.totals.blocked, sub: "policy denials", tone: overview.totals.blocked > 0 ? "deny" : "info" },
          { label: "Awaiting approval", value: overview.totals.awaitingApproval, sub: "digest-bound", tone: overview.totals.awaitingApproval > 0 ? "warn" : "info" },
          { label: "Rolled back", value: overview.totals.rolledBack, sub: "state restored", tone: "info" },
          { label: "Run capabilities", value: overview.identity.issuedCapabilities, sub: overview.identity.activeAgentPrincipals + " active principals", tone: "info" },
        ].map((kpi) => (
          <div className={"sc-kpi sc-kpi-" + kpi.tone} key={kpi.label}>
            <span className="sc-kpi-label">{kpi.label}</span>
            <strong>{kpi.value}</strong>
            <small>{kpi.sub}</small>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <nav className="sc-tabs" role="tablist">
        <button className={tab === "activity" ? "active" : ""} onClick={() => setTab("activity")}>
          Activity
        </button>
        <button className={tab === "approvals" ? "active" : ""} onClick={() => setTab("approvals")}>
          Approvals
          {pendingApprovals.length > 0 && <span className="sc-badge">{pendingApprovals.length}</span>}
        </button>
        <button className={tab === "modules" ? "active" : ""} onClick={() => setTab("modules")}>
          Modules
        </button>
      </nav>

      {/* ============ ACTIVITY ============ */}
      {tab === "activity" && (
        <div className="sc-activity">
          <aside className="sc-scope" aria-label="Scope">
            <button
              className={"sc-scope-item" + (scope.kind === "all" ? " active" : "")}
              onClick={() => setScope({ kind: "all" })}
            >
              <span className="sc-scope-glyph">∗</span> All activity
            </button>
            <button
              className={"sc-scope-item" + (scope.kind === "platform" ? " active" : "")}
              onClick={() => setScope({ kind: "platform" })}
            >
              <span className="sc-scope-glyph">⌂</span> Platform
            </button>
            <div className="sc-scope-heading">Agents</div>
            {agents.map((agent) => {
              const active =
                (scope.kind === "agent" || scope.kind === "run") && scope.agentId === agent.id;
              const runs = runsByAgent[agent.id] ?? [];
              return (
                <div key={agent.id} className="sc-scope-group">
                  <button
                    className={"sc-scope-item" + (scope.kind === "agent" && active ? " active" : "")}
                    onClick={() => setScope({ kind: "agent", agentId: agent.id })}
                  >
                    <span className="sc-scope-avatar">{agent.name.slice(0, 1).toUpperCase()}</span>
                    <span className="sc-scope-name">{agent.name}</span>
                    <span className="sc-scope-count">{runs.length}</span>
                  </button>
                  {active && runs.length > 0 && (
                    <div className="sc-scope-runs">
                      {runs.map((run) => (
                        <button
                          key={run.id}
                          className={
                            "sc-scope-run" +
                            (scope.kind === "run" && scope.runId === run.id ? " active" : "")
                          }
                          onClick={() => setScope({ kind: "run", agentId: agent.id, runId: run.id })}
                          title={run.prompt}
                        >
                          <span className={"sc-dot-" + runTone(run.status)} />
                          <span className="sc-scope-run-prompt">{run.prompt}</span>
                          <small>{run.status.replaceAll("_", " ")}</small>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </aside>

          <main className="sc-main">
            {/* Scope header / run card */}
            <div className="sc-scope-header">
              <div>
                <div className="sc-breadcrumbs">
                  <span>Security Center</span>
                  <b>/</b>
                  <strong>{scopeLabel}</strong>
                </div>
                {scopeRun ? (
                  <>
                    <h2>{scopeRun.prompt}</h2>
                    <p>
                      {fullTime(scopeRun.startedAt ?? scopeRun.createdAt)} · policy{" "}
                      {short(scopeRun.policyVersion, 26)} · capability{" "}
                      {short(scopeRun.securityContextId, 8)}
                    </p>
                  </>
                ) : (
                  <p className="sc-scope-summary">
                    {scope.kind === "platform"
                      ? "Control-plane startup, recovery and ledger events."
                      : "Every decision below is signed into the tamper-evident ledger."}
                  </p>
                )}
              </div>
              <div className="sc-scope-header-side">
                {scopeRun && (
                  <>
                    <span className={"sc-runstate sc-runstate-" + runTone(scopeRun.status)}>
                      {scopeRun.status.replaceAll("_", " ")}
                    </span>
                    {scopeAgent && (
                      <button className="sc-link" onClick={() => onOpenRun(scopeAgent.id, scopeRun)}>
                        Open in Playground →
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>

            {scopeRun && (
              <div className="sc-run-facts">
                <div>
                  <span>Effects</span>
                  <strong>{scopeRun.effects.length + scopeRun.externalEffects.length}</strong>
                </div>
                <div>
                  <span>Blocked</span>
                  <strong>
                    {[...scopeRun.effects, ...scopeRun.externalEffects].filter(
                      (effect) => effect.decision === "deny",
                    ).length}
                  </strong>
                </div>
                <div>
                  <span>Manifest digest</span>
                  <strong className="sc-mono">
                    {short(scopeRun.manifestDigest, 14)}
                    {scopeRun.manifestDigest && (
                      <CopyChip value={scopeRun.manifestDigest} label="manifest digest" />
                    )}
                  </strong>
                </div>
                <div>
                  <span>Workspace integrity</span>
                  <strong className="sc-mono">
                    {scopeRun.workspaceHashBefore && scopeRun.workspaceHashAfter
                      ? scopeRun.workspaceHashBefore === scopeRun.workspaceHashAfter
                        ? scopeRun.status === "rolled_back"
                          ? "restored exactly"
                          : "unchanged"
                        : "committed change"
                      : "pending"}
                  </strong>
                </div>
              </div>
            )}

            {/* Pipeline */}
            <div className="sc-pipeline" role="group" aria-label="Enforcement pipeline">
              {stageLanes.map((lane, index) => {
                const entry = laneCounts.get(lane.id)!;
                const active = stageFilter === lane.id;
                return (
                  <div className="sc-pipeline-cell" key={lane.id}>
                    {index > 0 && <span className="sc-pipeline-link" />}
                    <button
                      className={
                        "sc-stage sc-stage-" + (entry.total === 0 ? "empty" : entry.tone) +
                        (active ? " active" : "")
                      }
                      onClick={() => setStageFilter(active ? null : lane.id)}
                      title={entry.total + " events in " + lane.label}
                    >
                      <span className="sc-stage-glyph">{lane.glyph}</span>
                      <span className="sc-stage-label">{lane.label}</span>
                      <span className="sc-stage-count">{entry.total}</span>
                    </button>
                  </div>
                );
              })}
            </div>

            {/* Toolbar */}
            <div className="sc-toolbar">
              <div className="sc-mix" title={"allow " + decisionMix.allow + " · review " + decisionMix.review + " · deny " + decisionMix.deny}>
                {decisionMix.total > 0 ? (
                  <>
                    <span className="sc-mix-bar">
                      <i style={{ flexGrow: decisionMix.allow }} className="sc-mix-allow" />
                      <i style={{ flexGrow: decisionMix.review }} className="sc-mix-review" />
                      <i style={{ flexGrow: decisionMix.deny }} className="sc-mix-deny" />
                    </span>
                    <span className="sc-mix-legend">
                      <em className="sc-mix-allow-dot" /> {decisionMix.allow}
                      <em className="sc-mix-review-dot" /> {decisionMix.review}
                      <em className="sc-mix-deny-dot" /> {decisionMix.deny}
                    </span>
                  </>
                ) : (
                  <span className="sc-mix-empty">No decisions in scope</span>
                )}
              </div>
              <div className="sc-filters">
                {(["all", "allow", "review", "deny"] as const).map((value) => (
                  <button
                    key={value}
                    className={
                      "sc-filter sc-filter-" + value + (decisionFilter === value ? " active" : "")
                    }
                    onClick={() => setDecisionFilter(value)}
                  >
                    {value === "all" ? "All" : decisionLabel(value === "review" ? "require_approval" : value)}
                  </button>
                ))}
                <input
                  className="sc-search"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search events, rules, resources…"
                  aria-label="Search events"
                />
              </div>
            </div>

            {/* Timeline */}
            <div className="sc-timeline">
              {visibleEvents.length === 0 ? (
                <div className="sc-empty">
                  <span className="sc-empty-glyph">◈</span>
                  <h3>No events in this scope</h3>
                  <p>
                    {scope.kind === "run" || scope.kind === "agent"
                      ? "Send this Agent a task in the Playground — every decision will land here."
                      : "Adjust the filters, or run an Agent to generate security evidence."}
                  </p>
                </div>
              ) : (
                visibleEvents.map((event) => {
                  const tone = eventTone(event);
                  const resource = eventResource(event);
                  return (
                    <button
                      key={event.sequence}
                      className={
                        "sc-event" +
                        (drawer?.kind === "event" && drawer.event.sequence === event.sequence
                          ? " active"
                          : "")
                      }
                      onClick={() => setDrawer({ kind: "event", event })}
                    >
                      <span className="sc-event-rail">
                        <i className={"sc-node sc-node-" + tone} />
                      </span>
                      <time title={fullTime(event.createdAt)}>{relativeTime(event.createdAt)}</time>
                      <div className="sc-event-body">
                        <div className="sc-event-title">
                          <strong>{eventTitle(event)}</strong>
                          {resource && <code>{short(resource, 44)}</code>}
                        </div>
                        <small>
                          {event.reason ?? "Security event recorded"}
                          {scope.kind !== "run" && event.agentName ? " · " + event.agentName : ""}
                        </small>
                      </div>
                      <span className={"sc-decision sc-decision-" + tone}>
                        {decisionLabel(event.decision)}
                      </span>
                    </button>
                  );
                })
              )}
            </div>
          </main>
        </div>
      )}

      {/* ============ APPROVALS ============ */}
      {tab === "approvals" && (
        <div className="sc-approvals">
          <section>
            <div className="sc-section-heading">
              <h2>Pending decisions</h2>
              <span>{pendingApprovals.length}</span>
            </div>
            {pendingApprovals.length === 0 ? (
              <div className="sc-empty">
                <span className="sc-empty-glyph">❖</span>
                <h3>Nothing is waiting on you</h3>
                <p>High-risk manifests pause here until a human approves the exact digest.</p>
              </div>
            ) : (
              <div className="sc-approval-grid">
                {pendingApprovals.map((approval) => {
                  const agent = agentById.get(approval.agentId);
                  const run = (runsByAgent[approval.agentId] ?? []).find(
                    (item) => item.id === approval.runId,
                  );
                  return (
                    <article className="sc-approval-card" key={approval.id}>
                      <header>
                        <span className="sc-approval-flag">Needs review</span>
                        <span className="sc-approval-ttl" title={"Expires " + fullTime(approval.expiresAt)}>
                          expires in {expiresIn(approval.expiresAt)}
                        </span>
                      </header>
                      <h3>{run?.prompt ?? "Staged manifest"}</h3>
                      <p>
                        {agent?.name ?? "Agent"} staged{" "}
                        {(run?.effects.length ?? 0) + (run?.externalEffects.length ?? 0)} effect(s)
                        bound to digest
                      </p>
                      <div className="sc-approval-digest">
                        <code>{short(approval.manifestDigest, 26)}</code>
                        <CopyChip value={approval.manifestDigest} label="manifest digest" />
                      </div>
                      <footer>
                        <button
                          className="sc-button"
                          onClick={() => setDrawer({ kind: "approval", approvalId: approval.id })}
                        >
                          Review changes
                        </button>
                        <button
                          className="sc-button sc-button-danger"
                          disabled={busy}
                          onClick={() => void decideApproval(approval.id, "deny")}
                        >
                          Deny
                        </button>
                      </footer>
                    </article>
                  );
                })}
              </div>
            )}
          </section>

          <section>
            <div className="sc-section-heading">
              <h2>Decision history</h2>
              <span>{decidedApprovals.length}</span>
            </div>
            {decidedApprovals.length === 0 ? (
              <p className="sc-quiet">No decided approvals yet.</p>
            ) : (
              <div className="sc-history">
                {decidedApprovals.map((approval) => {
                  const agent = agentById.get(approval.agentId);
                  const run = (runsByAgent[approval.agentId] ?? []).find(
                    (item) => item.id === approval.runId,
                  );
                  return (
                    <button
                      className="sc-history-row"
                      key={approval.id}
                      onClick={() =>
                        run && agent
                          ? setScope({ kind: "run", agentId: agent.id, runId: run.id })
                          : undefined
                      }
                    >
                      <span className={"sc-history-status sc-history-" + approval.status}>
                        {approval.status}
                      </span>
                      <div>
                        <strong>{run?.prompt ?? short(approval.runId, 10)}</strong>
                        <small>
                          {agent?.name ?? "Agent"} · digest {short(approval.manifestDigest, 18)}
                        </small>
                      </div>
                      <time title={fullTime(approval.decidedAt)}>
                        {relativeTime(approval.decidedAt ?? approval.createdAt)}
                      </time>
                    </button>
                  );
                })}
              </div>
            )}
          </section>
        </div>
      )}

      {/* ============ MODULES ============ */}
      {tab === "modules" && (
        <div className="sc-modules">
          {overview.modules.map((module) => (
            <article className={"sc-module sc-module-" + module.status} key={module.id}>
              <header>
                <span className={"sc-module-kind sc-module-kind-" + module.kind}>{module.kind}</span>
                <span className={"sc-module-status sc-module-status-" + module.status}>
                  <i />
                  {module.status}
                </span>
              </header>
              <h3>{module.name}</h3>
              <p>{module.description}</p>
              <div className="sc-module-tags">
                {module.capabilities.map((capability) => (
                  <span key={capability}>{capability}</span>
                ))}
              </div>
              <footer>
                <span className="sc-mono">{module.id}@{module.version}</span>
                <strong>{module.events} events</strong>
              </footer>
            </article>
          ))}
        </div>
      )}

      {/* ============ DRAWER ============ */}
      {drawer && (
        <div className="sc-drawer-backdrop" onMouseDown={() => setDrawer(null)}>
          <aside className="sc-drawer" onMouseDown={(event) => event.stopPropagation()}>
            <button className="sc-drawer-close" onClick={() => setDrawer(null)} aria-label="Close">
              ×
            </button>

            {drawer.kind === "event" && (
              <>
                <header className="sc-drawer-heading">
                  <i className={"sc-node sc-node-" + eventTone(drawer.event)} />
                  <div>
                    <small>Event #{drawer.event.sequence} · {fullTime(drawer.event.createdAt)}</small>
                    <h2>{eventTitle(drawer.event)}</h2>
                  </div>
                </header>
                <p className="sc-drawer-reason">
                  {drawer.event.reason ?? "No additional reason was recorded."}
                </p>
                <div className="sc-drawer-chips">
                  <span className={"sc-decision sc-decision-" + eventTone(drawer.event)}>
                    {decisionLabel(drawer.event.decision)}
                  </span>
                  {drawer.event.ruleId && <code className="sc-rule">{drawer.event.ruleId}</code>}
                </div>
                <dl className="sc-facts">
                  <div><dt>Module</dt><dd>{drawer.event.moduleId ?? "audit-ledger"}</dd></div>
                  <div><dt>Stage</dt><dd>{drawer.event.stage ?? "verify"}</dd></div>
                  <div><dt>Human</dt><dd className="sc-mono">{short(drawer.event.humanId, 26)}</dd></div>
                  <div><dt>Agent</dt><dd>{drawer.event.agentName ?? "Platform"}</dd></div>
                  <div><dt>Run</dt><dd className="sc-mono">{short(drawer.event.runId, 22)}</dd></div>
                  <div><dt>Effect</dt><dd className="sc-mono">{short(drawer.event.effectId, 22)}</dd></div>
                </dl>
                {drawer.event.payload && Object.keys(drawer.event.payload).length > 0 && (
                  <div className="sc-drawer-block">
                    <span>Redacted evidence</span>
                    <pre>{JSON.stringify(drawer.event.payload, null, 2)}</pre>
                  </div>
                )}
                <footer className="sc-drawer-footer">
                  <span>
                    HMAC {short(drawer.event.eventMac, 18)}
                    <CopyChip value={drawer.event.eventMac} label="event MAC" />
                  </span>
                  <span className={overview.ledger.valid ? "sc-ok" : "sc-bad"}>
                    chain {overview.ledger.valid ? "intact" : "broken"}
                  </span>
                </footer>
              </>
            )}

            {drawer.kind === "approval" && (
              <>
                <header className="sc-drawer-heading">
                  <i className="sc-node sc-node-warn" />
                  <div>
                    <small>Digest-bound approval</small>
                    <h2>{approvalDetail?.run.prompt ?? "Loading staged manifest…"}</h2>
                  </div>
                </header>
                {approvalDetail ? (
                  <>
                    <p className="sc-drawer-reason">
                      Approving executes exactly this manifest. Any change to the staged content
                      invalidates the digest and the approval.
                    </p>
                    <div className="sc-drawer-chips">
                      <code className="sc-rule sc-mono">
                        {short(approvalDetail.approval.manifestDigest, 30)}
                      </code>
                      <CopyChip value={approvalDetail.approval.manifestDigest} label="digest" />
                      <span className="sc-approval-ttl">
                        expires in {expiresIn(approvalDetail.approval.expiresAt)}
                      </span>
                    </div>
                    <div className="sc-drawer-block">
                      <span>Workspace while pending</span>
                      <div className="sc-hash-proof">
                        <code>{short(approvalDetail.run.workspaceHashBefore, 14)}</code>
                        <b>→</b>
                        <code>{short(approvalDetail.currentWorkspaceHash, 14)}</code>
                        <strong>
                          {approvalDetail.run.workspaceHashBefore ===
                          approvalDetail.currentWorkspaceHash
                            ? "unchanged"
                            : "concurrent change!"}
                        </strong>
                      </div>
                    </div>
                    {approvalDetail.run.effects.map((effect) => {
                      const preview = approvalDetail.previews.find(
                        (item) => item.effectId === effect.id,
                      );
                      return (
                        <div className="sc-drawer-effect" key={effect.id}>
                          <div className="sc-drawer-effect-row">
                            <span className="sc-effect-kind">{effect.type.split(".")[1]}</span>
                            <code>{effect.resource}</code>
                            <span className={"sc-decision sc-decision-warn"}>
                              {decisionLabel(effect.decision)}
                            </span>
                          </div>
                          {preview?.binary ? (
                            <p className="sc-quiet">Binary or linked file · content hidden</p>
                          ) : preview ? (
                            <div className="sc-diff">
                              {preview.before !== null && (
                                <div className="sc-diff-before">
                                  <span>before</span>
                                  <pre>{preview.before || "(empty)"}</pre>
                                </div>
                              )}
                              {preview.after !== null && (
                                <div className="sc-diff-after">
                                  <span>after</span>
                                  <pre>{preview.after || "(empty)"}</pre>
                                </div>
                              )}
                            </div>
                          ) : null}
                        </div>
                      );
                    })}
                    {approvalDetail.run.externalEffects.map((effect) => (
                      <div className="sc-drawer-effect" key={effect.id}>
                        <div className="sc-drawer-effect-row">
                          <span className="sc-effect-kind">{effect.method}</span>
                          <code>{effect.url}</code>
                          <span className="sc-decision sc-decision-warn">
                            {decisionLabel(effect.decision)}
                          </span>
                        </div>
                        {effect.bodyPreview && <pre className="sc-body-preview">{effect.bodyPreview}</pre>}
                      </div>
                    ))}
                    <div className="sc-drawer-actions">
                      <button
                        className="sc-button sc-button-danger"
                        disabled={busy}
                        onClick={() => void decideApproval(drawer.approvalId, "deny")}
                      >
                        Deny & rollback
                      </button>
                      <button
                        className="sc-button sc-button-primary"
                        disabled={busy}
                        onClick={() => void decideApproval(drawer.approvalId, "approve")}
                      >
                        Approve exact manifest
                      </button>
                    </div>
                  </>
                ) : (
                  <p className="sc-quiet">Loading staged diff…</p>
                )}
              </>
            )}
          </aside>
        </div>
      )}
    </section>
  );
}
