import {
  AlertIcon,
  CheckCircleFillIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ClockIcon,
  ContainerIcon,
  CopyIcon,
  DatabaseIcon,
  EyeIcon,
  FileDiffIcon,
  GitBranchIcon,
  GlobeIcon,
  GraphIcon,
  KeyIcon,
  LockIcon,
  PersonIcon,
  PlayIcon,
  PulseIcon,
  SearchIcon,
  ServerIcon,
  ShieldCheckIcon,
  ShieldLockIcon,
  WorkflowIcon,
  XCircleFillIcon,
} from "@primer/octicons-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import type {
  Agent,
  AgentRun,
  Approval,
  EffectPreview,
  SecurityEvent,
  SecurityModule,
  SecurityOverview,
  SecurityStage,
} from "./types";

type Tab = "runs" | "approvals" | "modules" | "architecture";
type Tone = "success" | "attention" | "danger" | "neutral";

const lifecycle: Array<{
  id: string;
  label: string;
  icon: typeof KeyIcon;
  stages: SecurityStage[];
}> = [
  { id: "identity", label: "Identity", icon: KeyIcon, stages: ["identity"] },
  { id: "runtime", label: "Runtime", icon: ContainerIcon, stages: ["runtime"] },
  { id: "policy", label: "Policy", icon: ShieldLockIcon, stages: ["observe", "policy"] },
  { id: "approval", label: "Approval", icon: PersonIcon, stages: ["approval"] },
  { id: "effect", label: "Effect", icon: PlayIcon, stages: ["execute"] },
  { id: "evidence", label: "Evidence", icon: DatabaseIcon, stages: ["recover", "verify"] },
];

const eventNames: Record<string, string> = {
  "identity.control_plane_ready": "Identity plane ready",
  "identity.agent_provisioned": "Agent principal provisioned",
  "identity.agent_activated": "Agent principal activated",
  "identity.agent_revoked": "Agent principal revoked",
  "identity.delegation_issued": "Run capability issued",
  "identity.delegation_revoked": "Run capability revoked",
  "run.staged": "Disposable workspace staged",
  "runtime.command_execution": "Command executed",
  "runtime.file_change": "File change observed",
  "runtime.mcp_tool_call": "Tool call observed",
  "effect.reviewed": "File effect reviewed",
  "external_effect.reviewed": "External request reviewed",
  "external_effect.executed": "External request executed",
  "external_effect.execution_uncertain": "External outcome uncertain",
  "approval.requested": "Human approval requested",
  "approval.approved": "Approval granted",
  "approval.denied": "Approval denied",
  "approval.expired": "Approval expired",
  "run.committed": "Manifest committed",
  "run.rolled_back": "Workspace restored",
  "run.failed": "Run failed safely",
  "run.cancelled": "Run cancelled",
  "run.external_outcome_uncertain": "External outcome uncertain",
  "trace.mismatch": "Trace mismatch detected",
  "ledger.verified": "Audit ledger verified",
  "service.initialized": "Control plane initialized",
};

interface ApprovalDetail {
  approval: Approval;
  run: AgentRun;
  previews: EffectPreview[];
  currentWorkspaceHash: string;
}

interface SecurityCenterProps {
  initialAgentId: string | null;
  initialRunId?: string | null;
  onOpenRun: (agentId: string, run: AgentRun) => void;
}

function titleFor(event: SecurityEvent) {
  return eventNames[event.type] ?? event.type.replaceAll("_", " ").replaceAll(".", " / ");
}

function toneFor(event: SecurityEvent): Tone {
  if (["critical", "high"].includes(event.severity ?? "") || ["deny", "denied"].includes(event.decision ?? "")) return "danger";
  if (["require_approval", "expired", "uncertain", "revoked"].includes(event.decision ?? "")) return "attention";
  if (["allow", "approved", "issued"].includes(event.decision ?? "")) return "success";
  return "neutral";
}

function runTone(status: AgentRun["status"]): Tone {
  if (["failed", "rolled_back", "cancelled"].includes(status)) return "danger";
  if (["awaiting_approval", "reviewing_effects", "rolling_back"].includes(status)) return "attention";
  if (status === "completed") return "success";
  return "neutral";
}

function short(value: string | null | undefined, length = 10) {
  if (!value) return "None";
  return value.length > length ? value.slice(0, length) + "…" : value;
}

function fullTime(value: string | null | undefined) {
  if (!value) return "Not recorded";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function elapsed(start: string | null | undefined, end: string | null | undefined) {
  if (!start) return "Pending";
  const milliseconds = Date.parse(end ?? new Date().toISOString()) - Date.parse(start);
  if (milliseconds < 1_000) return milliseconds + " ms";
  if (milliseconds < 60_000) return (milliseconds / 1_000).toFixed(1) + " s";
  return (milliseconds / 60_000).toFixed(1) + " min";
}

function decisionText(value: string | null | undefined) {
  if (!value) return "observed";
  if (value === "require_approval") return "review";
  return value.replaceAll("_", " ");
}

function eventResource(event: SecurityEvent) {
  const payload = event.payload ?? {};
  const candidate = payload.resource ?? payload.url ?? payload.summary;
  return typeof candidate === "string" ? candidate : null;
}

function CopyControl({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="secx-icon-button"
      type="button"
      aria-label={copied ? "Copied" : "Copy " + label}
      title={copied ? "Copied" : "Copy " + label}
      onClick={(event) => {
        event.stopPropagation();
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1_200);
        });
      }}
    >
      {copied ? <CheckIcon size={14} /> : <CopyIcon size={14} />}
    </button>
  );
}

export function SecurityCenter({ initialAgentId, initialRunId, onOpenRun }: SecurityCenterProps) {
  const [tab, setTab] = useState<Tab>("runs");
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [runsByAgent, setRunsByAgent] = useState<Record<string, AgentRun[]>>({});
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(initialAgentId);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(initialRunId ?? null);
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null);
  const [selectedModuleId, setSelectedModuleId] = useState<string | null>(null);
  const [stageFilter, setStageFilter] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [approvalDetail, setApprovalDetail] = useState<ApprovalDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ledgerStatus, setLedgerStatus] = useState<string | null>(null);
  const selectionRef = useRef({ agentId: selectedAgentId, runId: selectedRunId });
  selectionRef.current = { agentId: selectedAgentId, runId: selectedRunId };

  const refreshStructure = useCallback(async () => {
    try {
      const [nextOverview, agentResponse, approvalResponse] = await Promise.all([
        api.securityOverview(),
        api.listAgents(),
        api.approvals(),
      ]);
      const entries = await Promise.all(
        agentResponse.agents.map(async (agent) => [agent.id, (await api.runs(agent.id)).runs] as const),
      );
      const nextRuns = Object.fromEntries(entries);
      setOverview(nextOverview);
      setAgents(agentResponse.agents);
      setRunsByAgent(nextRuns);
      setApprovals(approvalResponse.approvals);
      setSelectedModuleId((current) => current ?? nextOverview.modules[0]?.id ?? null);
      setSelectedAgentId((current) => {
        const agentId = current && agentResponse.agents.some((agent) => agent.id === current)
          ? current
          : (initialAgentId && agentResponse.agents.some((agent) => agent.id === initialAgentId)
              ? initialAgentId
              : agentResponse.agents[0]?.id ?? null);
        if (agentId) {
          setSelectedRunId((currentRun) => {
            const available = nextRuns[agentId] ?? [];
            if (currentRun && available.some((run) => run.id === currentRun)) return currentRun;
            if (initialRunId && available.some((run) => run.id === initialRunId)) return initialRunId;
            return available[0]?.id ?? null;
          });
        }
        return agentId;
      });
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  }, [initialAgentId, initialRunId]);

  useEffect(() => {
    void refreshStructure();
    const timer = window.setInterval(() => void refreshStructure(), 5_000);
    return () => window.clearInterval(timer);
  }, [refreshStructure]);

  useEffect(() => {
    let active = true;
    const refreshEvents = async () => {
      try {
        const query = new URLSearchParams({ limit: "500" });
        if (selectionRef.current.agentId) query.set("agentId", selectionRef.current.agentId);
        if (selectionRef.current.runId) query.set("runId", selectionRef.current.runId);
        const response = await api.securityEvents(query.toString());
        if (!active) return;
        setEvents(response.events);
        setSelectedEventId((current) => {
          if (current && response.events.some((event) => event.sequence === current)) return current;
          return response.events.reduce((highest, event) => Math.max(highest, event.sequence), 0) || null;
        });
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
  }, [selectedAgentId, selectedRunId]);

  const agentById = useMemo(() => new Map(agents.map((agent) => [agent.id, agent])), [agents]);
  const selectedAgent = selectedAgentId ? agentById.get(selectedAgentId) ?? null : null;
  const selectedRun = selectedAgentId && selectedRunId
    ? (runsByAgent[selectedAgentId] ?? []).find((run) => run.id === selectedRunId) ?? null
    : null;
  const selectedEvent = selectedEventId
    ? events.find((event) => event.sequence === selectedEventId) ?? null
    : null;
  const selectedModule = overview?.modules.find((module) => module.id === selectedModuleId) ?? null;

  const sessions = useMemo(() => {
    if (!selectedAgent) return [];
    const groups = new Map<string, AgentRun[]>();
    for (const run of runsByAgent[selectedAgent.id] ?? []) {
      const id = run.pendingThreadId ?? selectedAgent.codexThreadId ?? "unassigned";
      groups.set(id, [...(groups.get(id) ?? []), run]);
    }
    return [...groups.entries()].map(([id, runs]) => ({ id, runs }));
  }, [runsByAgent, selectedAgent]);

  const stageCounts = useMemo(() => {
    return new Map(lifecycle.map((lane) => [
      lane.id,
      events.filter((event) => event.stage && lane.stages.includes(event.stage)).length,
    ]));
  }, [events]);

  const visibleEvents = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const lane = lifecycle.find((item) => item.id === stageFilter);
    return [...events]
      .sort((a, b) => a.sequence - b.sequence)
      .filter((event) => {
        if (lane && !(event.stage && lane.stages.includes(event.stage))) return false;
        if (decisionFilter !== "all") {
          if (decisionFilter === "allow" && !["allow", "approved", "issued"].includes(event.decision ?? "")) return false;
          if (decisionFilter === "review" && event.decision !== "require_approval") return false;
          if (decisionFilter === "deny" && !["deny", "denied"].includes(event.decision ?? "")) return false;
        }
        if (!needle) return true;
        return [titleFor(event), event.reason, event.ruleId, event.moduleId, eventResource(event)]
          .some((value) => value?.toLowerCase().includes(needle));
      });
  }, [decisionFilter, events, search, stageFilter]);

  const pendingApprovals = approvals.filter((approval) => approval.status === "pending");
  const moduleEvents = selectedModule
    ? overview?.recentEvents.filter((event) => event.moduleId === selectedModule.id) ?? []
    : [];

  const openApproval = async (approvalId: string) => {
    try {
      setApprovalDetail(await api.approval(approvalId));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const decideApproval = async (approvalId: string, decision: "approve" | "deny") => {
    setBusy(true);
    try {
      await (decision === "approve" ? api.approve(approvalId) : api.deny(approvalId));
      setApprovalDetail(null);
      await refreshStructure();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const verifyLedger = async () => {
    setLedgerStatus("Verifying");
    try {
      const result = await api.verifyLedger();
      setLedgerStatus(result.valid ? `Verified ${result.events} events` : `Broken at ${result.brokenAt ?? "unknown"}`);
      window.setTimeout(() => setLedgerStatus(null), 4_000);
    } catch (reason) {
      setLedgerStatus(reason instanceof Error ? reason.message : String(reason));
    }
  };

  if (!overview) {
    return (
      <section className="secx secx-loading" aria-live="polite">
        <div className="secx-skeleton secx-skeleton-title" />
        <div className="secx-skeleton secx-skeleton-nav" />
        <div className="secx-skeleton secx-skeleton-body" />
      </section>
    );
  }

  const tabs: Array<{ id: Tab; label: string; icon: typeof PulseIcon; count?: number }> = [
    { id: "runs", label: "Run traces", icon: PulseIcon },
    { id: "approvals", label: "Approvals", icon: PersonIcon, count: pendingApprovals.length },
    { id: "modules", label: "Modules", icon: GitBranchIcon, count: overview.modules.length },
    { id: "architecture", label: "Architecture", icon: GraphIcon },
  ];

  return (
    <section className="secx">
      <header className="secx-header">
        <div className="secx-title">
          <span className="secx-product-mark"><ShieldCheckIcon size={21} /></span>
          <div>
            <h1>Security Center</h1>
            <p>Investigate every Agent effect from delegation to evidence.</p>
          </div>
        </div>
        <div className="secx-header-actions">
          <span className={"secx-posture secx-tone-" + (overview.posture === "protected" ? "success" : "danger")}>
            {overview.posture === "protected" ? <CheckCircleFillIcon size={14} /> : <AlertIcon size={14} />}
            {overview.posture === "protected" ? "Protected" : "Degraded"}
          </span>
          <button className="secx-ledger" onClick={() => void verifyLedger()}>
            <LockIcon size={14} />
            {ledgerStatus ?? `${overview.ledger.events} signed events`}
          </button>
        </div>
      </header>

      {error && (
        <div className="secx-alert" role="alert">
          <AlertIcon size={16} />
          <span>{error}</span>
          <button onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      <div className="secx-metrics" aria-label="Security overview">
        <div><span>Runs monitored</span><strong>{overview.totals.runs}</strong><small>{overview.totals.agents} Agents</small></div>
        <div><span>Effects mediated</span><strong>{overview.totals.effects}</strong><small>Files and HTTP</small></div>
        <div><span>Policy blocks</span><strong className={overview.totals.blocked ? "secx-danger-text" : ""}>{overview.totals.blocked}</strong><small>{overview.totals.rolledBack} restored</small></div>
        <div><span>Capabilities issued</span><strong>{overview.identity.issuedCapabilities}</strong><small>{overview.identity.activeAgentPrincipals} active principals</small></div>
      </div>

      <nav className="secx-tabs" aria-label="Security Center sections">
        {tabs.map((item) => {
          const Icon = item.icon;
          return (
            <button key={item.id} className={tab === item.id ? "active" : ""} onClick={() => setTab(item.id)}>
              <Icon size={15} />
              {item.label}
              {Boolean(item.count) && <span>{item.count}</span>}
            </button>
          );
        })}
      </nav>

      {tab === "runs" && (
        <div className="secx-workbench">
          <aside className="secx-run-index">
            <div className="secx-panel-title">
              <div><h2>Execution context</h2><p>Agent / Session / Run</p></div>
            </div>
            <div className="secx-agent-switcher">
              <label htmlFor="secx-agent-select">Agent</label>
              <div>
                <ServerIcon size={15} />
                <select
                  id="secx-agent-select"
                  value={selectedAgentId ?? ""}
                  onChange={(event) => {
                    const agentId = event.target.value || null;
                    setSelectedAgentId(agentId);
                    setSelectedRunId(agentId ? runsByAgent[agentId]?.[0]?.id ?? null : null);
                    setStageFilter(null);
                  }}
                >
                  {agents.length === 0 && <option value="">No Agents</option>}
                  {agents.map((agent) => <option value={agent.id} key={agent.id}>{agent.name}</option>)}
                </select>
                <ChevronDownIcon size={14} />
              </div>
            </div>
            <div className="secx-session-list">
              {sessions.length === 0 ? (
                <div className="secx-compact-empty">
                  <WorkflowIcon size={20} />
                  <p>No Runs for this Agent.</p>
                </div>
              ) : sessions.map((session) => (
                <section className="secx-session" key={session.id}>
                  <header><GitBranchIcon size={13} /><span>Session</span><code>{short(session.id, 8)}</code></header>
                  {session.runs.map((run) => (
                    <button
                      className={"secx-run-item" + (run.id === selectedRunId ? " active" : "")}
                      key={run.id}
                      onClick={() => {
                        setSelectedRunId(run.id);
                        setStageFilter(null);
                      }}
                    >
                      <span className={"secx-run-icon secx-tone-" + runTone(run.status)}>
                        {run.status === "completed" ? <CheckCircleFillIcon size={13} /> : run.status === "rolled_back" ? <XCircleFillIcon size={13} /> : <ClockIcon size={13} />}
                      </span>
                      <span><strong>{run.prompt}</strong><small>{fullTime(run.createdAt)} · {run.status.replaceAll("_", " ")}</small></span>
                      <ChevronRightIcon size={14} />
                    </button>
                  ))}
                </section>
              ))}
            </div>
          </aside>

          <main className="secx-trace-panel">
            {selectedRun ? (
              <>
                <header className="secx-run-header">
                  <div>
                    <div className="secx-breadcrumb"><span>{selectedAgent?.name}</span><ChevronRightIcon size={12} /><code>{short(selectedRun.id, 12)}</code></div>
                    <h2>{selectedRun.prompt}</h2>
                    <p>{fullTime(selectedRun.startedAt ?? selectedRun.createdAt)} · {elapsed(selectedRun.startedAt, selectedRun.completedAt)}</p>
                  </div>
                  <div className="secx-run-actions">
                    <span className={"secx-status secx-tone-" + runTone(selectedRun.status)}>{selectedRun.status.replaceAll("_", " ")}</span>
                    {selectedAgent && <button onClick={() => onOpenRun(selectedAgent.id, selectedRun)}>Open Playground</button>}
                  </div>
                </header>

                <div className="secx-run-proof">
                  <div><FileDiffIcon size={15} /><span>Effects</span><strong>{selectedRun.effects.length + selectedRun.externalEffects.length}</strong></div>
                  <div><ShieldLockIcon size={15} /><span>Policy</span><strong>{short(selectedRun.policyVersion, 16)}</strong></div>
                  <div><KeyIcon size={15} /><span>Capability</span><strong>{short(selectedRun.securityContextId, 12)}</strong></div>
                  <div><LockIcon size={15} /><span>Manifest</span><strong>{short(selectedRun.manifestDigest, 12)}</strong>{selectedRun.manifestDigest && <CopyControl value={selectedRun.manifestDigest} label="manifest digest" />}</div>
                </div>

                <section className="secx-lifecycle">
                  <header><h3>Run path</h3><p>Click a stage to isolate its evidence.</p></header>
                  <div className="secx-lifecycle-track">
                    {lifecycle.map((lane, index) => {
                      const Icon = lane.icon;
                      const count = stageCounts.get(lane.id) ?? 0;
                      const laneEvents = events.filter((event) => event.stage && lane.stages.includes(event.stage));
                      const tone = laneEvents.some((event) => toneFor(event) === "danger") ? "danger"
                        : laneEvents.some((event) => toneFor(event) === "attention") ? "attention"
                          : count ? "success" : "neutral";
                      return (
                        <button
                          key={lane.id}
                          className={"secx-stage secx-tone-" + tone + (stageFilter === lane.id ? " active" : "")}
                          onClick={() => setStageFilter(stageFilter === lane.id ? null : lane.id)}
                        >
                          {index < lifecycle.length - 1 && <i className="secx-stage-connector" />}
                          <span className="secx-stage-icon"><Icon size={16} /></span>
                          <strong>{lane.label}</strong>
                          <small>{count ? `${count} events` : "Not reached"}</small>
                        </button>
                      );
                    })}
                  </div>
                </section>

                <section className="secx-event-stream">
                  <div className="secx-event-toolbar">
                    <div><h3>Trace events</h3><span>{visibleEvents.length} shown</span></div>
                    <div className="secx-event-filters">
                      <div className="secx-search"><SearchIcon size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search trace" aria-label="Search trace" /></div>
                      <select value={decisionFilter} onChange={(event) => setDecisionFilter(event.target.value)} aria-label="Decision filter">
                        <option value="all">All decisions</option>
                        <option value="allow">Allowed</option>
                        <option value="review">Review</option>
                        <option value="deny">Denied</option>
                      </select>
                    </div>
                  </div>
                  <div className="secx-event-columns" aria-hidden="true"><span>Time</span><span>Stage</span><span>Event</span><span>Decision</span></div>
                  <div className="secx-event-list">
                    {visibleEvents.length === 0 ? (
                      <div className="secx-empty"><EyeIcon size={28} /><h3>No trace events</h3><p>Run the Agent once to populate this execution path.</p></div>
                    ) : visibleEvents.map((event) => {
                      const lane = lifecycle.find((item) => event.stage && item.stages.includes(event.stage));
                      return (
                        <button key={event.sequence} className={"secx-event-row" + (selectedEventId === event.sequence ? " active" : "")} onClick={() => setSelectedEventId(event.sequence)}>
                          <time>{new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(event.createdAt))}</time>
                          <span className="secx-event-stage">{lane?.label ?? event.stage ?? "System"}</span>
                          <span className="secx-event-summary"><strong>{titleFor(event)}</strong><small>{eventResource(event) ?? event.reason ?? "Evidence recorded"}</small></span>
                          <span className={"secx-decision secx-tone-" + toneFor(event)}>{decisionText(event.decision)}</span>
                        </button>
                      );
                    })}
                  </div>
                </section>
              </>
            ) : (
              <div className="secx-empty secx-empty-large">
                <PulseIcon size={34} />
                <h2>Select a Run to investigate</h2>
                <p>Each Run keeps its own identity, policy, effects and evidence.</p>
              </div>
            )}
          </main>

          <aside className="secx-inspector">
            <div className="secx-panel-title"><div><h2>Evidence</h2><p>Selected trace event</p></div>{selectedEvent && <span>#{selectedEvent.sequence}</span>}</div>
            {selectedEvent ? (
              <div className="secx-inspector-content">
                <header><span className={"secx-evidence-icon secx-tone-" + toneFor(selectedEvent)}><ShieldCheckIcon size={17} /></span><div><h3>{titleFor(selectedEvent)}</h3><p>{fullTime(selectedEvent.createdAt)}</p></div></header>
                <p className="secx-reason">{selectedEvent.reason ?? "This event was recorded by the security evidence ledger."}</p>
                <dl>
                  <div><dt>Decision</dt><dd><span className={"secx-decision secx-tone-" + toneFor(selectedEvent)}>{decisionText(selectedEvent.decision)}</span></dd></div>
                  <div><dt>Module</dt><dd>{selectedEvent.moduleId ?? "audit-ledger"}</dd></div>
                  <div><dt>Rule</dt><dd>{selectedEvent.ruleId ?? "No rule"}</dd></div>
                  <div><dt>Human</dt><dd><code>{short(selectedEvent.humanId, 20)}</code></dd></div>
                  <div><dt>Agent</dt><dd>{selectedEvent.agentName ?? "Platform"}</dd></div>
                  <div><dt>Effect</dt><dd><code>{short(selectedEvent.effectId, 20)}</code></dd></div>
                </dl>
                {selectedEvent.payload && Object.keys(selectedEvent.payload).length > 0 && (
                  <section className="secx-payload"><h4>Redacted payload</h4><pre>{JSON.stringify(selectedEvent.payload, null, 2)}</pre></section>
                )}
                <footer><div><LockIcon size={13} /><span>Ledger MAC</span></div><code>{short(selectedEvent.eventMac, 25)}</code><CopyControl value={selectedEvent.eventMac} label="event MAC" /></footer>
              </div>
            ) : <div className="secx-compact-empty"><EyeIcon size={24} /><p>Select an event to inspect its rule, identity and ledger proof.</p></div>}
          </aside>
        </div>
      )}

      {tab === "approvals" && (
        <div className="secx-page">
          <header className="secx-page-header"><div><h2>Human approvals</h2><p>Review the exact measured manifest before any high-risk effect persists.</p></div><span>{pendingApprovals.length} pending</span></header>
          <div className="secx-approval-list">
            {approvals.length === 0 ? <div className="secx-empty secx-empty-large"><PersonIcon size={34} /><h2>No approval requests</h2><p>High-risk effects will pause here with a digest-bound review.</p></div>
              : approvals.map((approval) => {
                const run = (runsByAgent[approval.agentId] ?? []).find((item) => item.id === approval.runId);
                return (
                  <button className="secx-approval-row" key={approval.id} onClick={() => void openApproval(approval.id)}>
                    <span className={"secx-approval-icon secx-tone-" + (approval.status === "pending" ? "attention" : approval.status === "approved" ? "success" : "danger")}><PersonIcon size={16} /></span>
                    <span><strong>{run?.prompt ?? "Staged manifest"}</strong><small>{agentById.get(approval.agentId)?.name ?? "Agent"} · digest {short(approval.manifestDigest, 16)}</small></span>
                    <span className="secx-status">{approval.status}</span>
                    <time>{fullTime(approval.createdAt)}</time>
                    <ChevronRightIcon size={15} />
                  </button>
                );
              })}
          </div>
        </div>
      )}

      {tab === "modules" && (
        <div className="secx-module-workbench">
          <aside className="secx-module-index">
            <div className="secx-panel-title"><div><h2>Security modules</h2><p>Composable enforcement chain</p></div></div>
            {overview.modules.map((module) => (
              <button className={selectedModuleId === module.id ? "active" : ""} key={module.id} onClick={() => setSelectedModuleId(module.id)}>
                <span className="secx-module-icon">{moduleIcon(module)}</span>
                <span><strong>{module.name}</strong><small>{module.kind} · {module.events} events</small></span>
                <span className={"secx-module-state " + module.status}>{module.status}</span>
              </button>
            ))}
          </aside>
          <main className="secx-module-detail">
            {selectedModule ? (
              <>
                <header><span className="secx-module-hero-icon">{moduleIcon(selectedModule, 24)}</span><div><span>{selectedModule.kind} module</span><h2>{selectedModule.name}</h2><p>{selectedModule.description}</p></div></header>
                <div className="secx-module-meta"><div><span>Plugin ID</span><code>{selectedModule.id}</code></div><div><span>Version</span><code>{selectedModule.version}</code></div><div><span>Status</span><strong>{selectedModule.status}</strong></div><div><span>Observed events</span><strong>{selectedModule.events}</strong></div></div>
                <section><h3>Capabilities</h3><div className="secx-capabilities">{selectedModule.capabilities.map((capability) => <span key={capability}><CheckIcon size={13} />{capability}</span>)}</div></section>
                <section><h3>Recent activity</h3>{moduleEvents.length ? <div className="secx-module-events">{moduleEvents.map((event) => <button key={event.sequence} onClick={() => { setTab("runs"); setSelectedAgentId(event.agentId ?? null); setSelectedRunId(event.runId ?? null); setSelectedEventId(event.sequence); }}><span className={"secx-tone-" + toneFor(event)}><PulseIcon size={13} /></span><span><strong>{titleFor(event)}</strong><small>{event.reason ?? fullTime(event.createdAt)}</small></span><ChevronRightIcon size={14} /></button>)}</div> : <p className="secx-muted">No recent activity for this module.</p>}</section>
              </>
            ) : <div className="secx-empty"><GitBranchIcon size={28} /><h3>Select a module</h3></div>}
          </main>
        </div>
      )}

      {tab === "architecture" && (
        <div className="secx-architecture">
          <header className="secx-page-header"><div><h2>Zero-trust middleware architecture</h2><p>Explore trust boundaries, the primary Run path and the controlled effect boundary.</p></div><button onClick={() => window.open("/diagrams/aeg-architecture.html", "_blank", "noopener,noreferrer")}>Open full screen</button></header>
          <iframe src="/diagrams/aeg-architecture.html" title="Agent Effect Gateway architecture" />
        </div>
      )}

      {approvalDetail && (
        <div className="secx-modal-backdrop" onMouseDown={() => setApprovalDetail(null)}>
          <article className="secx-modal" onMouseDown={(event) => event.stopPropagation()}>
            <header><div><span>Digest-bound approval</span><h2>{approvalDetail.run.prompt}</h2></div><button aria-label="Close" onClick={() => setApprovalDetail(null)}>×</button></header>
            <div className="secx-modal-digest"><LockIcon size={15} /><code>{approvalDetail.approval.manifestDigest}</code><CopyControl value={approvalDetail.approval.manifestDigest} label="manifest digest" /></div>
            <section className="secx-effect-review">
              {approvalDetail.run.effects.map((effect) => {
                const preview = approvalDetail.previews.find((item) => item.effectId === effect.id);
                return <article key={effect.id}><header><FileDiffIcon size={15} /><strong>{effect.resource}</strong><span>{effect.type}</span></header>{preview && !preview.binary && <div className="secx-diff"><div><span>Before</span><pre>{preview.before || "(empty)"}</pre></div><div><span>After</span><pre>{preview.after || "(empty)"}</pre></div></div>}</article>;
              })}
              {approvalDetail.run.externalEffects.map((effect) => <article key={effect.id}><header><GlobeIcon size={15} /><strong>{effect.method} {effect.url}</strong><span>HTTP</span></header>{effect.bodyPreview && <pre className="secx-http-body">{effect.bodyPreview}</pre>}</article>)}
            </section>
            <footer><button className="secx-danger-button" disabled={busy} onClick={() => void decideApproval(approvalDetail.approval.id, "deny")}>Deny and restore</button><button className="secx-primary-button" disabled={busy} onClick={() => void decideApproval(approvalDetail.approval.id, "approve")}>Approve manifest</button></footer>
          </article>
        </div>
      )}
    </section>
  );
}

function moduleIcon(module: SecurityModule, size = 17) {
  if (module.kind === "identity") return <KeyIcon size={size} />;
  if (module.kind === "runtime") return <ContainerIcon size={size} />;
  if (module.kind === "effect") return <FileDiffIcon size={size} />;
  if (module.kind === "approval") return <PersonIcon size={size} />;
  return <DatabaseIcon size={size} />;
}
