import {
  AlertIcon,
  BeakerIcon,
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
  GearIcon,
  GitBranchIcon,
  GlobeIcon,
  GraphIcon,
  KeyIcon,
  LockIcon,
  PersonIcon,
  PulseIcon,
  SearchIcon,
  ServerIcon,
  ShieldCheckIcon,
  ShieldLockIcon,
  SlidersIcon,
  TrashIcon,
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
  PolicyProfile,
  PolicySimulation,
  PolicyTemplate,
  SecurityEvent,
  SecurityModule,
  SecurityOverview,
  SecurityStage,
} from "./types";

type Tab = "overview" | "activity" | "approvals" | "policies" | "modules" | "architecture";
type Tone = "success" | "attention" | "danger" | "neutral";
type PolicyBundle = {
  profile: PolicyProfile;
  templates: Record<Exclude<PolicyTemplate, "custom">, PolicyProfile>;
  hardDenyRules: string[];
  pendingApprovals: number;
};

const checkpoints: Array<{ id: string; label: string; detail: string; icon: typeof KeyIcon; stages: SecurityStage[] }> = [
  { id: "intake", label: "Intake", detail: "Identity and analyzers", icon: KeyIcon, stages: ["identity", "observe"] },
  { id: "runtime", label: "Runtime", detail: "Isolated execution", icon: ContainerIcon, stages: ["runtime"] },
  { id: "review", label: "Effect review", detail: "Measured diff and policy", icon: ShieldLockIcon, stages: ["policy"] },
  { id: "approval", label: "Approval", detail: "Digest-bound decision", icon: PersonIcon, stages: ["approval"] },
  { id: "commit", label: "Commit", detail: "Atomic persist or restore", icon: DatabaseIcon, stages: ["execute", "recover", "verify"] },
];

const eventNames: Record<string, string> = {
  "identity.control_plane_ready": "Identity plane ready",
  "identity.agent_provisioned": "Agent principal provisioned",
  "identity.agent_activated": "Agent principal activated",
  "identity.agent_revoked": "Agent principal revoked",
  "identity.delegation_issued": "Run capability issued",
  "identity.delegation_revoked": "Run capability revoked",
  "intake.accepted": "Intake accepted",
  "intake.reviewed": "Intake signal reviewed",
  "run.staged": "Disposable workspace staged",
  "runtime.command_execution": "Command executed",
  "runtime.file_change": "File change observed",
  "runtime.mcp_tool_call": "Tool call observed",
  "effect.reviewed": "File effect reviewed",
  "external_effect.reviewed": "External request reviewed",
  "external_effect.executed": "External request executed",
  "approval.requested": "Human approval requested",
  "approval.approved": "Approval granted",
  "approval.denied": "Approval denied",
  "approval.expired": "Approval expired",
  "policy.updated": "Agent policy updated",
  "policy.template_applied": "Policy template applied",
  "module.configured": "Security module configured",
  "run.committed": "Manifest committed",
  "run.rolled_back": "Workspace restored",
  "run.failed": "Run failed safely",
  "run.cancelled": "Run cancelled",
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
  if (["allow", "approved", "issued", "enabled"].includes(event.decision ?? "")) return "success";
  return "neutral";
}

function runTone(status: AgentRun["status"]): Tone {
  if (["failed", "rolled_back", "cancelled"].includes(status)) return "danger";
  if (["awaiting_approval", "reviewing_effects", "rolling_back"].includes(status)) return "attention";
  return status === "completed" ? "success" : "neutral";
}

function short(value: string | null | undefined, length = 10) {
  if (!value) return "None";
  return value.length > length ? value.slice(0, length) + "…" : value;
}

function fullTime(value: string | null | undefined) {
  if (!value) return "Not recorded";
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(value));
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
  return value === "require_approval" ? "review" : value.replaceAll("_", " ");
}

function eventResource(event: SecurityEvent) {
  const candidate = event.payload?.resource ?? event.payload?.url ?? event.payload?.summary;
  return typeof candidate === "string" ? candidate : null;
}

function moduleIcon(module: SecurityModule, size = 17) {
  if (module.kind === "policy") return <ShieldLockIcon size={size} />;
  if (module.kind === "gateway") return <ContainerIcon size={size} />;
  if (module.kind === "analyzer") return <BeakerIcon size={size} />;
  if (module.kind === "approval") return <PersonIcon size={size} />;
  return <DatabaseIcon size={size} />;
}

function CopyControl({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return <button className="secx-icon-button" type="button" aria-label={copied ? "Copied" : "Copy " + label} onClick={(event) => {
    event.stopPropagation();
    void navigator.clipboard.writeText(value).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1_200); });
  }}>{copied ? <CheckIcon size={14} /> : <CopyIcon size={14} />}</button>;
}

function ChipEditor({ label, tone, values, onChange, placeholder = "Add glob and press Enter" }: { label: string; tone: Tone; values: string[]; onChange: (values: string[]) => void; placeholder?: string }) {
  const [input, setInput] = useState("");
  const add = () => {
    const value = input.trim();
    if (!value || values.includes(value)) return;
    onChange([...values, value]);
    setInput("");
  };
  return <section className={"secx-rule-group secx-rule-" + tone}>
    <header><span>{label}</span><small>{values.length} rules</small></header>
    <div className="secx-chip-input">{values.map((value) => <span className="secx-rule-chip" key={value}><code>{value}</code><button type="button" aria-label={"Remove " + value} onClick={() => onChange(values.filter((item) => item !== value))}><TrashIcon size={11} /></button></span>)}<input value={input} placeholder={placeholder} onChange={(event) => setInput(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === ",") { event.preventDefault(); add(); } }} onBlur={add} /></div>
  </section>;
}

export function SecurityCenter({ initialAgentId, initialRunId, onOpenRun }: SecurityCenterProps) {
  const [tab, setTab] = useState<Tab>(initialRunId ? "activity" : "overview");
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [runsByAgent, setRunsByAgent] = useState<Record<string, AgentRun[]>>({});
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [modules, setModules] = useState<SecurityModule[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(initialAgentId);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(initialRunId ?? null);
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null);
  const [selectedModuleId, setSelectedModuleId] = useState<string | null>(null);
  const [stageFilter, setStageFilter] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [approvalDetail, setApprovalDetail] = useState<ApprovalDetail | null>(null);
  const [policyBundle, setPolicyBundle] = useState<PolicyBundle | null>(null);
  const [policyDraft, setPolicyDraft] = useState<PolicyProfile | null>(null);
  const [simulationKind, setSimulationKind] = useState<"file" | "http">("file");
  const [simulationResource, setSimulationResource] = useState("src/index.ts");
  const [simulationMethod, setSimulationMethod] = useState("GET");
  const [simulation, setSimulation] = useState<PolicySimulation | null>(null);
  const [policyConfirm, setPolicyConfirm] = useState(false);
  const [moduleConfig, setModuleConfig] = useState<Record<string, unknown>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [ledgerStatus, setLedgerStatus] = useState<string | null>(null);
  const selectionRef = useRef({ agentId: selectedAgentId, runId: selectedRunId });
  selectionRef.current = { agentId: selectedAgentId, runId: selectedRunId };

  const refreshStructure = useCallback(async () => {
    try {
      const [nextOverview, agentResponse, approvalResponse, moduleResponse] = await Promise.all([api.securityOverview(), api.listAgents(), api.approvals(), api.securityModules()]);
      const entries = await Promise.all(agentResponse.agents.map(async (agent) => [agent.id, (await api.runs(agent.id)).runs] as const));
      const nextRuns = Object.fromEntries(entries);
      setOverview(nextOverview);
      setAgents(agentResponse.agents);
      setRunsByAgent(nextRuns);
      setApprovals(approvalResponse.approvals);
      setModules(moduleResponse.modules.map((module) => ({ ...module, events: nextOverview.modules.find((item) => item.id === module.id)?.events ?? 0 })));
      setSelectedModuleId((current) => current ?? moduleResponse.modules[0]?.id ?? null);
      setSelectedAgentId((current) => {
        const id = current && agentResponse.agents.some((agent) => agent.id === current) ? current : initialAgentId && agentResponse.agents.some((agent) => agent.id === initialAgentId) ? initialAgentId : agentResponse.agents[0]?.id ?? null;
        if (id) setSelectedRunId((runId) => runId && nextRuns[id]?.some((run) => run.id === runId) ? runId : initialRunId && nextRuns[id]?.some((run) => run.id === initialRunId) ? initialRunId : nextRuns[id]?.[0]?.id ?? null);
        return id;
      });
      setError(null);
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
  }, [initialAgentId, initialRunId]);

  useEffect(() => {
    void refreshStructure();
    const timer = window.setInterval(() => void refreshStructure(), 5_000);
    return () => window.clearInterval(timer);
  }, [refreshStructure]);

  useEffect(() => {
    if (!selectedAgentId) { setPolicyBundle(null); setPolicyDraft(null); return; }
    let active = true;
    void api.policy(selectedAgentId).then((bundle) => { if (active) { setPolicyBundle(bundle); setPolicyDraft(structuredClone(bundle.profile)); } }).catch((reason) => active && setError(reason instanceof Error ? reason.message : String(reason)));
    return () => { active = false; };
  }, [selectedAgentId]);

  useEffect(() => {
    const module = modules.find((item) => item.id === selectedModuleId);
    setModuleConfig(module ? structuredClone(module.config) : {});
  }, [modules, selectedModuleId]);

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const query = new URLSearchParams({ limit: "500" });
        if (tab === "activity" && selectionRef.current.agentId) query.set("agentId", selectionRef.current.agentId);
        if (tab === "activity" && selectionRef.current.runId) query.set("runId", selectionRef.current.runId);
        const response = await api.securityEvents(query.toString());
        if (!active) return;
        setEvents(response.events);
        setSelectedEventId((current) => current && response.events.some((event) => event.sequence === current) ? current : response.events.at(-1)?.sequence ?? null);
      } catch (reason) { if (active) setError(reason instanceof Error ? reason.message : String(reason)); }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 2_500);
    return () => { active = false; window.clearInterval(timer); };
  }, [selectedAgentId, selectedRunId, tab]);

  useEffect(() => {
    if (!selectedAgentId || !simulationResource.trim()) { setSimulation(null); return; }
    const timer = window.setTimeout(() => {
      const input = simulationKind === "file" ? { kind: "file" as const, resource: simulationResource } : { kind: "http" as const, resource: simulationResource, method: simulationMethod };
      void api.simulatePolicy(selectedAgentId, input, policyDraft ?? undefined).then(({ result }) => setSimulation(result)).catch(() => setSimulation(null));
    }, 220);
    return () => window.clearTimeout(timer);
  }, [policyDraft, selectedAgentId, simulationKind, simulationMethod, simulationResource]);

  const agentById = useMemo(() => new Map(agents.map((agent) => [agent.id, agent])), [agents]);
  const selectedAgent = selectedAgentId ? agentById.get(selectedAgentId) ?? null : null;
  const selectedRun = selectedAgentId && selectedRunId ? (runsByAgent[selectedAgentId] ?? []).find((run) => run.id === selectedRunId) ?? null : null;
  const selectedEvent = selectedEventId ? events.find((event) => event.sequence === selectedEventId) ?? null : null;
  const selectedModule = modules.find((module) => module.id === selectedModuleId) ?? null;
  const pendingApprovals = approvals.filter((approval) => approval.status === "pending");
  const sessions = useMemo(() => {
    if (!selectedAgent) return [];
    const groups = new Map<string, AgentRun[]>();
    for (const run of runsByAgent[selectedAgent.id] ?? []) {
      const id = run.pendingThreadId ?? selectedAgent.codexThreadId ?? "unassigned";
      groups.set(id, [...(groups.get(id) ?? []), run]);
    }
    return [...groups.entries()].map(([id, runs]) => ({ id, runs }));
  }, [runsByAgent, selectedAgent]);
  const stageCounts = useMemo(() => new Map(checkpoints.map((lane) => [lane.id, events.filter((event) => event.stage && lane.stages.includes(event.stage)).length])), [events]);
  const visibleEvents = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const lane = checkpoints.find((item) => item.id === stageFilter);
    return [...events].sort((a, b) => a.sequence - b.sequence).filter((event) => {
      if (lane && !(event.stage && lane.stages.includes(event.stage))) return false;
      if (decisionFilter === "allow" && !["allow", "approved", "issued"].includes(event.decision ?? "")) return false;
      if (decisionFilter === "review" && event.decision !== "require_approval") return false;
      if (decisionFilter === "deny" && !["deny", "denied"].includes(event.decision ?? "")) return false;
      if (!needle) return true;
      return [titleFor(event), event.reason, event.ruleId, event.moduleId, eventResource(event)].some((value) => value?.toLowerCase().includes(needle));
    });
  }, [decisionFilter, events, search, stageFilter]);

  const openApproval = async (id: string) => {
    try { setApprovalDetail(await api.approval(id)); } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
  };
  const decideApproval = async (id: string, decision: "approve" | "deny") => {
    setBusy(true);
    try { await (decision === "approve" ? api.approve(id) : api.deny(id)); setApprovalDetail(null); await refreshStructure(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };
  const verifyLedger = async () => {
    setLedgerStatus("Verifying");
    try { const result = await api.verifyLedger(); setLedgerStatus(result.valid ? `Verified ${result.events} events` : `Broken at ${result.brokenAt ?? "unknown"}`); window.setTimeout(() => setLedgerStatus(null), 4_000); }
    catch (reason) { setLedgerStatus(reason instanceof Error ? reason.message : String(reason)); }
  };
  const savePolicy = async () => {
    if (!selectedAgentId || !policyDraft) return;
    setBusy(true);
    try {
      const result = await api.updatePolicy(selectedAgentId, policyDraft);
      const bundle = await api.policy(selectedAgentId);
      setPolicyBundle(bundle); setPolicyDraft(structuredClone(bundle.profile)); setPolicyConfirm(false);
      setNotice(`Policy v${result.profile.version} saved. ${result.invalidatedApprovals} approval(s) invalidated.`);
      await refreshStructure();
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };
  const applyTemplate = async (template: Exclude<PolicyTemplate, "custom">) => {
    if (!selectedAgentId) return;
    setBusy(true);
    try {
      const result = await api.applyPolicyTemplate(selectedAgentId, template);
      const bundle = await api.policy(selectedAgentId);
      setPolicyBundle(bundle); setPolicyDraft(structuredClone(bundle.profile)); setNotice(`${template} template applied as v${result.profile.version}.`);
      await refreshStructure();
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };
  const configureModule = async (body: { enabled?: boolean; config?: Record<string, unknown> }) => {
    if (!selectedModule) return;
    setBusy(true);
    try {
      const result = await api.configureSecurityModule(selectedModule.id, body);
      setNotice(`${result.module.name} revision ${result.module.revision} is active. ${result.invalidatedApprovals} approval(s) invalidated.`);
      await refreshStructure();
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };

  if (!overview) return <section className="secx secx-loading" aria-live="polite"><div className="secx-skeleton secx-skeleton-title" /><div className="secx-skeleton secx-skeleton-nav" /><div className="secx-skeleton secx-skeleton-body" /></section>;

  const tabs: Array<{ id: Tab; label: string; icon: typeof PulseIcon; count?: number }> = [
    { id: "overview", label: "Overview", icon: ShieldCheckIcon },
    { id: "activity", label: "Activity", icon: PulseIcon },
    { id: "approvals", label: "Approvals", icon: PersonIcon, count: pendingApprovals.length },
    { id: "policies", label: "Policies", icon: SlidersIcon },
    { id: "modules", label: "Modules", icon: GitBranchIcon, count: modules.length },
    { id: "architecture", label: "Architecture", icon: GraphIcon },
  ];

  return <section className="secx">
    <header className="secx-header"><div className="secx-title"><span className="secx-product-mark"><ShieldCheckIcon size={21} /></span><div><h1>Security Center</h1><p>Policy, runtime decisions and evidence for every Agent.</p></div></div><div className="secx-header-actions"><span className={"secx-posture secx-tone-" + (overview.posture === "protected" ? "success" : "danger")}>{overview.posture === "protected" ? <CheckCircleFillIcon size={14} /> : <AlertIcon size={14} />}{overview.posture === "protected" ? "Protected" : "Degraded"}</span><button className="secx-ledger" onClick={() => void verifyLedger()}><LockIcon size={14} />{ledgerStatus ?? `${overview.ledger.events} signed events`}</button></div></header>
    {error && <div className="secx-alert" role="alert"><AlertIcon size={16} /><span>{error}</span><button onClick={() => setError(null)}>Dismiss</button></div>}
    {notice && <div className="secx-notice" role="status"><CheckCircleFillIcon size={15} /><span>{notice}</span><button onClick={() => setNotice(null)}>Dismiss</button></div>}
    <nav className="secx-tabs" aria-label="Security Center sections">{tabs.map((item) => { const Icon = item.icon; return <button key={item.id} className={tab === item.id ? "active" : ""} onClick={() => setTab(item.id)}><Icon size={15} />{item.label}{Boolean(item.count) && <span>{item.count}</span>}</button>; })}</nav>
    {tab === "overview" && <OverviewPage overview={overview} modules={modules} events={events} setTab={setTab} setSelectedModuleId={setSelectedModuleId} setSelectedAgentId={setSelectedAgentId} setSelectedRunId={setSelectedRunId} setSelectedEventId={setSelectedEventId} />}
    {tab === "activity" && <ActivityPage agents={agents} runsByAgent={runsByAgent} selectedAgent={selectedAgent} selectedAgentId={selectedAgentId} setSelectedAgentId={setSelectedAgentId} selectedRun={selectedRun} selectedRunId={selectedRunId} setSelectedRunId={setSelectedRunId} sessions={sessions} events={events} visibleEvents={visibleEvents} selectedEvent={selectedEvent} selectedEventId={selectedEventId} setSelectedEventId={setSelectedEventId} stageCounts={stageCounts} stageFilter={stageFilter} setStageFilter={setStageFilter} search={search} setSearch={setSearch} decisionFilter={decisionFilter} setDecisionFilter={setDecisionFilter} onOpenRun={onOpenRun} />}
    {tab === "approvals" && <ApprovalsPage approvals={approvals} pending={pendingApprovals.length} runsByAgent={runsByAgent} agentById={agentById} openApproval={openApproval} />}
    {tab === "policies" && <PoliciesPage agents={agents} selectedAgent={selectedAgent} selectedAgentId={selectedAgentId} setSelectedAgentId={setSelectedAgentId} bundle={policyBundle} draft={policyDraft} setDraft={setPolicyDraft} simulationKind={simulationKind} setSimulationKind={setSimulationKind} simulationResource={simulationResource} setSimulationResource={setSimulationResource} simulationMethod={simulationMethod} setSimulationMethod={setSimulationMethod} simulation={simulation} busy={busy} applyTemplate={applyTemplate} setPolicyConfirm={setPolicyConfirm} />}
    {tab === "modules" && <ModulesPage modules={modules} selectedModule={selectedModule} selectedModuleId={selectedModuleId} setSelectedModuleId={setSelectedModuleId} moduleConfig={moduleConfig} setModuleConfig={setModuleConfig} busy={busy} configureModule={configureModule} openEvent={(event) => { setSelectedAgentId(event.agentId ?? null); setSelectedRunId(event.runId ?? null); setSelectedEventId(event.sequence); setTab("activity"); }} />}
    {tab === "architecture" && <div className="secx-architecture"><header className="secx-page-header"><div><h2>Agent security middleware architecture</h2><p>Explore checkpoints, trust boundaries, plug-in hooks and the controlled effect boundary.</p></div><button onClick={() => window.open("/diagrams/aeg-architecture.html", "_blank", "noopener,noreferrer")}>Open full screen</button></header><iframe src="/diagrams/aeg-architecture.html" title="Agent security middleware architecture" /></div>}
    {approvalDetail && <ApprovalModal detail={approvalDetail} busy={busy} close={() => setApprovalDetail(null)} decide={decideApproval} />}
    {policyConfirm && policyDraft && policyBundle && <PolicyModal draft={policyDraft} bundle={policyBundle} busy={busy} close={() => setPolicyConfirm(false)} save={savePolicy} />}
  </section>;
}

function OverviewPage({ overview, modules, events, setTab, setSelectedModuleId, setSelectedAgentId, setSelectedRunId, setSelectedEventId }: {
  overview: SecurityOverview;
  modules: SecurityModule[];
  events: SecurityEvent[];
  setTab: (tab: Tab) => void;
  setSelectedModuleId: (id: string) => void;
  setSelectedAgentId: (id: string | null) => void;
  setSelectedRunId: (id: string | null) => void;
  setSelectedEventId: (id: number) => void;
}) {
  return <div className="secx-overview-page">
    <section className="secx-overview-hero"><div><span className="eyebrow">AEG runtime posture</span><h2>Every persistent effect passes five governed checkpoints.</h2><p>The Runtime receives a disposable copy. The kernel alone commits approved effects to protected state.</p></div><div className="secx-hero-proof"><ShieldCheckIcon size={28} /><strong>{overview.ledger.valid ? "Evidence verified" : "Evidence degraded"}</strong><span>{overview.ledger.events} HMAC-chained events</span></div></section>
    <div className="secx-metrics"><div><span>Runs monitored</span><strong>{overview.totals.runs}</strong><small>{overview.totals.agents} Agents</small></div><div><span>Effects mediated</span><strong>{overview.totals.effects}</strong><small>Files and HTTP</small></div><div><span>Policy blocks</span><strong className={overview.totals.blocked ? "secx-danger-text" : ""}>{overview.totals.blocked}</strong><small>{overview.totals.rolledBack} restored</small></div><div><span>Pending approvals</span><strong>{overview.totals.awaitingApproval}</strong><small>Digest-bound</small></div></div>
    <section className="secx-overview-grid">
      <article className="secx-overview-card secx-checkpoint-card"><header><div><span>Runtime path</span><h3>Five enforced checkpoints</h3></div><button onClick={() => setTab("activity")}>Inspect activity <ChevronRightIcon size={13} /></button></header><div className="secx-checkpoint-row">{checkpoints.map((checkpoint, index) => { const Icon = checkpoint.icon; return <div key={checkpoint.id} className="secx-checkpoint"><span><Icon size={16} /></span><strong>{index + 1}. {checkpoint.label}</strong><small>{checkpoint.detail}</small></div>; })}</div></article>
      <article className="secx-overview-card"><header><div><span>Identity and delegation</span><h3>Human to Agent to Run</h3></div><KeyIcon size={17} /></header><div className="secx-identity-chain"><div><PersonIcon size={15} /><span><small>Human</small><strong>{overview.identity.humans} operator</strong></span></div><ChevronRightIcon size={14} /><div><ServerIcon size={15} /><span><small>Agent principals</small><strong>{overview.identity.activeAgentPrincipals} active</strong></span></div><ChevronRightIcon size={14} /><div><KeyIcon size={15} /><span><small>Run capabilities</small><strong>{overview.identity.issuedCapabilities} issued</strong></span></div></div></article>
      <article className="secx-overview-card"><header><div><span>Module health</span><h3>{modules.filter((module) => module.status === "active").length} active of {modules.length}</h3></div><button onClick={() => setTab("modules")}>Configure <ChevronRightIcon size={13} /></button></header><div className="secx-health-list">{modules.slice(0, 6).map((module) => <button key={module.id} onClick={() => { setSelectedModuleId(module.id); setTab("modules"); }}><span className="secx-module-icon">{moduleIcon(module)}</span><span><strong>{module.name}</strong><small>{module.statusReason}</small></span><i className={"secx-health-dot " + module.status} /></button>)}</div></article>
      <article className="secx-overview-card"><header><div><span>Recent decisions</span><h3>Live security activity</h3></div><PulseIcon size={17} /></header><div className="secx-overview-events">{events.slice(-6).reverse().map((event) => <button key={event.sequence} onClick={() => { setSelectedAgentId(event.agentId ?? null); setSelectedRunId(event.runId ?? null); setSelectedEventId(event.sequence); setTab("activity"); }}><span className={"secx-tone-" + toneFor(event)}><PulseIcon size={13} /></span><span><strong>{titleFor(event)}</strong><small>{event.moduleId ?? "audit-ledger"} · {fullTime(event.createdAt)}</small></span><ChevronRightIcon size={13} /></button>)}</div></article>
    </section>
  </div>;
}

function ActivityPage(props: {
  agents: Agent[];
  runsByAgent: Record<string, AgentRun[]>;
  selectedAgent: Agent | null;
  selectedAgentId: string | null;
  setSelectedAgentId: (id: string | null) => void;
  selectedRun: AgentRun | null;
  selectedRunId: string | null;
  setSelectedRunId: (id: string | null) => void;
  sessions: Array<{ id: string; runs: AgentRun[] }>;
  events: SecurityEvent[];
  visibleEvents: SecurityEvent[];
  selectedEvent: SecurityEvent | null;
  selectedEventId: number | null;
  setSelectedEventId: (id: number) => void;
  stageCounts: Map<string, number>;
  stageFilter: string | null;
  setStageFilter: (id: string | null) => void;
  search: string;
  setSearch: (value: string) => void;
  decisionFilter: string;
  setDecisionFilter: (value: string) => void;
  onOpenRun: (agentId: string, run: AgentRun) => void;
}) {
  const { agents, runsByAgent, selectedAgent, selectedAgentId, setSelectedAgentId, selectedRun, selectedRunId, setSelectedRunId, sessions, events, visibleEvents, selectedEvent, selectedEventId, setSelectedEventId, stageCounts, stageFilter, setStageFilter, search, setSearch, decisionFilter, setDecisionFilter, onOpenRun } = props;
  return <div className="secx-workbench">
    <aside className="secx-run-index"><div className="secx-panel-title"><div><h2>Execution context</h2><p>Agent / Session / Run</p></div></div><div className="secx-agent-switcher"><label htmlFor="secx-agent-select">Agent</label><div><ServerIcon size={15} /><select id="secx-agent-select" value={selectedAgentId ?? ""} onChange={(event) => { const id = event.target.value || null; setSelectedAgentId(id); setSelectedRunId(id ? runsByAgent[id]?.[0]?.id ?? null : null); setStageFilter(null); }}><option value="">Select Agent</option>{agents.map((agent) => <option value={agent.id} key={agent.id}>{agent.name}</option>)}</select><ChevronDownIcon size={14} /></div></div><div className="secx-session-list">{sessions.length === 0 ? <div className="secx-compact-empty"><WorkflowIcon size={20} /><p>No Runs for this Agent.</p></div> : sessions.map((session) => <section className="secx-session" key={session.id}><header><GitBranchIcon size={13} /><span>Session</span><code>{short(session.id, 8)}</code></header>{session.runs.map((run) => <button className={"secx-run-item" + (run.id === selectedRunId ? " active" : "")} key={run.id} onClick={() => { setSelectedRunId(run.id); setStageFilter(null); }}><span className={"secx-run-icon secx-tone-" + runTone(run.status)}>{run.status === "completed" ? <CheckCircleFillIcon size={13} /> : run.status === "rolled_back" ? <XCircleFillIcon size={13} /> : <ClockIcon size={13} />}</span><span><strong>{run.prompt}</strong><small>{fullTime(run.createdAt)} · {run.status.replaceAll("_", " ")}</small></span><ChevronRightIcon size={14} /></button>)}</section>)}</div></aside>
    <main className="secx-trace-panel">{selectedRun ? <><header className="secx-run-header"><div><div className="secx-breadcrumb"><span>{selectedAgent?.name}</span><ChevronRightIcon size={12} /><code>{short(selectedRun.pendingThreadId ?? "session", 10)}</code><ChevronRightIcon size={12} /><code>{short(selectedRun.id, 10)}</code></div><h2>{selectedRun.prompt}</h2><p>{fullTime(selectedRun.startedAt ?? selectedRun.createdAt)} · {elapsed(selectedRun.startedAt, selectedRun.completedAt)}</p></div><div className="secx-run-actions"><span className={"secx-status secx-tone-" + runTone(selectedRun.status)}>{selectedRun.status.replaceAll("_", " ")}</span>{selectedAgent && <button onClick={() => onOpenRun(selectedAgent.id, selectedRun)}>Open Playground</button>}</div></header><div className="secx-run-proof"><div><FileDiffIcon size={15} /><span>Effects</span><strong>{selectedRun.effects.length + selectedRun.externalEffects.length}</strong></div><div><ShieldLockIcon size={15} /><span>Policy</span><strong>{short(selectedRun.policyVersion, 16)}</strong></div><div><KeyIcon size={15} /><span>Capability</span><strong>{short(selectedRun.securityContextId, 12)}</strong></div><div><LockIcon size={15} /><span>Manifest</span><strong>{short(selectedRun.manifestDigest, 12)}</strong>{selectedRun.manifestDigest && <CopyControl value={selectedRun.manifestDigest} label="manifest digest" />}</div></div><section className="secx-lifecycle"><header><h3>Agent path</h3><p>Select a checkpoint to isolate its evidence.</p></header><div className="secx-lifecycle-track secx-five-stage">{checkpoints.map((lane, index) => { const Icon = lane.icon; const count = stageCounts.get(lane.id) ?? 0; const laneEvents = events.filter((event) => event.stage && lane.stages.includes(event.stage)); const tone = laneEvents.some((event) => toneFor(event) === "danger") ? "danger" : laneEvents.some((event) => toneFor(event) === "attention") ? "attention" : count ? "success" : "neutral"; return <button key={lane.id} className={"secx-stage secx-tone-" + tone + (stageFilter === lane.id ? " active" : "")} onClick={() => setStageFilter(stageFilter === lane.id ? null : lane.id)}>{index < checkpoints.length - 1 && <i className="secx-stage-connector" />}<span className="secx-stage-icon"><Icon size={16} /></span><strong>{lane.label}</strong><small>{count ? `${count} events` : "Not reached"}</small></button>; })}</div></section><EventStream events={visibleEvents} selectedEventId={selectedEventId} setSelectedEventId={setSelectedEventId} search={search} setSearch={setSearch} decisionFilter={decisionFilter} setDecisionFilter={setDecisionFilter} /></> : <div className="secx-empty secx-empty-large"><PulseIcon size={34} /><h2>Select a Run to investigate</h2><p>Each Run keeps its own identity, session, policy, effects and evidence.</p></div>}</main>
    <aside className="secx-inspector"><div className="secx-panel-title"><div><h2>Evidence</h2><p>Selected trace event</p></div>{selectedEvent && <span>#{selectedEvent.sequence}</span>}</div>{selectedEvent ? <div className="secx-inspector-content"><header><span className={"secx-evidence-icon secx-tone-" + toneFor(selectedEvent)}><ShieldCheckIcon size={17} /></span><div><h3>{titleFor(selectedEvent)}</h3><p>{fullTime(selectedEvent.createdAt)}</p></div></header><p className="secx-reason">{selectedEvent.reason ?? "This event was recorded by the security evidence ledger."}</p><dl><div><dt>Decision</dt><dd><span className={"secx-decision secx-tone-" + toneFor(selectedEvent)}>{decisionText(selectedEvent.decision)}</span></dd></div><div><dt>Module</dt><dd><span className="secx-module-badge">{selectedEvent.moduleId ?? "audit-ledger"}</span></dd></div><div><dt>Rule</dt><dd>{selectedEvent.ruleId ?? "No rule"}</dd></div><div><dt>Human</dt><dd><code>{short(selectedEvent.humanId, 20)}</code></dd></div><div><dt>Agent principal</dt><dd><code>{short(selectedEvent.agentPrincipalId, 20)}</code></dd></div><div><dt>Run</dt><dd><code>{short(selectedEvent.runId, 20)}</code></dd></div></dl>{selectedEvent.payload && Object.keys(selectedEvent.payload).length > 0 && <section className="secx-payload"><h4>Redacted payload</h4><pre>{JSON.stringify(selectedEvent.payload, null, 2)}</pre></section>}<footer><div><LockIcon size={13} /><span>Ledger MAC</span></div><code>{short(selectedEvent.eventMac, 25)}</code><CopyControl value={selectedEvent.eventMac} label="event MAC" /></footer></div> : <div className="secx-compact-empty"><EyeIcon size={24} /><p>Select an event to inspect its module, rule, identity and ledger proof.</p></div>}</aside>
  </div>;
}

function EventStream({ events, selectedEventId, setSelectedEventId, search, setSearch, decisionFilter, setDecisionFilter }: { events: SecurityEvent[]; selectedEventId: number | null; setSelectedEventId: (id: number) => void; search: string; setSearch: (value: string) => void; decisionFilter: string; setDecisionFilter: (value: string) => void }) {
  return <section className="secx-event-stream"><div className="secx-event-toolbar"><div><h3>Trace events</h3><span>{events.length} shown</span></div><div className="secx-event-filters"><div className="secx-search"><SearchIcon size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search trace" /></div><select value={decisionFilter} onChange={(event) => setDecisionFilter(event.target.value)}><option value="all">All decisions</option><option value="allow">Allowed</option><option value="review">Review</option><option value="deny">Denied</option></select></div></div><div className="secx-event-columns"><span>Time</span><span>Stage</span><span>Event and module</span><span>Decision</span></div><div className="secx-event-list">{events.length === 0 ? <div className="secx-empty"><EyeIcon size={28} /><h3>No trace events</h3><p>Run the Agent once to populate this execution path.</p></div> : events.map((event) => { const lane = checkpoints.find((item) => event.stage && item.stages.includes(event.stage)); return <button key={event.sequence} className={"secx-event-row" + (selectedEventId === event.sequence ? " active" : "")} onClick={() => setSelectedEventId(event.sequence)}><time>{new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(event.createdAt))}</time><span className="secx-event-stage">{lane?.label ?? event.stage ?? "System"}</span><span className="secx-event-summary"><strong>{titleFor(event)}</strong><small><span className="secx-module-badge">{event.moduleId ?? "audit-ledger"}</span>{eventResource(event) ?? event.reason ?? "Evidence recorded"}</small></span><span className={"secx-decision secx-tone-" + toneFor(event)}>{decisionText(event.decision)}</span></button>; })}</div></section>;
}

function ApprovalsPage({ approvals, pending, runsByAgent, agentById, openApproval }: {
  approvals: Approval[];
  pending: number;
  runsByAgent: Record<string, AgentRun[]>;
  agentById: Map<string, Agent>;
  openApproval: (id: string) => Promise<void>;
}) {
  return <div className="secx-page"><header className="secx-page-header"><div><h2>Human approvals</h2><p>Inspect Intake risk or the exact measured manifest before execution continues.</p></div><span>{pending} pending</span></header><div className="secx-approval-list">{approvals.length === 0 ? <div className="secx-empty secx-empty-large"><PersonIcon size={34} /><h2>No approval requests</h2><p>High-risk Intake and effects will pause here with digest binding.</p></div> : approvals.map((approval) => { const run = (runsByAgent[approval.agentId] ?? []).find((item) => item.id === approval.runId); return <button className="secx-approval-row" key={approval.id} onClick={() => void openApproval(approval.id)}><span className={"secx-approval-icon secx-tone-" + (approval.status === "pending" ? "attention" : approval.status === "approved" ? "success" : "danger")}><PersonIcon size={16} /></span><span><strong>{run?.prompt ?? "Secured Run"}</strong><small>{agentById.get(approval.agentId)?.name ?? "Agent"} · {approval.scope} · digest {short(approval.manifestDigest, 16)}</small></span><span className="secx-status">{approval.status}</span><time>{fullTime(approval.createdAt)}</time><ChevronRightIcon size={15} /></button>; })}</div></div>;
}

function PoliciesPage(props: {
  agents: Agent[];
  selectedAgent: Agent | null;
  selectedAgentId: string | null;
  setSelectedAgentId: (id: string) => void;
  bundle: PolicyBundle | null;
  draft: PolicyProfile | null;
  setDraft: (profile: PolicyProfile) => void;
  simulationKind: "file" | "http";
  setSimulationKind: (kind: "file" | "http") => void;
  simulationResource: string;
  setSimulationResource: (value: string) => void;
  simulationMethod: string;
  setSimulationMethod: (value: string) => void;
  simulation: PolicySimulation | null;
  busy: boolean;
  applyTemplate: (template: Exclude<PolicyTemplate, "custom">) => Promise<void>;
  setPolicyConfirm: (value: boolean) => void;
}) {
  const { agents, selectedAgent, selectedAgentId, setSelectedAgentId, bundle, draft, setDraft, simulationKind, setSimulationKind, simulationResource, setSimulationResource, simulationMethod, setSimulationMethod, simulation, busy, applyTemplate, setPolicyConfirm } = props;
  const setGuardrail = (patch: Partial<PolicyProfile["analyzers"]["guardrail-model"]>) => {
    if (!draft) return;
    setDraft({
      ...draft,
      analyzers: {
        ...draft.analyzers,
        "guardrail-model": { ...draft.analyzers["guardrail-model"], ...patch },
      },
    });
  };
  const setSecretScanner = (patch: Partial<PolicyProfile["analyzers"]["secret-scanner"]>) => {
    if (!draft) return;
    setDraft({
      ...draft,
      analyzers: {
        ...draft.analyzers,
        "secret-scanner": { ...draft.analyzers["secret-scanner"], ...patch },
      },
    });
  };
  const toggleMethod = (method: "POST" | "PUT" | "PATCH") => {
    if (!draft) return;
    const current = draft.external.requireApprovalMethods;
    setDraft({
      ...draft,
      external: {
        ...draft.external,
        requireApprovalMethods: current.includes(method)
          ? current.filter((item) => item !== method)
          : [...current, method],
      },
    });
  };
  return <div className="secx-policy-workbench">
    <aside className="secx-policy-agents">
      <div className="secx-panel-title"><div><h2>Agent policies</h2><p>Independent versioned profiles</p></div></div>
      {agents.map((agent) => <button key={agent.id} className={selectedAgentId === agent.id ? "active" : ""} onClick={() => setSelectedAgentId(agent.id)}>
        <span className="agent-avatar">{agent.name.slice(0, 1).toUpperCase()}</span>
        <span><strong>{agent.name}</strong><small>{agent.policyProfile.template} · v{agent.policyProfile.version}</small></span>
        <ChevronRightIcon size={14} />
      </button>)}
    </aside>
    <main className="secx-policy-editor">{draft && bundle && selectedAgent ? <>
      <header className="secx-policy-header">
        <div><span>Policy profile</span><h2>{selectedAgent.name}</h2><p>Profile v{bundle.profile.version} · updated {fullTime(bundle.profile.updatedAt)}</p></div>
        <div className="secx-template-actions">{(["relaxed", "balanced", "strict"] as const).map((template) => <button type="button" key={template} disabled={busy} className={bundle.profile.template === template ? "active" : ""} onClick={() => void applyTemplate(template)}>{template}</button>)}</div>
      </header>
      <div className="secx-policy-sections">
        <ChipEditor label="Auto allow" tone="success" values={draft.fileRules.autoAllow} onChange={(autoAllow) => setDraft({ ...draft, fileRules: { ...draft.fileRules, autoAllow } })} />
        <ChipEditor label="Require approval" tone="attention" values={draft.fileRules.requireApproval} onChange={(requireApproval) => setDraft({ ...draft, fileRules: { ...draft.fileRules, requireApproval } })} />
        <ChipEditor label="Deny" tone="danger" values={draft.fileRules.deny} onChange={(deny) => setDraft({ ...draft, fileRules: { ...draft.fileRules, deny } })} />
        <section className="secx-locked-rules">
          <header><span><LockIcon size={13} /> Kernel hard-deny</span><small>Cannot be overridden</small></header>
          <div>{bundle.hardDenyRules.map((rule) => <span key={rule}><LockIcon size={11} /><code>{rule}</code></span>)}</div>
        </section>
        <section className="secx-policy-settings">
          <header><span>Approval and Intake analyzers</span><small>Per-Agent behavior</small></header>
          <div className="secx-policy-setting-grid">
            <label>Approval TTL<input type="number" min={1} max={60} value={draft.approval.ttlMinutes} onChange={(event) => setDraft({ ...draft, approval: { ttlMinutes: Number(event.target.value) } })} /><small>minutes</small></label>
            <label className="secx-check"><input type="checkbox" checked={draft.analyzers["secret-scanner"].enabled} onChange={(event) => setSecretScanner({ enabled: event.target.checked })} />Secret scanner</label>
            <label>Secret action<select value={draft.analyzers["secret-scanner"].action} onChange={(event) => setSecretScanner({ action: event.target.value as "deny" | "require_approval" })}><option value="deny">Deny</option><option value="require_approval">Require approval</option></select></label>
            <label className="secx-check"><input type="checkbox" checked={draft.analyzers["guardrail-model"].enabled} onChange={(event) => setGuardrail({ enabled: event.target.checked })} />Guardrail model</label>
            <label>Review ≥<input type="number" min={0} max={1} step={0.01} value={draft.analyzers["guardrail-model"].reviewThreshold} onChange={(event) => setGuardrail({ reviewThreshold: Number(event.target.value) })} /></label>
            <label>Deny ≥<input type="number" min={0} max={1} step={0.01} value={draft.analyzers["guardrail-model"].denyThreshold} onChange={(event) => setGuardrail({ denyThreshold: Number(event.target.value) })} /></label>
          </div>
        </section>
        <section className="secx-policy-network">
          <header><span>External effects and Runtime egress</span><small>Policy profile rules</small></header>
          <div className="secx-policy-network-grid">
            <ChipEditor label="Agent HTTP hosts · platform subset" tone="success" values={draft.external.allowHosts} placeholder="Add platform-approved hostname" onChange={(allowHosts) => setDraft({ ...draft, external: { ...draft.external, allowHosts } })} />
            <ChipEditor label="Egress allow rules" tone="attention" values={draft.egress.allow} placeholder="Add domain=/method=/path= rule" onChange={(allow) => setDraft({ ...draft, egress: { allow } })} />
          </div>
          <div className="secx-method-rules"><span>Require approval for declared HTTP</span>{(["POST", "PUT", "PATCH"] as const).map((method) => <label key={method}><input type="checkbox" checked={draft.external.requireApprovalMethods.includes(method)} onChange={() => toggleMethod(method)} />{method}</label>)}</div>
        </section>
      </div>
      <footer className="secx-policy-save"><span>{bundle.pendingApprovals ? `${bundle.pendingApprovals} pending approval(s) will expire on save.` : "Configuration changes are signed ledger events."}</span><button className="secx-primary-button" disabled={busy} onClick={() => setPolicyConfirm(true)}>Review and save</button></footer>
    </> : <div className="secx-empty"><SlidersIcon size={28} /><h3>Select an Agent policy</h3></div>}</main>
    <aside className="secx-simulator"><div className="secx-panel-title"><div><h2>Policy simulator</h2><p>Evaluate the current draft</p></div><BeakerIcon size={16} /></div><div className="secx-simulator-form"><div className="secx-segment"><button className={simulationKind === "file" ? "active" : ""} onClick={() => { setSimulationKind("file"); setSimulationResource("src/index.ts"); }}>File</button><button className={simulationKind === "http" ? "active" : ""} onClick={() => { setSimulationKind("http"); setSimulationResource("https://api.github.com/repos"); }}>HTTP</button></div><label>{simulationKind === "file" ? "Workspace path" : "Request URL"}<input value={simulationResource} onChange={(event) => setSimulationResource(event.target.value)} /></label>{simulationKind === "http" && <label>Method<select value={simulationMethod} onChange={(event) => setSimulationMethod(event.target.value)}>{["GET", "POST", "PUT", "PATCH", "DELETE"].map((method) => <option key={method}>{method}</option>)}</select></label>}</div>{simulation ? <div className={"secx-simulation-result secx-tone-" + (simulation.decision === "allow" ? "success" : simulation.decision === "deny" ? "danger" : "attention")}><span>{simulation.locked ? <LockIcon size={18} /> : <WorkflowIcon size={18} />}</span><small>Final decision</small><strong>{decisionText(simulation.decision)}</strong><p>{simulation.reason}</p><dl><div><dt>Module</dt><dd>{simulation.moduleId}</dd></div><div><dt>Rule</dt><dd>{simulation.ruleId}</dd></div><div><dt>Matched</dt><dd>{simulation.matchedRule ?? "Fallback"}</dd></div></dl></div> : <div className="secx-compact-empty"><BeakerIcon size={24} /><p>Enter a path or URL to evaluate policy.</p></div>}</aside>
  </div>;
}

function ModulesPage(props: {
  modules: SecurityModule[];
  selectedModule: SecurityModule | null;
  selectedModuleId: string | null;
  setSelectedModuleId: (id: string) => void;
  moduleConfig: Record<string, unknown>;
  setModuleConfig: (value: Record<string, unknown>) => void;
  busy: boolean;
  configureModule: (body: { enabled?: boolean; config?: Record<string, unknown> }) => Promise<void>;
  openEvent: (event: SecurityEvent) => void;
}) {
  const { modules, selectedModule, selectedModuleId, setSelectedModuleId, moduleConfig, setModuleConfig, busy, configureModule, openEvent } = props;
  return <div className="secx-module-workbench"><aside className="secx-module-index"><div className="secx-panel-title"><div><h2>Security modules</h2><p>Composable enforcement chain</p></div></div>{modules.map((module) => <button className={selectedModuleId === module.id ? "active" : ""} key={module.id} onClick={() => setSelectedModuleId(module.id)}><span className="secx-module-icon">{moduleIcon(module)}</span><span><strong>{module.name}</strong><small>{module.kind} · r{module.revision}</small></span><i className={"secx-health-dot " + module.status} /></button>)}</aside><main className="secx-module-detail">{selectedModule ? <><header><span className="secx-module-hero-icon">{moduleIcon(selectedModule, 24)}</span><div><span>{selectedModule.kind} module</span><h2>{selectedModule.name}</h2><p>{selectedModule.description}</p></div><div className="secx-module-toggle">{selectedModule.locked ? <span title="Kernel-bound module"><LockIcon size={14} /> Locked</span> : <label><input type="checkbox" checked={selectedModule.enabled} disabled={busy} onChange={(event) => void configureModule({ enabled: event.target.checked })} /><i /><span>{selectedModule.enabled ? "Enabled" : "Disabled"}</span></label>}</div></header><div className="secx-module-meta"><div><span>Plugin ID</span><code>{selectedModule.id}</code></div><div><span>Version</span><code>{selectedModule.version}</code></div><div><span>Health</span><strong className={"secx-tone-" + (selectedModule.status === "active" ? "success" : selectedModule.status === "degraded" ? "attention" : "neutral")}>{selectedModule.status}</strong></div><div><span>Observed events</span><strong>{selectedModule.events}</strong></div></div><p className="secx-module-health"><PulseIcon size={14} />{selectedModule.statusReason}</p><section><h3>Capabilities</h3><div className="secx-capabilities">{selectedModule.capabilities.map((capability) => <span key={capability}><CheckIcon size={13} />{capability}</span>)}</div></section>{selectedModule.configSchema && <section className="secx-config-form"><div className="secx-section-heading"><div><h3>Configuration</h3><p>Generated from this module's schema.</p></div><GearIcon size={16} /></div><div>{Object.entries(selectedModule.configSchema.properties).map(([key, schema]) => <label key={key}><span>{schema.title}<small>{schema.description}</small></span>{schema.type === "array" ? <textarea rows={3} value={Array.isArray(moduleConfig[key]) ? (moduleConfig[key] as string[]).join("\n") : ""} onChange={(event) => setModuleConfig({ ...moduleConfig, [key]: event.target.value.split("\n").map((item) => item.trim()).filter(Boolean) })} /> : schema.type === "boolean" ? <input type="checkbox" checked={Boolean(moduleConfig[key])} onChange={(event) => setModuleConfig({ ...moduleConfig, [key]: event.target.checked })} /> : schema.enum ? <select value={String(moduleConfig[key] ?? "")} onChange={(event) => setModuleConfig({ ...moduleConfig, [key]: event.target.value })}>{schema.enum.map((option) => <option key={option}>{option}</option>)}</select> : <input type={schema.type === "number" ? "number" : "text"} min={schema.minimum} max={schema.maximum} value={String(moduleConfig[key] ?? "")} onChange={(event) => setModuleConfig({ ...moduleConfig, [key]: schema.type === "number" ? Number(event.target.value) : event.target.value })} />}</label>)}</div><button className="secx-primary-button" disabled={busy} onClick={() => void configureModule({ config: moduleConfig })}>Save module configuration</button></section>}<section><h3>Recent activity</h3>{selectedModule.recentEvents?.length ? <div className="secx-module-events">{selectedModule.recentEvents.map((event) => <button key={event.sequence} onClick={() => openEvent(event)}><span className={"secx-tone-" + toneFor(event)}><PulseIcon size={13} /></span><span><strong>{titleFor(event)}</strong><small>{event.reason ?? fullTime(event.createdAt)}</small></span><ChevronRightIcon size={14} /></button>)}</div> : <p className="secx-muted">No recent activity for this module.</p>}</section></> : <div className="secx-empty"><GitBranchIcon size={28} /><h3>Select a module</h3></div>}</main></div>;
}

function ApprovalModal({ detail, busy, close, decide }: { detail: ApprovalDetail; busy: boolean; close: () => void; decide: (id: string, decision: "approve" | "deny") => Promise<void> }) {
  return <div className="secx-modal-backdrop" onMouseDown={close}><article className="secx-modal" onMouseDown={(event) => event.stopPropagation()}><header><div><span>{detail.approval.scope === "intake" ? "Intake inspection" : "Digest-bound manifest approval"}</span><h2>{detail.run.prompt}</h2></div><button aria-label="Close" onClick={close}>×</button></header><div className="secx-modal-digest"><LockIcon size={15} /><code>{detail.approval.manifestDigest}</code><CopyControl value={detail.approval.manifestDigest} label="approval digest" /></div><section className="secx-effect-review">{detail.approval.scope === "intake" && <div className="secx-intake-review"><AlertIcon size={18} /><div><strong>Execution has not started.</strong><p>An Intake analyzer requested human inspection before Runtime access.</p></div></div>}{detail.run.effects.map((effect) => { const preview = detail.previews.find((item) => item.effectId === effect.id); return <article key={effect.id}><header><FileDiffIcon size={15} /><strong>{effect.resource}</strong><span>{effect.type}</span></header>{preview && !preview.binary && <div className="secx-diff"><div><span>Before</span><pre>{preview.before || "(empty)"}</pre></div><div><span>After</span><pre>{preview.after || "(empty)"}</pre></div></div>}</article>; })}{detail.run.externalEffects.map((effect) => <article key={effect.id}><header><GlobeIcon size={15} /><strong>{effect.method} {effect.url}</strong><span>HTTP</span></header>{effect.bodyPreview && <pre className="secx-http-body">{effect.bodyPreview}</pre>}</article>)}</section><footer><button className="secx-danger-button" disabled={busy} onClick={() => void decide(detail.approval.id, "deny")}>Deny and restore</button><button className="secx-primary-button" disabled={busy} onClick={() => void decide(detail.approval.id, "approve")}>{detail.approval.scope === "intake" ? "Approve execution" : "Approve manifest"}</button></footer></article></div>;
}

function PolicyModal({ draft, bundle, busy, close, save }: { draft: PolicyProfile; bundle: PolicyBundle; busy: boolean; close: () => void; save: () => Promise<void> }) {
  return <div className="secx-modal-backdrop" onMouseDown={close}><article className="secx-modal secx-policy-modal" onMouseDown={(event) => event.stopPropagation()}><header><div><span>Policy change review</span><h2>Publish profile v{bundle.profile.version + 1}</h2></div><button aria-label="Close" onClick={close}>×</button></header><section className="secx-policy-diff"><div><strong>File rules</strong><span>{draft.fileRules.autoAllow.length} allow</span><span>{draft.fileRules.requireApproval.length} review</span><span>{draft.fileRules.deny.length} deny</span></div><div><strong>Analyzers</strong><span>Secret scanner {draft.analyzers["secret-scanner"].enabled ? draft.analyzers["secret-scanner"].action.replaceAll("_", " ") : "off"}</span><span>Guardrail model {draft.analyzers["guardrail-model"].enabled ? `review ${draft.analyzers["guardrail-model"].reviewThreshold} / deny ${draft.analyzers["guardrail-model"].denyThreshold}` : "off"}</span></div><div><strong>External policy</strong><span>{draft.external.allowHosts.length} allowlisted host(s)</span><span>{draft.external.requireApprovalMethods.join(", ") || "No methods require approval"}</span><span>{draft.egress.allow.length} egress rule(s)</span></div><div className={bundle.pendingApprovals ? "warning" : ""}><strong>Approval impact</strong><span>{bundle.pendingApprovals} pending approval(s) will expire</span><span>A signed policy.updated event will be recorded</span></div></section><footer><button disabled={busy} onClick={close}>Cancel</button><button className="secx-primary-button" disabled={busy} onClick={() => void save()}>Publish policy</button></footer></article></div>;
}
