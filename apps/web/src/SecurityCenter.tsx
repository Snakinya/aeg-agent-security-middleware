import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import type {
  Agent,
  AgentRun,
  SecurityEvent,
  SecurityModule,
  SecurityOverview,
  SecurityStage,
} from "./types";

const lanes: Array<{ id: string; label: string; stages: SecurityStage[] }> = [
  { id: "identity", label: "Identity", stages: ["identity"] },
  { id: "runtime", label: "Runtime", stages: ["runtime"] },
  { id: "policy", label: "Policy", stages: ["observe", "policy"] },
  { id: "approval", label: "Approval", stages: ["approval"] },
  { id: "effect", label: "Effect", stages: ["execute"] },
  { id: "evidence", label: "Evidence", stages: ["recover", "verify"] },
];

type SecurityView = "runs" | "modules";

interface SecurityCenterProps {
  initialAgentId: string | null;
  onOpenRun: (agentId: string, run: AgentRun) => void;
}

function short(value: string | null | undefined, length = 12): string {
  if (!value) return "None";
  return value.length > length ? value.slice(0, length) + "…" : value;
}

function eventLabel(event: SecurityEvent): string {
  return event.type.replaceAll("_", " ").replaceAll(".", " / ");
}

function eventTone(event: SecurityEvent): "critical" | "warning" | "success" | "neutral" {
  if (event.severity === "critical" || event.decision === "deny") return "critical";
  if (
    event.severity === "high" ||
    event.decision === "require_approval" ||
    event.decision === "uncertain"
  ) {
    return "warning";
  }
  if (
    event.decision === "allow" ||
    event.decision === "approved" ||
    event.decision === "issued"
  ) {
    return "success";
  }
  return "neutral";
}

function runTone(status: AgentRun["status"]): "critical" | "warning" | "success" | "neutral" {
  if (["failed", "cancelled", "rolled_back"].includes(status)) return "critical";
  if (["awaiting_approval", "reviewing_effects", "rolling_back"].includes(status)) {
    return "warning";
  }
  if (status === "completed") return "success";
  return "neutral";
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "Not recorded";
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
  return formatTimestamp(value);
}

function formatDuration(run: AgentRun): string {
  if (!run.startedAt) return "Not started";
  const end = run.completedAt ? Date.parse(run.completedAt) : Date.now();
  const seconds = Math.max(0, Math.round((end - Date.parse(run.startedAt)) / 1_000));
  if (seconds < 60) return seconds + "s";
  return Math.floor(seconds / 60) + "m " + (seconds % 60) + "s";
}

function sessionId(run: AgentRun, agent: Agent): string {
  return run.pendingThreadId ?? agent.codexThreadId ?? "pending-session";
}

function decisionLabel(value: string | null | undefined): string {
  if (!value) return "Observed";
  if (value === "require_approval") return "Review";
  return value.replaceAll("_", " ");
}

function moduleEventCount(module: SecurityModule): number {
  return module.events ?? 0;
}

export function SecurityCenter({ initialAgentId, onOpenRun }: SecurityCenterProps) {
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [runsByAgent, setRunsByAgent] = useState<Record<string, AgentRun[]>>({});
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(initialAgentId);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [selectedModuleId, setSelectedModuleId] = useState<string | null>(null);
  const [view, setView] = useState<SecurityView>("runs");
  const [platformSelected, setPlatformSelected] = useState(false);
  const [moduleFilter, setModuleFilter] = useState("all");
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const selectionRef = useRef({ selectedAgentId, platformSelected });
  selectionRef.current = { selectedAgentId, platformSelected };

  const refreshStructure = useCallback(async () => {
    setRefreshing(true);
    try {
      const [nextOverview, agentResponse] = await Promise.all([
        api.securityOverview(),
        api.listAgents(),
      ]);
      const runEntries = await Promise.all(
        agentResponse.agents.map(async (agent) => {
          const response = await api.runs(agent.id);
          return [agent.id, response.runs] as const;
        }),
      );
      const nextRuns = Object.fromEntries(runEntries);
      setOverview(nextOverview);
      setAgents(agentResponse.agents);
      setRunsByAgent(nextRuns);
      setSelectedAgentId((current) => {
        if (selectionRef.current.platformSelected) return current;
        if (current && agentResponse.agents.some((agent) => agent.id === current)) return current;
        if (initialAgentId && agentResponse.agents.some((agent) => agent.id === initialAgentId)) {
          return initialAgentId;
        }
        return agentResponse.agents[0]?.id ?? null;
      });
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setRefreshing(false);
    }
  }, [initialAgentId]);

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      if (active) await refreshStructure();
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [refreshStructure]);

  const selectedAgent = useMemo(
    () => agents.find((agent) => agent.id === selectedAgentId) ?? null,
    [agents, selectedAgentId],
  );
  const agentRuns = selectedAgentId ? runsByAgent[selectedAgentId] ?? [] : [];

  useEffect(() => {
    if (platformSelected || !selectedAgentId) {
      setSelectedRunId(null);
      return;
    }
    setSelectedRunId((current) =>
      current && agentRuns.some((run) => run.id === current)
        ? current
        : (agentRuns[0]?.id ?? null),
    );
  }, [agentRuns, platformSelected, selectedAgentId]);

  const selectedRun = useMemo(
    () => agentRuns.find((run) => run.id === selectedRunId) ?? null,
    [agentRuns, selectedRunId],
  );

  useEffect(() => {
    let active = true;
    const refreshEvents = async () => {
      try {
        const query = new URLSearchParams({ limit: "500" });
        if (!platformSelected && selectedAgentId) query.set("agentId", selectedAgentId);
        if (!platformSelected && selectedRunId) query.set("runId", selectedRunId);
        const response = await api.securityEvents(query.toString());
        if (!active) return;
        const nextEvents = platformSelected
          ? response.events.filter((event) => !event.agentId)
          : response.events;
        setEvents(nextEvents);
        setSelectedEvent((current) =>
          current
            ? nextEvents.find((event) => event.sequence === current.sequence) ?? nextEvents[0] ?? null
            : nextEvents[0] ?? null,
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
  }, [platformSelected, selectedAgentId, selectedRunId]);

  const sessions = useMemo(() => {
    if (!selectedAgent) return [];
    const grouped = new Map<string, AgentRun[]>();
    for (const run of agentRuns) {
      const id = sessionId(run, selectedAgent);
      grouped.set(id, [...(grouped.get(id) ?? []), run]);
    }
    return [...grouped.entries()].map(([id, runs]) => ({ id, runs }));
  }, [agentRuns, selectedAgent]);

  const visibleEvents = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return events.filter((event) => {
      if (moduleFilter !== "all" && event.moduleId !== moduleFilter) return false;
      if (decisionFilter !== "all" && event.decision !== decisionFilter) return false;
      if (!needle) return true;
      return [
        event.type,
        event.reason,
        event.ruleId,
        event.agentName,
        event.runPrompt,
        event.moduleId,
        event.payload ? JSON.stringify(event.payload) : null,
      ].some((value) => value?.toLowerCase().includes(needle));
    });
  }, [decisionFilter, events, moduleFilter, search]);

  const chronologicalEvents = [...visibleEvents].reverse();
  const selectedModule =
    overview?.modules.find((module) => module.id === selectedModuleId) ??
    overview?.modules[0] ??
    null;
  const runEffects = selectedRun
    ? [...selectedRun.effects, ...selectedRun.externalEffects]
    : [];
  const deniedEffects = runEffects.filter((effect) => effect.decision === "deny").length;
  const reviewEffects = runEffects.filter(
    (effect) => effect.decision === "require_approval",
  ).length;

  const chooseAgent = (agentId: string) => {
    setPlatformSelected(false);
    setView("runs");
    setSelectedAgentId(agentId);
    setSelectedRunId(null);
    setSelectedEvent(null);
  };

  const choosePlatform = () => {
    setPlatformSelected(true);
    setView("runs");
    setSelectedRunId(null);
    setSelectedEvent(null);
  };

  if (!overview) {
    return (
      <section className="security-center security-loading" aria-live="polite">
        <span className="security-live-dot" />
        {error ?? "Loading security data…"}
      </section>
    );
  }

  return (
    <section className="security-center">
      <header className="security-header">
        <div>
          <h1>Security Center</h1>
          <p>Inspect protection decisions in the context of one Agent, Session and Run.</p>
        </div>
        <div className="security-header-actions">
          <div className={"security-posture security-posture-" + overview.posture}>
            <span className="security-live-dot" />
            <strong>{overview.posture === "protected" ? "Protected" : "Degraded"}</strong>
            <small>{overview.ledger.valid ? "Ledger verified" : "Ledger verification failed"}</small>
          </div>
          <button className="security-refresh" onClick={() => void refreshStructure()} disabled={refreshing}>
            {refreshing ? "Refreshing" : "Refresh"}
          </button>
        </div>
      </header>

      {error && <div className="security-inline-error">Security data could not refresh: {error}</div>}

      <div className="security-tabs" role="tablist" aria-label="Security Center views">
        <button className={view === "runs" ? "active" : ""} onClick={() => setView("runs")}>Agent runs</button>
        <button className={view === "modules" ? "active" : ""} onClick={() => setView("modules")}>Modules</button>
        <span>{overview.ledger.events} signed events</span>
      </div>

      {view === "modules" ? (
        <div className="module-workbench">
          <nav className="module-index" aria-label="Security modules">
            <div className="security-panel-title"><span>Installed modules</span><strong>{overview.modules.length}</strong></div>
            {overview.modules.map((module) => (
              <button
                key={module.id}
                className={selectedModule?.id === module.id ? "selected" : ""}
                onClick={() => setSelectedModuleId(module.id)}
              >
                <span className={"module-state module-state-" + module.status} />
                <div><strong>{module.name}</strong><small>{module.kind} / {module.version}</small></div>
                <b>{moduleEventCount(module)}</b>
              </button>
            ))}
          </nav>
          <main className="module-detail">
            {selectedModule && (
              <>
                <div className="module-detail-heading">
                  <div>
                    <span className="security-overline">{selectedModule.kind} module</span>
                    <h2>{selectedModule.name}</h2>
                    <p>{selectedModule.description}</p>
                  </div>
                  <span className={"module-status module-status-" + selectedModule.status}>{selectedModule.status}</span>
                </div>
                <dl className="module-facts">
                  <div><dt>Module ID</dt><dd>{selectedModule.id}</dd></div>
                  <div><dt>Version</dt><dd>{selectedModule.version}</dd></div>
                  <div><dt>Events</dt><dd>{moduleEventCount(selectedModule)}</dd></div>
                  <div><dt>Configuration</dt><dd>{selectedModule.statusReason}</dd></div>
                </dl>
                <section className="module-capabilities">
                  <h3>Capabilities</h3>
                  {selectedModule.capabilities.map((capability) => <div key={capability}>{capability}</div>)}
                </section>
                <section className="module-contract">
                  <h3>Integration contract</h3>
                  <p>
                    Modules declare metadata, review effects and consume redacted security events.
                    A module may tighten a decision, while the registry prevents it from relaxing an
                    existing restriction.
                  </p>
                </section>
              </>
            )}
          </main>
        </div>
      ) : (
        <div className="security-workbench">
          <nav className="security-scope" aria-label="Agent and Run navigation">
            <div className="security-panel-title"><span>Agents</span><strong>{agents.length}</strong></div>
            <button className={"platform-scope " + (platformSelected ? "selected" : "")} onClick={choosePlatform}>
              <span className="platform-mark">P</span>
              <div><strong>Platform</strong><small>Startup and ledger events</small></div>
            </button>
            <div className="security-agent-list">
              {agents.map((agent) => (
                <div key={agent.id} className="security-agent-group">
                  <button
                    className={selectedAgentId === agent.id && !platformSelected ? "selected" : ""}
                    onClick={() => chooseAgent(agent.id)}
                  >
                    <span className="security-agent-avatar">{agent.name.slice(0, 1).toUpperCase()}</span>
                    <div><strong>{agent.name}</strong><small>{agent.principalStatus} principal</small></div>
                    <b>{runsByAgent[agent.id]?.length ?? 0}</b>
                  </button>
                  {selectedAgentId === agent.id && !platformSelected && (
                    <div className="security-session-tree">
                      {sessions.length === 0 ? (
                        <p>No Runs recorded for this Agent.</p>
                      ) : sessions.map((session) => (
                        <section key={session.id}>
                          <div className="session-tree-heading"><span>Session</span><code title={session.id}>{short(session.id, 16)}</code></div>
                          {session.runs.map((run, index) => (
                            <button
                              key={run.id}
                              className={selectedRunId === run.id ? "selected" : ""}
                              onClick={() => { setSelectedRunId(run.id); setSelectedEvent(null); }}
                            >
                              <span className={"run-state run-state-" + runTone(run.status)} />
                              <div><strong>Run {session.runs.length - index}</strong><small>{run.prompt}</small></div>
                            </button>
                          ))}
                        </section>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </nav>

          <main className="security-run-panel">
            {platformSelected ? (
              <div className="run-heading">
                <div>
                  <div className="security-breadcrumbs"><span>Security Center</span><b>/</b><strong>Platform</strong></div>
                  <h2>Platform events</h2>
                  <p>Control-plane startup, recovery and ledger verification events.</p>
                </div>
                <span className="run-status-label run-status-label-success">{visibleEvents.length} events</span>
              </div>
            ) : selectedAgent && selectedRun ? (
              <>
                <div className="run-heading">
                  <div>
                    <div className="security-breadcrumbs">
                      <span>Security Center</span><b>/</b><span>{selectedAgent.name}</span><b>/</b>
                      <span>{short(sessionId(selectedRun, selectedAgent), 12)}</span><b>/</b><strong>{short(selectedRun.id, 8)}</strong>
                    </div>
                    <h2>{selectedRun.prompt}</h2>
                    <p>Started {formatTimestamp(selectedRun.startedAt ?? selectedRun.createdAt)} / {formatDuration(selectedRun)}</p>
                  </div>
                  <div className="run-heading-actions">
                    <span className={"run-status-label run-status-label-" + runTone(selectedRun.status)}>{selectedRun.status.replaceAll("_", " ")}</span>
                    <button onClick={() => onOpenRun(selectedAgent.id, selectedRun)}>Open in Playground</button>
                  </div>
                </div>
                <div className="run-summary" aria-label="Selected Run summary">
                  <div><span>Effects</span><strong>{runEffects.length}</strong></div>
                  <div><span>Blocked</span><strong>{deniedEffects}</strong></div>
                  <div><span>Reviews</span><strong>{reviewEffects}</strong></div>
                  <div><span>Runtime calls</span><strong>{selectedRun.trace.length}</strong></div>
                  <div><span>Policy</span><strong title={selectedRun.policyVersion ?? "Not evaluated"}>{short(selectedRun.policyVersion, 14)}</strong></div>
                </div>
                <div className="run-context">
                  <div><span>Agent principal</span><code>{short(selectedAgent.principalId, 28)}</code></div>
                  <div><span>Session</span><code>{short(sessionId(selectedRun, selectedAgent), 28)}</code></div>
                  <div><span>Capability</span><code>{short(selectedRun.securityContextId, 28)}</code></div>
                </div>
              </>
            ) : selectedAgent ? (
              <div className="security-empty">
                <span className="security-empty-glyph">◈</span>
                <h2>No security evidence yet</h2>
                <p>
                  Send <strong>{selectedAgent.name}</strong> a task in the Playground. Every run
                  will appear here with its staged effects, policy decisions and ledger events.
                </p>
              </div>
            ) : (
              <div className="security-empty">
                <span className="security-empty-glyph">◈</span>
                <h2>No Agent selected</h2>
                <p>Select an Agent from the navigation to inspect its Runs and decisions.</p>
              </div>
            )}

            {(platformSelected || selectedRun) && (
              <>
                <section className="trace-map" aria-label="Run security pipeline">
                  <div className="trace-map-heading">
                    <div><strong>Security trace</strong><span>{visibleEvents.length} events in this scope</span></div>
                    <div className="trace-legend"><span className="legend-allow">Allow</span><span className="legend-review">Review</span><span className="legend-deny">Deny</span></div>
                  </div>
                  {lanes.map((lane) => {
                    const laneEvents = chronologicalEvents.filter((event) => event.stage && lane.stages.includes(event.stage));
                    return (
                      <div className="trace-map-lane" key={lane.id}>
                        <span>{lane.label}</span>
                        <div>
                          {laneEvents.map((event) => (
                            <button
                              key={event.sequence}
                              className={"trace-block trace-block-" + eventTone(event) + (selectedEvent?.sequence === event.sequence ? " selected" : "")}
                              title={eventLabel(event) + ": " + (event.reason ?? "Security event")}
                              onClick={() => setSelectedEvent(event)}
                            >
                              {eventLabel(event)}
                            </button>
                          ))}
                          {laneEvents.length === 0 && <span className="trace-lane-empty">No event</span>}
                        </div>
                      </div>
                    );
                  })}
                </section>

                <div className="security-event-toolbar">
                  <div><strong>Events</strong><span>{visibleEvents.length}</span></div>
                  <select value={moduleFilter} onChange={(event) => setModuleFilter(event.target.value)} aria-label="Filter by module">
                    <option value="all">All modules</option>
                    {overview.modules.map((module) => <option value={module.id} key={module.id}>{module.name}</option>)}
                  </select>
                  <select value={decisionFilter} onChange={(event) => setDecisionFilter(event.target.value)} aria-label="Filter by decision">
                    <option value="all">All decisions</option><option value="allow">Allow</option><option value="require_approval">Review</option><option value="deny">Deny</option><option value="approved">Approved</option>
                  </select>
                  <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search events" aria-label="Search events" />
                </div>

                <div className="security-event-list">
                  {visibleEvents.length === 0 ? (
                    <div className="security-empty compact"><p>No events match the current filters.</p></div>
                  ) : visibleEvents.map((event) => (
                    <button className={"security-event-row " + (selectedEvent?.sequence === event.sequence ? "selected" : "")} key={event.sequence} onClick={() => setSelectedEvent(event)}>
                      <span className={"event-severity event-severity-" + eventTone(event)} />
                      <time title={formatTimestamp(event.createdAt)}>{relativeTime(event.createdAt)}</time>
                      <span className="event-stage">{event.stage ?? "verify"}</span>
                      <div><strong>{eventLabel(event)}</strong><small>{event.reason ?? "Security event recorded"}</small></div>
                      <span className={"event-decision event-decision-" + eventTone(event)}>{decisionLabel(event.decision)}</span>
                    </button>
                  ))}
                </div>
              </>
            )}
          </main>

          <aside className="security-inspector">
            {selectedEvent ? (
              <>
                <div className="inspector-heading"><span className={"event-severity event-severity-" + eventTone(selectedEvent)} /><div><small>Event {selectedEvent.sequence}</small><h2>{eventLabel(selectedEvent)}</h2></div></div>
                <p className="inspector-reason">{selectedEvent.reason ?? "No additional reason was recorded."}</p>
                <dl className="inspector-facts">
                  <div><dt>Module</dt><dd>{selectedEvent.moduleId ?? "audit-ledger"}</dd></div>
                  <div><dt>Stage</dt><dd>{selectedEvent.stage ?? "verify"}</dd></div>
                  <div><dt>Decision</dt><dd>{decisionLabel(selectedEvent.decision)}</dd></div>
                  <div><dt>Rule</dt><dd>{selectedEvent.ruleId ?? "None"}</dd></div>
                  <div><dt>Human</dt><dd>{short(selectedEvent.humanId, 24)}</dd></div>
                  <div><dt>Agent</dt><dd>{selectedEvent.agentName ?? "Platform"}</dd></div>
                  <div><dt>Run</dt><dd>{short(selectedEvent.runId, 20)}</dd></div>
                  <div><dt>Event MAC</dt><dd>{short(selectedEvent.eventMac, 20)}</dd></div>
                </dl>
                {selectedEvent.payload && Object.keys(selectedEvent.payload).length > 0 && (
                  <div className="inspector-block"><span>Redacted evidence</span><pre>{JSON.stringify(selectedEvent.payload, null, 2)}</pre></div>
                )}
                <footer><span>{formatTimestamp(selectedEvent.createdAt)}</span><span className={overview.ledger.valid ? "ledger-ok" : "ledger-bad"}>Ledger {overview.ledger.valid ? "verified" : "failed"}</span></footer>
              </>
            ) : (
              <div className="security-empty compact"><h2>Event details</h2><p>Select an event from the Trace or event list.</p></div>
            )}
          </aside>
        </div>
      )}
    </section>
  );
}
