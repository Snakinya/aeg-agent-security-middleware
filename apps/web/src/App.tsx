import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, setAuthToken } from "./api";
import { SecurityCenter } from "./SecurityCenter";
import type { Agent, AgentRun, EffectPreview, Message, SystemInfo } from "./types";

const starterPrompts = [
  "Create a small TypeScript CLI that prints a weather summary from sample JSON.",
  "Inspect this workspace and explain what you would improve first.",
  "Build a responsive single-page todo app with tests.",
];

const pollingStatuses: AgentRun["status"][] = [
  "queued",
  "running",
  "reviewing_effects",
  "committing",
  "rolling_back",
];

const emptyForm = {
  name: "",
  description: "",
  instructions:
    "Help me build and test software in this workspace. Keep changes small and explain the result.",
};

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function StatusPill({ status }: { status: Agent["status"] }) {
  return (
    <span className={"status status-" + status}>
      <span className="status-dot" />
      {status}
    </span>
  );
}

function Spinner() {
  return <span className="spinner" aria-label="Loading" />;
}

export default function App() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [prompt, setPrompt] = useState("");
  const [activeRun, setActiveRun] = useState<AgentRun | null>(null);
  const [runHistory, setRunHistory] = useState<AgentRun[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authInput, setAuthInput] = useState("");
  const [ledgerResult, setLedgerResult] = useState<string | null>(null);
  const [effectPreviews, setEffectPreviews] = useState<EffectPreview[]>([]);
  const [approvalWorkspaceHash, setApprovalWorkspaceHash] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<"playground" | "security">("playground");
  const messageEnd = useRef<HTMLDivElement>(null);
  const selectedIdRef = useRef<string | null>(null);
  const mountedRef = useRef(true);
  const pollingRunIds = useRef(new Set<string>());
  selectedIdRef.current = selectedId;

  const selected = useMemo(
    () => agents.find((agent) => agent.id === selectedId) ?? null,
    [agents, selectedId],
  );
  const runIsOpen =
    activeRun !== null &&
    !(["completed", "failed", "cancelled", "rolled_back"] as AgentRun["status"][]).includes(
      activeRun.status,
    );

  const refreshAgents = useCallback(async () => {
    const { agents: next } = await api.listAgents();
    setAgents(next);
    setSelectedId((current) =>
      current && next.some((agent) => agent.id === current)
        ? current
        : (next[0]?.id ?? null),
    );
  }, []);

  const refreshMessages = useCallback(async (agentId: string) => {
    const result = await api.messages(agentId);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setMessages(result.messages);
    }
  }, []);

  const refreshRuns = useCallback(async (agentId: string) => {
    const result = await api.runs(agentId);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setRunHistory(result.runs);
    }
    return result.runs;
  }, []);

  const bootstrap = useCallback(async () => {
    await Promise.all([refreshAgents(), api.system().then(setSystem)]);
  }, [refreshAgents]);

  useEffect(() => {
    mountedRef.current = true;
    void api
      .auth()
      .then(async ({ required }) => {
        if (!mountedRef.current) return;
        setAuthRequired(required);
        if (!required) await bootstrap();
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : String(reason)));
    return () => {
      mountedRef.current = false;
    };
  }, [bootstrap]);

  useEffect(() => {
    setActiveRun(null);
    setShowSettings(false);
    if (!selectedId) {
      setMessages([]);
      setRunHistory([]);
      return;
    }
    void Promise.all([refreshMessages(selectedId), refreshRuns(selectedId)])
      .then(([, runs]) => {
        if (selectedIdRef.current !== selectedId) return;
        const latest = runs[0] ?? null;
        setActiveRun(latest);
        if (latest && pollingStatuses.includes(latest.status)) {
          void pollRun(latest.id, selectedId).catch((reason) =>
            setError(reason instanceof Error ? reason.message : String(reason)),
          );
        }
      })
      .catch((reason) =>
        setError(reason instanceof Error ? reason.message : String(reason)),
      );
  }, [refreshMessages, refreshRuns, selectedId]);

  useEffect(() => {
    if (selected) {
      setForm({
        name: selected.name,
        description: selected.description,
        instructions: selected.instructions,
      });
    }
  }, [selected]);

  useEffect(() => {
    messageEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activeRun]);

  useEffect(() => {
    const approvalId = activeRun?.status === "awaiting_approval" ? activeRun.approvalId : null;
    if (!approvalId) {
      setEffectPreviews([]);
      setApprovalWorkspaceHash(null);
      return;
    }
    void api
      .approval(approvalId)
      .then((result) => {
        if (mountedRef.current) {
          setEffectPreviews(result.previews);
          setApprovalWorkspaceHash(result.currentWorkspaceHash);
        }
      })
      .catch((reason) =>
        setError(reason instanceof Error ? reason.message : String(reason)),
      );
  }, [activeRun?.approvalId, activeRun?.status]);

  const createAgent = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { agent } = await api.createAgent(form);
      await refreshAgents();
      setSelectedId(agent.id);
      setShowCreate(false);
      setForm(emptyForm);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const saveAgent = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      await api.updateAgent(selected.id, form);
      await refreshAgents();
      setShowSettings(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const toggleAgent = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      if (selected.status === "stopped") {
        await api.startAgent(selected.id);
      } else {
        await api.stopAgent(selected.id);
      }
      await refreshAgents();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const deleteAgent = async () => {
    if (!selected) return;
    if (!window.confirm("Delete " + selected.name + "? Its workspace will be archived.")) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.deleteAgent(selected.id);
      await refreshAgents();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const pollRun = async (runId: string, agentId: string) => {
    if (pollingRunIds.current.has(runId)) return;
    pollingRunIds.current.add(runId);
    try {
      while (mountedRef.current) {
        await new Promise((resolve) => window.setTimeout(resolve, 900));
        if (!mountedRef.current) return;
        const result = await api.run(runId);
        if (selectedIdRef.current === agentId) setActiveRun(result.run);
        if (!pollingStatuses.includes(result.run.status)) {
          await Promise.all([refreshMessages(agentId), refreshAgents(), refreshRuns(agentId)]);
          return;
        }
      }
    } finally {
      pollingRunIds.current.delete(runId);
    }
  };

  const sendMessage = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected || !prompt.trim()) return;
    const content = prompt.trim();
    setPrompt("");
    setError(null);
    try {
      const result = await api.sendMessage(selected.id, content);
      if (selectedIdRef.current === selected.id) {
        setMessages((current) => [...current, result.message]);
        setActiveRun(result.run);
        setRunHistory((current) => [result.run, ...current]);
      }
      setAgents((current) =>
        current.map((agent) =>
          agent.id === selected.id ? { ...agent, status: "busy" } : agent,
        ),
      );
      await pollRun(result.run.id, selected.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      setActiveRun(null);
      await refreshAgents();
    }
  };

  const decideApproval = async (decision: "approve" | "deny") => {
    if (!activeRun?.approvalId || !selected) return;
    setBusy(true);
    setError(null);
    try {
      const result =
        decision === "approve"
          ? await api.approve(activeRun.approvalId)
          : await api.deny(activeRun.approvalId);
      setActiveRun(result.run);
      await Promise.all([
        refreshMessages(selected.id),
        refreshAgents(),
        refreshRuns(selected.id),
      ]);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      const result = await api.run(activeRun.id);
      setActiveRun(result.run);
      await Promise.all([refreshAgents(), refreshRuns(selected.id)]);
    } finally {
      setBusy(false);
    }
  };

  const verifyLedger = async () => {
    setLedgerResult("verifying");
    try {
      const result = await api.verifyLedger();
      setLedgerResult(
        result.valid
          ? `verified · ${result.events} events · ${result.head.slice(0, 12)}…`
          : `integrity failure at event ${result.brokenAt ?? "unknown"}`,
      );
    } catch (reason) {
      setLedgerResult(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const unlock = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setAuthToken(authInput);
    try {
      await bootstrap();
      setAuthRequired(false);
      setAuthInput("");
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        setError("The access token is not valid.");
      } else {
        setError(reason instanceof Error ? reason.message : String(reason));
      }
    } finally {
      setBusy(false);
    }
  };

  if (authRequired === null) {
    return (
      <main className="auth-screen">
        <section className="auth-card" aria-live="polite">
          <div className="brand-mark">A</div>
          <span className="eyebrow">Agent Launchpad</span>
          <h1>Connecting to the control plane</h1>
          {error ? <div className="error-banner" role="alert">{error}</div> : <Spinner />}
        </section>
      </main>
    );
  }

  if (authRequired) {
    return (
      <main className="auth-screen">
        <form className="auth-card" onSubmit={unlock}>
          <div className="brand-mark">A</div>
          <span className="eyebrow">Agent Launchpad</span>
          <h1>Enter the access token</h1>
          <p>This shared demo token is configured by the platform operator.</p>
          {error && <div className="error-banner" role="alert">{error}</div>}
          <label>
            Access token
            <input
              autoFocus
              type="password"
              value={authInput}
              onChange={(event) => setAuthInput(event.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <button className="button button-primary" disabled={busy || !authInput.trim()}>
            {busy ? <Spinner /> : "Open Launchpad"}
          </button>
        </form>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">A</div>
          <div>
            <strong>Agent Launchpad</strong>
            <span>
              {system?.runtimeProvider === "container"
                ? "Local container · Codex CLI"
                : "ECS / Docker · Codex CLI"}
            </span>
          </div>
        </div>

        <button
          className="button button-primary create-button"
          onClick={() => {
            setForm(emptyForm);
            setShowCreate(true);
          }}
        >
          <span>＋</span> Create Agent
        </button>

        <div className="workspace-nav" aria-label="Workspace navigation">
          <button
            className={activeView === "playground" ? "active" : ""}
            onClick={() => setActiveView("playground")}
          >
            <span>⌁</span>
            Playground
          </button>
          <button
            className={activeView === "security" ? "active" : ""}
            onClick={() => setActiveView("security")}
          >
            <span>◈</span>
            Security Center
          </button>
        </div>

        <div className="sidebar-label">
          <span>Your Agents</span>
          <span>{agents.length}</span>
        </div>
        <nav className="agent-list">
          {agents.map((agent) => (
            <button
              className={"agent-card " + (agent.id === selectedId ? "selected" : "")}
              key={agent.id}
              onClick={() => {
                setSelectedId(agent.id);
                setActiveView("playground");
              }}
            >
              <div className="agent-avatar">{agent.name.slice(0, 1).toUpperCase()}</div>
              <div className="agent-card-copy">
                <strong>{agent.name}</strong>
                <span>{agent.description || "Coding Agent"}</span>
              </div>
              <span className={"mini-dot mini-" + agent.status} />
            </button>
          ))}
          {agents.length === 0 && (
            <div className="empty-sidebar">
              <span>◇</span>
              Create your first coding Agent.
            </div>
          )}
        </nav>

        <div className="runtime-card">
          <span className="eyebrow">Runtime</span>
          <strong>{system?.runtime ?? "Checking…"}</strong>
          <span>
            {system?.arkModel ?? "Ark model not configured"}
            {system?.containerEngine ? " · " + system.containerEngine : ""}
          </span>
          <span>
            External HTTP · {system?.externalHttpGatewayEnabled
              ? system.externalHttpAllowlist.join(", ")
              : "disabled until allowlist is set"}
          </span>
        </div>
      </aside>

      <main className="main">
        {!system?.arkConfigured || !system?.codexAvailable ? (
          <div className="config-banner">
            <span>!</span>
            <div>
              <strong>Runtime configuration needed</strong>
              <p>
                {!system?.arkConfigured
                  ? "Set ARK_API_KEY and ARK_MODEL in .env before using the Playground."
                  : system.runtimeProvider === "container"
                    ? "The local container engine or Agent Runtime image is unavailable. Rerun npm run poc."
                    : "Codex CLI was not found. Use the Docker image or install @openai/codex."}
              </p>
            </div>
          </div>
        ) : null}

        {error && (
          <div className="error-banner" role="alert">
            <span>{error}</span>
            <button onClick={() => setError(null)}>×</button>
          </div>
        )}

        {activeView === "security" ? (
          <SecurityCenter
            initialAgentId={selectedId}
            onOpenRun={(agentId, run) => {
              setSelectedId(agentId);
              setActiveRun(run);
              setLedgerResult(null);
              setActiveView("playground");
            }}
          />
        ) : selected ? (
          <>
            <header className="agent-header">
              <div>
                <div className="header-title-row">
                  <h1>{selected.name}</h1>
                  <StatusPill status={selected.status} />
                </div>
                <p>{selected.description || "A Codex coding Agent in an isolated workspace."}</p>
              </div>
              <div className="header-actions">
                <button
                  className="button button-ghost"
                  onClick={() => setShowSettings((value) => !value)}
                  disabled={busy || selected.status === "busy"}
                >
                  Settings
                </button>
                <button
                  className="button button-ghost"
                  onClick={toggleAgent}
                  disabled={busy}
                >
                  {selected.status === "stopped" ? "Start" : "Stop"}
                </button>
                <button
                  className="button button-danger"
                  onClick={deleteAgent}
                  disabled={busy || selected.status === "busy"}
                >
                  Delete
                </button>
              </div>
            </header>

            <div className="protection-strip">
              <div>
                <span className="protection-shield">✓</span>
                <span>
                  <strong>AEG protection active</strong>
                  Effects are staged, evaluated and verified before they persist.
                </span>
              </div>
              <button onClick={() => setActiveView("security")}>Open Security Center →</button>
            </div>

            {showSettings && (
              <form className="settings-panel" onSubmit={saveAgent}>
                <div className="settings-title">
                  <div>
                    <span className="eyebrow">Agent configuration</span>
                    <h2>Instructions and identity</h2>
                  </div>
                  <button type="button" onClick={() => setShowSettings(false)}>×</button>
                </div>
                <div className="form-grid">
                  <label>
                    Name
                    <input
                      value={form.name}
                      onChange={(event) => setForm({ ...form, name: event.target.value })}
                      required
                      maxLength={80}
                    />
                  </label>
                  <label>
                    Description
                    <input
                      value={form.description}
                      onChange={(event) =>
                        setForm({ ...form, description: event.target.value })
                      }
                      maxLength={500}
                    />
                  </label>
                </div>
                <label>
                  System instructions
                  <textarea
                    value={form.instructions}
                    onChange={(event) =>
                      setForm({ ...form, instructions: event.target.value })
                    }
                    rows={5}
                    maxLength={10_000}
                  />
                </label>
                <div className="panel-footer">
                  <code>{selected.workspacePath}</code>
                  <button className="button button-primary" disabled={busy}>
                    {busy ? <Spinner /> : "Save changes"}
                  </button>
                </div>
              </form>
            )}

            <section className="playground">
              <div className="playground-topbar">
                <div>
                  <span className="eyebrow">Playground</span>
                  <h2>Build something with your Agent</h2>
                </div>
                <div className="session-info">
                  <span className="pulse" />
                  {selected.codexThreadId ? "Session connected" : "New session"}
                </div>
              </div>

              {runHistory.length > 0 && (
                <div className="run-history" aria-label="Run history">
                  <div className="run-history-label">
                    <span className="eyebrow">Run evidence</span>
                    <strong>{runHistory.length}</strong>
                  </div>
                  <div className="run-history-scroll">
                    {runHistory.slice(0, 10).map((run, index) => (
                      <button
                        key={run.id}
                        className={"run-chip " + (activeRun?.id === run.id ? "selected" : "")}
                        disabled={runIsOpen && activeRun?.id !== run.id}
                        aria-pressed={activeRun?.id === run.id}
                        onClick={() => {
                          setActiveRun(run);
                          setLedgerResult(null);
                        }}
                      >
                        <span className={"run-status-dot run-status-" + run.status} />
                        <span>
                          <b>#{runHistory.length - index}</b>
                          {run.prompt}
                        </span>
                        <small>{run.status.replaceAll("_", " ")}</small>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div className="messages">
                {messages.length === 0 && !activeRun ? (
                  <div className="welcome">
                    <div className="welcome-orbit">
                      <div>⌁</div>
                    </div>
                    <h3>What should {selected.name} build?</h3>
                    <p>
                      The Agent can inspect files, write code, run commands, and continue the
                      same Codex session across messages.
                    </p>
                    <div className="prompt-grid">
                      {starterPrompts.map((item) => (
                        <button key={item} onClick={() => setPrompt(item)}>
                          <span>↗</span>
                          {item}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : (
                  messages.map((message) => (
                    <article className={"message message-" + message.role} key={message.id}>
                      <div className="message-meta">
                        <strong>{message.role === "user" ? "You" : selected.name}</strong>
                        <span>{formatTime(message.createdAt)}</span>
                      </div>
                      <div className="message-body">{message.content}</div>
                    </article>
                  ))
                )}
                {activeRun && pollingStatuses.includes(activeRun.status) && (
                  <article className="message message-assistant thinking">
                    <div className="message-meta">
                      <strong>{selected.name}</strong>
                      <span>{activeRun.status.replaceAll("_", " ")}</span>
                    </div>
                    <div className="thinking-row">
                      <Spinner />
                      {activeRun.status === "running"
                        ? "Codex is working inside a disposable staging workspace…"
                        : "AEG is reviewing or applying the effect manifest…"}
                    </div>
                  </article>
                )}
                {activeRun?.status === "awaiting_approval" && (
                  <article className="approval-card">
                    <div className="approval-heading">
                      <div>
                        <span className="eyebrow">Digest-bound approval</span>
                        <strong>
                          {activeRun.externalEffects.length > 0
                            ? "External action is staged"
                            : "Operational changes are staged"}
                        </strong>
                      </div>
                      <span className="decision-badge decision-require_approval">review</span>
                    </div>
                    <p>
                      No external request has been sent. This approval applies only to the exact
                      combined manifest below.
                    </p>
                    <code className="digest">{activeRun.manifestDigest}</code>
                    {activeRun.workspaceHashBefore && approvalWorkspaceHash && (
                      <div className="state-proof state-proof-stable">
                        <div>
                          <span>Protected workspace</span>
                          <code>{activeRun.workspaceHashBefore.slice(0, 12)}</code>
                          <b>→</b>
                          <code>{approvalWorkspaceHash.slice(0, 12)}</code>
                        </div>
                        <strong>
                          {activeRun.workspaceHashBefore === approvalWorkspaceHash
                            ? "unchanged while pending"
                            : "concurrent change detected"}
                        </strong>
                      </div>
                    )}
                    <div className="effect-list">
                      {activeRun.effects.map((effect) => {
                        const preview = effectPreviews.find(
                          (item) => item.effectId === effect.id,
                        );
                        return (
                          <div className="effect-review" key={effect.id}>
                            <div className="effect-row">
                              <span className={"effect-kind effect-" + effect.type.split(".")[1]}>
                                {effect.type.split(".")[1]}
                              </span>
                              <code>{effect.resource}</code>
                              <span className={"decision-badge decision-" + effect.decision}>
                                {effect.decision.replace("require_", "")}
                              </span>
                            </div>
                            {preview?.binary ? (
                              <div className="binary-preview">Binary or linked file · content hidden</div>
                            ) : preview ? (
                              <div className="diff-preview">
                                {preview.before !== null && (
                                  <div>
                                    <span>Before</span>
                                    <pre>{preview.before || "(empty file)"}</pre>
                                  </div>
                                )}
                                {preview.after !== null && (
                                  <div>
                                    <span>After</span>
                                    <pre>{preview.after || "(empty file)"}</pre>
                                  </div>
                                )}
                                {preview.truncated && <small>Preview truncated at 24 KB</small>}
                              </div>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                    {activeRun.externalEffects.length > 0 && (
                      <div className="external-effect-list">
                        {activeRun.externalEffects.map((effect) => (
                          <div className="external-effect" key={effect.id}>
                            <div className="effect-row">
                              <span className="effect-kind effect-http">{effect.method}</span>
                              <code>{effect.url}</code>
                              <span className={"decision-badge decision-" + effect.decision}>
                                {effect.decision.replace("require_", "")}
                              </span>
                            </div>
                            <div className="external-effect-meta">
                              <span>{effect.ruleId}</span>
                              <code>{effect.requestDigest.slice(0, 16)}…</code>
                              <span>{effect.bodyBytes} request bytes</span>
                            </div>
                            <p>{effect.reason}</p>
                            {effect.bodyPreview && <pre>{effect.bodyPreview}</pre>}
                          </div>
                        ))}
                      </div>
                    )}
                    <div className="approval-actions">
                      <button
                        className="button button-ghost"
                        disabled={busy}
                        onClick={() => void decideApproval("deny")}
                      >
                        Deny & rollback
                      </button>
                      <button
                        className="button button-primary"
                        disabled={busy}
                        onClick={() => void decideApproval("approve")}
                      >
                        {busy ? <Spinner /> : "Approve exact manifest"}
                      </button>
                    </div>
                  </article>
                )}
                {activeRun?.status === "failed" && (
                  <article className="run-error">
                    <strong>Run failed</strong>
                    <span>{activeRun.error}</span>
                  </article>
                )}
                {activeRun?.status === "rolled_back" && (
                  <article className="run-error security-rollback">
                    <strong>Effects rolled back</strong>
                    <span>{activeRun.securitySummary}</span>
                  </article>
                )}
                {activeRun &&
                  (activeRun.effects.length > 0 || activeRun.externalEffects.length > 0) &&
                  activeRun.status !== "awaiting_approval" && (
                  <article className="evidence-card">
                    <div className="approval-heading">
                      <div>
                        <span className="eyebrow">Run evidence</span>
                        <strong>{activeRun.securitySummary ?? "Effect review"}</strong>
                      </div>
                      <button className="ledger-button" onClick={() => void verifyLedger()}>
                        Verify ledger
                      </button>
                    </div>
                    <div className="effect-list">
                      {activeRun.effects.map((effect) => (
                        <div className="effect-row" key={effect.id}>
                          <span className={"effect-kind effect-" + effect.type.split(".")[1]}>
                            {effect.type.split(".")[1]}
                          </span>
                          <code>{effect.resource}</code>
                          <span className={"decision-badge decision-" + effect.decision}>
                            {effect.decision.replace("require_", "")}
                          </span>
                        </div>
                      ))}
                    </div>
                    {activeRun.externalEffects.length > 0 && (
                      <div className="external-effect-list">
                        {activeRun.externalEffects.map((effect) => (
                          <div className="external-effect" key={effect.id}>
                            <div className="effect-row">
                              <span className="effect-kind effect-http">{effect.method}</span>
                              <code>{effect.url}</code>
                              <span className={"external-status external-status-" + effect.status}>
                                {effect.status}
                              </span>
                            </div>
                            <p>{effect.reason}</p>
                            {effect.receipt && (
                              <div className="external-receipt">
                                <strong>HTTP {effect.receipt.statusCode}</strong>
                                <span>{effect.receipt.responseBytes} response bytes</span>
                                <code>{effect.receipt.responseHash.slice(0, 16)}…</code>
                                {effect.receipt.bodyPreview && (
                                  <pre>{effect.receipt.bodyPreview}</pre>
                                )}
                              </div>
                            )}
                            {effect.error && <div className="external-error">{effect.error}</div>}
                          </div>
                        ))}
                      </div>
                    )}
                    <div className="evidence-footer">
                      <code>{activeRun.manifestDigest?.slice(0, 20)}…</code>
                      <span>{activeRun.trace.length} trace events</span>
                      {ledgerResult && <span>{ledgerResult}</span>}
                    </div>
                    {activeRun.workspaceHashBefore && activeRun.workspaceHashAfter && (
                      <div
                        className={
                          "state-proof " +
                          (activeRun.workspaceHashBefore === activeRun.workspaceHashAfter
                            ? "state-proof-stable"
                            : "state-proof-changed")
                        }
                      >
                        <div>
                          <span>Workspace SHA-256</span>
                          <code>{activeRun.workspaceHashBefore.slice(0, 12)}</code>
                          <b>→</b>
                          <code>{activeRun.workspaceHashAfter.slice(0, 12)}</code>
                        </div>
                        <strong>
                          {activeRun.status === "rolled_back"
                            ? activeRun.workspaceHashBefore === activeRun.workspaceHashAfter
                              ? "restored exactly"
                              : "recovery mismatch"
                            : activeRun.workspaceHashBefore === activeRun.workspaceHashAfter
                              ? "workspace unchanged"
                              : "committed change"}
                        </strong>
                      </div>
                    )}
                    {activeRun.trace.length > 0 && (
                      <div className="trace-list">
                        {activeRun.trace.map((event) => (
                          <div className="trace-row" key={event.id}>
                            <span>{event.type.replaceAll("_", " ")}</span>
                            <code>{event.summary}</code>
                            {event.exitCode !== null && <b>exit {event.exitCode}</b>}
                          </div>
                        ))}
                      </div>
                    )}
                  </article>
                )}
                <div ref={messageEnd} />
              </div>

              <form className="composer" onSubmit={sendMessage}>
                <textarea
                  value={prompt}
                  onChange={(event) => setPrompt(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      event.currentTarget.form?.requestSubmit();
                    }
                  }}
                  placeholder={
                    selected.status === "stopped"
                      ? "Start this Agent to continue…"
                      : "Describe what you want the Agent to do…"
                  }
                  disabled={
                    selected.status === "stopped" ||
                    selected.status === "busy" ||
                    runIsOpen
                  }
                  rows={3}
                />
                <div className="composer-footer">
                  <span>
                    Enter to send · Shift + Enter for newline · {system?.codexSandboxMode ?? "checking sandbox"}
                  </span>
                  <button
                    className="send-button"
                    disabled={
                      !prompt.trim() ||
                      selected.status === "stopped" ||
                      selected.status === "busy" ||
                      runIsOpen
                    }
                    aria-label="Send message"
                  >
                    ↑
                  </button>
                </div>
              </form>
            </section>
          </>
        ) : (
          <div className="no-agent">
            <div className="no-agent-art">A</div>
            <span className="eyebrow">Agent Launchpad</span>
            <h1>Your runtime is ready for an Agent.</h1>
            <p>Create a workspace, give Codex a job, and continue the conversation here.</p>
            <button
              className="button button-primary"
              onClick={() => {
                setForm(emptyForm);
                setShowCreate(true);
              }}
            >
              Create your first Agent
            </button>
          </div>
        )}
      </main>

      {showCreate && (
        <div className="modal-backdrop" onMouseDown={() => setShowCreate(false)}>
          <form
            className="modal"
            onSubmit={createAgent}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="modal-heading">
              <div>
                <span className="eyebrow">New workspace</span>
                <h2>Create an Agent</h2>
                <p>Each Agent gets a persistent folder and a resumable Codex session.</p>
              </div>
              <button type="button" onClick={() => setShowCreate(false)}>×</button>
            </div>
            <label>
              Name
              <input
                autoFocus
                placeholder="Frontend Builder"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
                maxLength={80}
              />
            </label>
            <label>
              Description
              <input
                placeholder="Builds polished React prototypes"
                value={form.description}
                onChange={(event) =>
                  setForm({ ...form, description: event.target.value })
                }
                maxLength={500}
              />
            </label>
            <label>
              Instructions
              <textarea
                value={form.instructions}
                onChange={(event) =>
                  setForm({ ...form, instructions: event.target.value })
                }
                rows={6}
                maxLength={10_000}
              />
            </label>
            <div className="modal-footer">
              <button
                type="button"
                className="button button-ghost"
                onClick={() => setShowCreate(false)}
              >
                Cancel
              </button>
              <button className="button button-primary" disabled={busy}>
                {busy ? <Spinner /> : "Create Agent"}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
