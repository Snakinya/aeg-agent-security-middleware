#!/usr/bin/env node

const requireDemoEvidence = process.argv.includes("--require-demo-evidence");
const authToken = process.env.APP_AUTH_TOKEN?.trim() ?? "";
const headers = {
  accept: "application/json",
  ...(authToken ? { authorization: `Bearer ${authToken}` } : {}),
};

const normalizeBaseUrl = (value) => value.replace(/\/+$/, "");
const configuredPort = process.env.PUBLIC_PORT || process.env.PORT || "3000";
const candidates = [
  process.env.AEG_BASE_URL,
  `http://127.0.0.1:${configuredPort}`,
  "http://127.0.0.1:3000",
  "http://127.0.0.1:3100",
].filter(Boolean).map(normalizeBaseUrl).filter((value, index, values) => values.indexOf(value) === index);

async function requestJson(baseUrl, pathname, init = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetch(`${baseUrl}${pathname}`, {
      ...init,
      headers: {
        ...headers,
        ...(init.body ? { "content-type": "application/json" } : {}),
        ...(init.headers ?? {}),
      },
      signal: controller.signal,
    });
    const text = await response.text();
    let body;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}: ${typeof body === "string" ? body : JSON.stringify(body)}`);
    }
    return body;
  } finally {
    clearTimeout(timeout);
  }
}

async function discoverBaseUrl() {
  const failures = [];
  for (const candidate of candidates) {
    try {
      const health = await requestJson(candidate, "/api/health");
      if (health?.ok === true && health?.service === "volc-agent-launchpad") {
        return candidate;
      }
      failures.push(`${candidate} returned a different service`);
    } catch (error) {
      failures.push(`${candidate}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  throw new Error(`No running AEG instance found. Tried:\n  - ${failures.join("\n  - ")}`);
}

const results = [];
const pass = (name, detail = "") => results.push({ status: "pass", name, detail });
const fail = (name, detail) => results.push({ status: "fail", name, detail });
const skip = (name, detail) => results.push({ status: "skip", name, detail });
const check = (condition, name, detail) => condition ? pass(name, detail) : fail(name, detail);

function terminalRun(run) {
  return ["completed", "rolled_back", "failed", "cancelled"].includes(run.status);
}

async function main() {
  const baseUrl = await discoverBaseUrl();
  console.log(`AEG running verification: ${baseUrl}`);

  const [system, overview, ledger, moduleResponse, identity, agentResponse] = await Promise.all([
    requestJson(baseUrl, "/api/system"),
    requestJson(baseUrl, "/api/security/overview"),
    requestJson(baseUrl, "/api/ledger/verify"),
    requestJson(baseUrl, "/api/security/modules"),
    requestJson(baseUrl, "/api/identity"),
    requestJson(baseUrl, "/api/agents"),
  ]);

  pass("HTTP and API health", "AEG health contract matched");
  check(system.arkConfigured === true, "Ark configuration", "API key and model are configured without exposing either value");
  check(system.codexAvailable === true, "Codex Runtime", "Runtime provider reports Codex available");
  check(system.runtimeProvider === "container", "Container judging path", `provider=${system.runtimeProvider ?? "unknown"}, engine=${system.containerEngine ?? "none"}`);
  check(overview.posture === "protected", "Security posture", `posture=${overview.posture ?? "unknown"}`);
  check(ledger.valid === true && ledger.brokenAt === null, "HMAC ledger integrity", `${ledger.events ?? 0} events, no broken link`);

  const modules = Array.isArray(moduleResponse.modules) ? moduleResponse.modules : [];
  const requiredKernelModules = [
    "identity-delegation",
    "runtime-containment",
    "filesystem-effects",
    "policy-profile",
    "approval-manager",
    "audit-ledger",
  ];
  const missingKernelModules = requiredKernelModules.filter((id) => {
    const module = modules.find((item) => item.id === id);
    return !module || module.locked !== true || module.enabled !== true || module.status !== "active";
  });
  check(
    missingKernelModules.length === 0,
    "Locked kernel modules",
    missingKernelModules.length === 0
      ? `${requiredKernelModules.length} required modules are locked, enabled, and active`
      : `invalid: ${missingKernelModules.join(", ")}`,
  );

  const currentHuman = identity.currentHuman;
  check(
    currentHuman && Array.isArray(currentHuman.roles) && currentHuman.roles.includes("security_admin"),
    "Operator attribution",
    currentHuman ? `human=${currentHuman.id}, roles=${currentHuman.roles.join(",")}` : "no current Human principal",
  );

  const agents = Array.isArray(agentResponse.agents) ? agentResponse.agents : [];
  if (agents.length === 0) {
    if (requireDemoEvidence) {
      fail("Prepared demo evidence", "No Agent exists; create one and run the normal and rollback cases from docs/CASEBOOK.md");
    } else {
      skip("Per-Agent policy and Run evidence", "No Agent exists yet");
    }
  } else {
    const firstAgent = agents[0];
    const simulation = await requestJson(baseUrl, `/api/agents/${firstAgent.id}/policy/simulate`, {
      method: "POST",
      body: JSON.stringify({ kind: "file", resource: ".env" }),
    });
    check(
      simulation?.result?.decision === "deny" && simulation?.result?.locked === true,
      "Kernel hard-deny simulation",
      `agent=${firstAgent.name}, .env=${simulation?.result?.decision ?? "unknown"}, locked=${simulation?.result?.locked ?? false}`,
    );

    const runGroups = await Promise.all(
      agents.map(async (agent) => ({
        agent,
        runs: (await requestJson(baseUrl, `/api/agents/${agent.id}/runs`)).runs ?? [],
      })),
    );
    const allRuns = runGroups.flatMap(({ agent, runs }) => runs.map((run) => ({ agent, run })));
    const normal = allRuns.find(({ run }) =>
      run.status === "completed" &&
      run.effects?.length > 0 &&
      run.effects.every((effect) => effect.decision === "allow") &&
      run.workspaceHashBefore &&
      run.workspaceHashAfter &&
      run.workspaceHashBefore !== run.workspaceHashAfter
    );
    const rollback = allRuns.find(({ run }) =>
      run.status === "rolled_back" &&
      run.effects?.some((effect) => effect.decision === "deny") &&
      run.workspaceHashBefore &&
      run.workspaceHashAfter &&
      run.workspaceHashBefore === run.workspaceHashAfter
    );

    const evidenceResult = (found, name, successDetail, missingDetail) => {
      if (found) return pass(name, successDetail(found));
      if (requireDemoEvidence) return fail(name, missingDetail);
      return skip(name, missingDetail);
    };
    evidenceResult(
      normal,
      "Normal commit evidence",
      ({ agent, run }) => `agent=${agent.name}, run=${run.id}, ${run.effects.length} measured effect(s), workspace hash changed`,
      "Run Case 1 from docs/CASEBOOK.md",
    );
    evidenceResult(
      rollback,
      "Denial and exact recovery evidence",
      ({ agent, run }) => `agent=${agent.name}, run=${run.id}, before/after hashes match`,
      "Run Case 3 from docs/CASEBOOK.md",
    );

    if (rollback) {
      const events = (await requestJson(
        baseUrl,
        `/api/security/events?limit=500&agentId=${rollback.agent.id}&runId=${rollback.run.id}`,
      )).events ?? [];
      check(
        events.some((event) => event.decision === "deny") &&
          events.some((event) => event.type === "run.rolled_back" && event.stage === "recover"),
        "Correlated denial trace",
        `${events.length} ledger event(s) linked to Agent and Run`,
      );
    }

    const nonTerminal = allRuns.filter(({ run }) => !terminalRun(run));
    check(nonTerminal.length === 0, "No orphan active Run", nonTerminal.length === 0 ? "all Runs are terminal" : `${nonTerminal.length} active Run(s)`);
  }

  for (const result of results) {
    const symbol = result.status === "pass" ? "✓" : result.status === "skip" ? "○" : "✗";
    console.log(`${symbol} ${result.name}${result.detail ? ` — ${result.detail}` : ""}`);
  }
  const failed = results.filter((result) => result.status === "fail");
  const passed = results.filter((result) => result.status === "pass");
  const skipped = results.filter((result) => result.status === "skip");
  console.log(`\n${failed.length === 0 ? "PASS" : "FAIL"}: ${passed.length} passed, ${skipped.length} skipped, ${failed.length} failed`);
  if (system.codexSandboxMode === "danger-full-access") {
    console.log("NOTE: Landlock is unavailable on this Docker host; the documented disposable-container boundary is active.");
  }
  if (failed.length > 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
