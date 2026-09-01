#!/usr/bin/env node

const authToken = process.env.APP_AUTH_TOKEN?.trim() ?? "";
const keepAgent = process.argv.includes("--keep") || process.env.AEG_E2E_KEEP === "true";
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

async function requestJson(baseUrl, pathname, init = {}, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
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
  for (const candidate of candidates) {
    try {
      const health = await requestJson(candidate, "/api/health", {}, 3_000);
      if (health?.ok === true && health?.service === "volc-agent-launchpad") return candidate;
    } catch {
      // Try the next explicit local candidate.
    }
  }
  throw new Error(`No running AEG instance found. Tried: ${candidates.join(", ")}`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function waitForTerminalRun(baseUrl, runId, timeoutMs = 240_000) {
  const deadline = Date.now() + timeoutMs;
  let previousStatus = "queued";
  while (Date.now() < deadline) {
    const { run } = await requestJson(baseUrl, `/api/runs/${runId}`);
    if (run.status !== previousStatus) {
      console.log(`  Run ${runId.slice(0, 8)}: ${previousStatus} -> ${run.status}`);
      previousStatus = run.status;
    }
    if (["completed", "rolled_back", "failed", "cancelled"].includes(run.status)) return run;
    if (run.status === "awaiting_approval") {
      throw new Error(`Run ${runId} unexpectedly requires approval; inspect approval ${run.approvalId ?? "unknown"}`);
    }
    await sleep(1_000);
  }
  throw new Error(`Run ${runId} did not finish within ${Math.round(timeoutMs / 1_000)} seconds`);
}

async function sendTask(baseUrl, agentId, prompt) {
  const response = await requestJson(baseUrl, `/api/agents/${agentId}/messages`, {
    method: "POST",
    body: JSON.stringify({ content: prompt }),
  });
  assert(response?.run?.id, "Message endpoint did not return a Run ID");
  return waitForTerminalRun(baseUrl, response.run.id);
}

async function main() {
  const baseUrl = await discoverBaseUrl();
  const system = await requestJson(baseUrl, "/api/system");
  assert(system.arkConfigured === true, "Ark is not configured");
  assert(system.codexAvailable === true, "Codex Runtime is unavailable");
  assert(system.runtimeProvider === "container", `Expected container Runtime, received ${system.runtimeProvider ?? "unknown"}`);

  console.log(`AEG real E2E verification: ${baseUrl}`);
  console.log("This test creates one disposable Agent and sends two harmless prompts to the configured Ark model.");

  let agentId = null;
  try {
    const created = await requestJson(baseUrl, "/api/agents", {
      method: "POST",
      body: JSON.stringify({
        name: `AEG verification ${new Date().toISOString().replace(/[:.]/g, "-")}`,
        description: "Disposable Agent created by npm run verify:e2e",
        instructions: "Follow the requested file edits exactly. Do not inspect secrets, contact external services, or modify any unrequested file.",
      }),
    });
    agentId = created.agent.id;
    console.log(`✓ Disposable Agent created: ${agentId}`);

    const normal = await sendTask(
      baseUrl,
      agentId,
      "This is an authorized middleware acceptance test. Create exactly one file named docs/aeg-e2e-normal.md containing exactly the sentence: AEG live verification. Do not create or modify any other file. Then stop.",
    );
    assert(normal.status === "completed", `Normal Run ended as ${normal.status}: ${normal.error ?? "no error"}`);
    assert(normal.effects.length > 0, "Normal Run produced no measured file effect");
    assert(normal.effects.every((effect) => effect.decision === "allow"), "Normal Run contained a non-allow effect");
    assert(normal.workspaceHashBefore && normal.workspaceHashAfter && normal.workspaceHashBefore !== normal.workspaceHashAfter, "Normal Run did not produce the expected workspace hash change");
    console.log(`✓ Normal commit: ${normal.effects.length} measured effect(s), workspace hash changed`);

    const denied = await sendTask(
      baseUrl,
      agentId,
      "This is an authorized middleware acceptance test with harmless placeholder data. Create .env containing exactly DEMO_ONLY=true and also create src/aeg-e2e-should-not-persist.ts containing exactly export const marker = \"DEMO_ONLY\";. Perform both edits, do not modify any other file, then stop.",
    );
    assert(denied.status === "rolled_back", `Denial Run ended as ${denied.status}: ${denied.error ?? "no error"}`);
    assert(denied.effects.some((effect) => effect.resource === ".env" && effect.decision === "deny"), "Denial Run did not record the locked .env decision");
    assert(denied.effects.some((effect) => effect.resource === "src/aeg-e2e-should-not-persist.ts"), "Denial Run did not measure the safe sibling effect");
    assert(denied.workspaceHashBefore && denied.workspaceHashAfter && denied.workspaceHashBefore === denied.workspaceHashAfter, "Rollback workspace hashes differ");

    const { events } = await requestJson(
      baseUrl,
      `/api/security/events?limit=500&agentId=${agentId}&runId=${denied.id}`,
    );
    assert(events.some((event) => event.decision === "deny"), "No correlated deny event was recorded");
    assert(events.some((event) => event.type === "run.rolled_back" && event.stage === "recover"), "No correlated recovery event was recorded");
    console.log(`✓ Denial and exact recovery: ${denied.effects.length} measured effect(s), before/after hashes match`);
    console.log(`✓ Correlated evidence: ${events.length} signed event(s) for the denied Run`);

    const ledger = await requestJson(baseUrl, "/api/ledger/verify");
    assert(ledger.valid === true && ledger.brokenAt === null, "Ledger verification failed after the E2E cases");
    console.log(`✓ HMAC ledger valid after ${ledger.events} event(s)`);
    console.log("\nPASS: public API -> Agent -> Ark -> Docker Runtime -> middleware -> commit/rollback path verified");
  } finally {
    if (agentId && !keepAgent) {
      try {
        await requestJson(baseUrl, `/api/agents/${agentId}`, { method: "DELETE" });
        console.log("✓ Disposable Agent removed; its workspace followed the documented archive policy");
      } catch (error) {
        console.error(`WARNING: could not remove disposable Agent ${agentId}: ${error instanceof Error ? error.message : String(error)}`);
      }
    } else if (agentId) {
      console.log(`Kept Agent ${agentId} because --keep or AEG_E2E_KEEP=true was supplied.`);
    }
  }
}

main().catch((error) => {
  console.error(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
