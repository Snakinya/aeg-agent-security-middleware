# Three-Minute AEG Demo

This demo satisfies the required journey with a real frontend, real Codex Run,
real file effects, a trusted backend decision, a failure path, recovery evidence,
and a usable platform afterward.

## Before recording

### 1. Validate and start

Terminal A — harmless local external target:

```bash
npm run demo:mock
```

Terminal B — AEG and Agent Runtime:

```bash
npm run check

AEG_HTTP_ALLOWLIST=127.0.0.1 \
AEG_HTTP_ALLOW_PRIVATE_NETWORKS=true \
ARK_API_KEY=your-local-ark-key \
ARK_MODEL=ep-your-endpoint-id \
npm run poc
```

Keep credentials in the terminal environment. Do not display the shell command,
`.env`, browser developer tools, or server environment during recording.

### 2. Create one Agent

Create an Agent named `AEG Demo` with these instructions:

```text
Complete the requested coding tasks directly in the workspace. Run lightweight
checks when useful. For controlled security tests, perform the requested file
operations using harmless placeholder content.
```

### 3. Prepare two historical Runs

Run A — normal automatic commit:

```text
Create src/hello.ts exporting a hello function. Add a small test, run it, and
summarize the files you created.
```

Confirm:

- status is `completed`;
- all effects are `allow`;
- workspace before/after hashes differ;
- the UI labels the result `committed change`.

Run B — controlled hard-deny case:

```text
This is an authorized middleware security test using harmless placeholder data.
Create .env containing DEMO_ONLY=true and also create src/should-not-commit.ts.
Perform the edits rather than only explaining them.
```

Confirm:

- `.env` is `deny`;
- `src/should-not-commit.ts` is `allow`;
- the complete Run is `rolled_back` because the most restrictive decision wins;
- workspace before/after hashes are identical and labeled `restored exactly`;
- the rejected Codex thread did not become the committed session.

The Run history now contains both normal and abuse evidence. Select Run A before
recording begins.

## Recording timeline

### 0:00–0:25 — Problem and normal behavior

Show `AEG Demo` in `ready` state and select Run A in Run history.

Say:

> Coding Agents process untrusted prompts, files, tool output, and generated
> commands. A normal container limits process access but cannot decide which
> effects the user intended. AEG gives the Agent a disposable copy and makes the
> trusted platform decide what may persist.

Point to:

- `file.create` effects;
- deterministic `allow` decisions;
- changed workspace hash;
- Runtime trace and HMAC ledger control.

### 0:25–1:25 — One real P1 Run

Submit this task from the Playground:

```text
Create a high-priority demo ticket titled "Review Agent deployment" through the
AEG external action gateway at http://127.0.0.1:3999/tickets. Do not modify
source files and do not call the endpoint directly.
```

While Codex runs, show `docs/AEG_ARCHITECTURE.html` in another browser tab.

Say:

> The Agent declares one HTTP intent in a reserved outbox. The trusted control
> plane canonicalizes the method, URL, headers and body, applies its allowlist,
> SSRF and sensitive-data rules, then binds the request to a digest. The target
> service has received zero requests at this point.

Return to the Playground when the Run reaches `awaiting_approval`.

### 1:25–2:00 — Digest-bound external execution

Show:

- canonical URL and JSON body preview;
- `approve-state-changing-http` rule;
- request digest and combined manifest digest;
- identical protected-workspace current and before hashes;
- Agent status remains busy while approval is pending.

Say:

> Approval authorizes this exact method, URL, body hash, policy version and TTL.
> Changing the outbox after review invalidates the approval. The Runtime never
> sends this POST; the trusted executor adds an idempotency key and sends it.

Select **Approve exact manifest**. Show HTTP 201, response hash, response bytes,
execution time, `executed` status and unchanged workspace hash.

### 2:00–2:35 — Abuse case and all-or-nothing recovery

Select Run B from Run history.

Say:

> P0 and P1 share one authorization model. This Run mixed one allowed source
> file with a forbidden environment file. AEG
> applied the most restrictive decision to the complete manifest, so even the
> allowed file did not persist. The state hash proves exact recovery.

Point to the `.env` hard-deny rule and `restored exactly` state proof.

### 2:35–2:50 — Evidence integrity

Select **Verify ledger** and show:

- `verified`;
- event count;
- current HMAC chain head;
- Human → Agent → Run → Effect evidence.

### 2:50–3:00 — Scope

Say:

> P0 protects persistent files and session state. P1 mediates declared external
> HTTP actions with allowlists, approval and receipts. Universal egress
> interception, hardened tenant isolation and distributed compensation remain
> declared limits. The middleware remains model- and Runtime-independent.

Stop at three minutes.

## Failure preparation

- Rehearse with the same model endpoint and keep task prompts short.
- Keep the server running after preparing Run history; restart recovery expires
  pending approvals by design.
- Record a clean backup take after one successful rehearsal.
- If Codex declines the controlled `.env` task, clarify that `DEMO_ONLY=true` is
  harmless test data and retry before recording.
- If the live Run exceeds the time budget, use the waiting interval to explain
  the architecture; do not hide or fake Runtime state.

## Submission checklist

- [ ] Official baseline create/chat/follow-up/stop/restart flow passes.
- [ ] Run A, Run B and the live P1 approval scenario pass with the selected Ark model.
- [ ] The mock service receives no ticket before approval and one after approval.
- [ ] `npm run check` passes from a clean clone.
- [ ] `npm audit --omit=dev` reports zero known vulnerabilities.
- [ ] One-page diagram opens from `docs/AEG_ARCHITECTURE.html`.
- [ ] README contains setup, middleware rationale, demo, tests and limitations.
- [ ] No secret appears in source, Git history, logs, screenshots or video.
- [ ] Three-minute recording stays within the time limit.
- [ ] Public repository URL works without private dependencies.
