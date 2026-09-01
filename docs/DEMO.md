# Three-Minute AEG v3 Demo

The recording must contain one real frontend-to-Agent Run, one normal outcome,
one denial or recovery outcome, and the evidence that explains both.

## Reproducibility contract

A reviewer needs Node.js 22+, one supported container engine and an Ark API key
and model ID. ECS, Terraform and SingGuard are optional. The deterministic
transaction kernel, policy, approval, rollback and ledger work without the local
classifier.

```bash
git clone <repository-url> aeg
cd aeg
cp .env.example .env
# Set only ARK_API_KEY and ARK_MODEL in .env.
npm run poc
```

Open <http://localhost:3000>, create or select an Agent and run Cases 1, 3 and
3B from [CASEBOOK.md](CASEBOOK.md). In another terminal:

```bash
npm run verify:demo
```

A reviewer who wants a fresh automated real-model acceptance run can instead
execute:

```bash
npm run verify:e2e
```

It creates one disposable Agent, makes one allowed file change, attempts one
mixed `.env` change, proves exact rollback, then commits a later safe change on
the restored state. It verifies correlated evidence and the ledger before
removing the Agent. It consumes three Ark turns.

The expected result is `PASS: 14 passed, 0 skipped, 0 failed`. The command is
read-only and prints no key, prompt payload or file content. When another local
application owns port 3000, start with `PORT=3100 PUBLIC_PORT=3100 npm run poc`;
the verifier discovers that fallback automatically, or accepts
`AEG_BASE_URL=http://127.0.0.1:3100`.

For a clean clone with no prepared Runs, `npm run verify:live` checks the full
running control plane and marks only the historical Run evidence as skipped.
After Cases 1, 3 and 3B, the strict verifier must pass.

## Evidence contract for the three-minute demo

| Demo statement | Visible behavior | Independent evidence |
| --- | --- | --- |
| A real Agent still works | Playground completes a source task | Measured effects and changed workspace hash |
| Persistence is mediated | Run passes five checkpoints | Activity events identify the responsible modules |
| Hard deny cannot be configured away | `.env` is denied | Simulator reports locked rule; mixed Run rolls back |
| Recovery is exact | Safe sibling change also stays out | Before and after workspace hashes match |
| Containment does not poison the Agent | A later safe Run commits | Same Agent returns to the normal path after rollback |
| Approval covers exact content | Pending manifest shows digest and policy version | Replacement and policy invalidation tests |
| Optional model guard is modular | SingGuard event appears at Intake | Module health/configuration and normalized tags |
| Evidence is verifiable | Overview reports protected | HMAC chain verification succeeds |

## Before recording

1. Run `npm run check` and `npm audit --omit=dev`.
2. Start SingGuard with `npm run guardrail:singguard` when using the model case.
3. Start the platform with `npm run poc`; keep `.env` and terminals off-screen.
4. Select one Agent in `ready` state. Prepare these historical Runs:
   - Case 1 from [CASEBOOK.md](CASEBOOK.md): normal committed source change.
   - Case 3: forbidden `.env` mixed with a safe source change, fully rolled back.
   - The live Run recorded later will serve as Case 3B and prove recovery.
   - Optional: Case 4 or 5 for a SingGuard Intake decision.
5. Leave Security Center → Activity focused on the normal Run.

Use the same real Ark endpoint and container path during rehearsal and recording.
Do not use a real credential in any prompt, screenshot, trace or terminal.

## Recording timeline

### 0:00–0:20 — select the Agent and define the problem

Show the original Agent page, its lifecycle state and the selected Agent.

Say:

> Agent output can contain useful changes and dangerous side effects in one turn.
> AEG runs the Agent on disposable state and lets a trusted transactional kernel
> decide which measured effects may become persistent.

### 0:20–0:45 — architecture and boundary

Open Security Center → Architecture. Follow the five checkpoints from Intake to
Execute/Commit, then point to the module bus and trusted/untrusted boundary.

Say:

> The kernel owns staging, hashes, hard-deny, digest validation, atomic commit and
> rollback. Modules can inspect or tighten a decision; configuration can never
> override a kernel hard-deny. Model output and Runtime trace remain untrusted.

### 0:45–1:20 — one real live Run

Return to Playground and submit:

```text
Create docs/live-demo.md with one heading and one sentence describing AEG.
Then summarize the file you created.
```

While it runs, show the light security notice and current Run status. When it
finishes, open Activity and show the five checkpoint strip, measured file effect,
module badge and changed workspace hash.

Point out that this Run is newer than the prepared denied Run on the same Agent:
the middleware contained the malicious action without leaving the Agent stuck.

### 1:20–1:55 — exact human approval

Open the prepared Dockerfile approval case, or create it before the recording and
leave it pending. Show that the real workspace is unchanged, then open Approvals.

Say:

> This approval covers the exact file content, policy version, workspace
> before-state and TTL. A replacement after review changes the digest and is
> rejected. Policy changes expire pending approvals as well.

Approve the manifest. Show the completed Run and approver attribution. If live
Ark latency is unpredictable, keep this approval prepared before recording.

### 1:55–2:25 — denial and exact recovery

Select the prepared mixed `.env` Run.

Say:

> One effect hit the locked environment-file deny rule. Most-restrictive ordering
> rejected the complete manifest, so the otherwise allowed source file also stayed
> out. Equal before and after hashes prove that persistent state was restored.

Point to `hard-deny-platform-and-secrets`, `rolled_back`, and the equal hashes.

### 2:25–2:45 — modular analyzer evidence

Open the prepared SingGuard Run and its Activity event. Show the module ID,
normalized classification and the pre-Runtime decision. Briefly open Modules to
show provider, risk action and health. If SingGuard was stopped intentionally,
show the visible degraded event and continued deterministic controls instead.

### 2:45–3:00 — verification and limits

Verify the ledger on Overview.

Say:

> The redacted event chain verifies successfully. AEG governs persistent files,
> committed session state and declared HTTP actions. Production authentication,
> hardened tenant isolation and universal L3 egress enforcement remain documented
> extensions.

Stop before three minutes.

## Recording safety

- Record browser content only; exclude terminals, developer tools and `.env`.
- Use harmless placeholders and clear Run history that contains prior real secrets.
- Keep prompts short so one live Run fits the schedule.
- Preserve prepared evidence if Ark is slow; the required live Run must still be real.
- Verify the final take contains no API key, bearer token or local filesystem secret.

## Final checklist

- [ ] One Agent is selected from the original frontend and remains controllable.
- [ ] One real model/Runtime/file action runs during the recording.
- [ ] Normal commit and denial/recovery evidence are both shown.
- [ ] A safe Run after the denied Run completes on the same Agent.
- [ ] Architecture displays trust boundary and enforcement points.
- [ ] Approval digest or model degradation is demonstrated functionally.
- [ ] Ledger verification succeeds.
- [ ] The recording is three minutes or shorter.
