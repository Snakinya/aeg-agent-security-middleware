# Three-Minute AEG v3 Demo

The recording must contain one real frontend-to-Agent Run, one normal outcome,
one denial or recovery outcome, and the evidence that explains both.

## Before recording

1. Run `npm run check` and `npm audit --omit=dev`.
2. Start SingGuard with `npm run guardrail:singguard` when using the model case.
3. Start the platform with `npm run poc`; keep `.env` and terminals off-screen.
4. Select one Agent in `ready` state. Prepare these historical Runs:
   - Case 1 from [CASEBOOK.md](CASEBOOK.md): normal committed source change.
   - Case 3: forbidden `.env` mixed with a safe source change, fully rolled back.
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
- [ ] Architecture displays trust boundary and enforcement points.
- [ ] Approval digest or model degradation is demonstrated functionally.
- [ ] Ledger verification succeeds.
- [ ] The recording is three minutes or shorter.
