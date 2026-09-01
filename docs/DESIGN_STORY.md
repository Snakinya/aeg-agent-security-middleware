# AEG Design Story

## Security at the boundary where Agent output becomes real

> An Agent may be mistaken, manipulated or compromised. It should still be
> unable to create an unauthorized persistent effect.

This is the design story behind **AEG — Zero-Trust Agent Security Middleware**.
It explains the problem we selected, the insight that shaped the architecture,
why the design is stronger than a collection of guardrails, and how each claim
is demonstrated by executable evidence.

## 1. The missing layer in the Starter Kit

The Starter Kit already gives an Agent everything needed to be useful: a browser
Playground, lifecycle controls, persistent sessions, a workspace, Codex CLI, a
container Runtime and Ark model access.

That same capability creates the infrastructure problem. In one turn, an Agent
can generate four useful source files and one prohibited `.env` file. A chat log
may describe the work, but it cannot answer the questions that matter after an
Agent gains tools:

- What actually changed?
- Which change is allowed to become persistent?
- What exact content did a human approve?
- Can a safe sibling change survive when the same Run contains a forbidden one?
- What happens when a classifier, Runtime or commit operation fails?
- Can an operator reconstruct the decision without trusting the Agent's story?

The missing middleware therefore sits at the transition from **proposed action**
to **persistent effect**.

## 2. The core insight: propose freely, persist conditionally

AEG lets the Agent reason, execute commands and edit files inside disposable
state. The trusted control plane independently measures the result and decides
whether any of it may cross into protected state.

```text
Agent intent
    ↓
disposable execution
    ↓
measured effect manifest
    ↓
deterministic policy + tightening-only modules + exact human approval
    ↓
atomic commit or verified restore
```

This changes the security question from:

> “Does this prompt look safe?”

to:

> “Should this exact measured effect become durable under the current policy and
> before-state?”

Prompt analysis remains useful, but it becomes one sensor inside a larger
defense-in-depth protocol. It never receives authority to commit.

## 3. Why familiar approaches are insufficient alone

| Approach alone | Remaining problem | AEG design response |
| --- | --- | --- |
| Prompt classifier | Cannot know the final files, commands or side effects | Analyze Intake, then enforce again on measured effects |
| Runtime/tool logs | Produced by the domain being observed and may be incomplete | Treat trace as evidence; compute authoritative diffs in trusted code |
| Path allowlist | Cannot recover a mixed Run or bind a human to exact content | Stage the complete Run and decide one canonical manifest |
| Human approval by path or summary | Content may change after review | Bind approval to digest, policy version, before-state and TTL |
| Plug-in framework | One extension may weaken another or bypass execution | Modules can only preserve or tighten a decision; the kernel owns commit |
| Container isolation | Contains a process but does not decide which output persists | Combine disposable Runtime state with transactional persistence |
| Audit log | Describes history without proving enforcement or integrity | Correlate enforcement events and verify an HMAC chain |

The architectural value comes from how these mechanisms compose.

## 4. Five checkpoints form one governed Run

Every Run passes the same protocol. Each checkpoint answers one security
question and emits evidence that the operator can inspect.

| Checkpoint | Security question | Mechanism | Visible proof |
| --- | --- | --- | --- |
| **1. Intake** | Should this request reach the Runtime? | Human→Agent→Run delegation, secret scan, optional SingGuard/Ark analyzer | Intake decision, module ID, normalized risk or degradation event |
| **2. Runtime** | Can the Agent work without touching protected state? | Run-specific workspace and Codex Home copies inside a disposable container | Staging event, Runtime metadata and correlated trace |
| **3. Effect Review** | What actually changed, and what is the strictest decision? | Control-plane hashes, canonical manifest, hard-deny and policy modules | Per-effect allow/review/deny rows and responsible rule/module |
| **4. Approval** | What exact effect is the human authorizing? | Digest + policy version + real before-state + TTL | Exact preview, approval scope, approver and invalidation reason |
| **5. Execute / Commit** | Can the decision still be applied safely? | Revalidation, safe paths, snapshot, atomic application and final hash | Commit receipt or rollback with before/after hash equality |

The Runtime cannot skip a checkpoint because it never owns the protected paths
or the commit primitive.

## 5. The mechanism kernel is deliberately small and non-configurable

The kernel owns only the security properties that must remain true under every
configuration:

- staging of workspace and committed Agent session state;
- independent effect measurement;
- platform hard-deny rules;
- canonical manifest and approval digest;
- path validation and before-state checks;
- commit, snapshot restoration and final hash verification;
- policy-version binding and chained evidence.

These controls are locked in the Security Center. Their lack of a disable switch
is a visible product promise: customization cannot redefine the meaning of a
successful commit.

The kernel enforces eight invariants, documented in
[ARCHITECTURE.md](ARCHITECTURE.md). The most important are:

```text
Runtime never receives protected workspace paths
Policy uses measured facts rather than Runtime claims
Any hard deny rejects the complete manifest
Approval authorizes one immutable digest
Rolled-back workspace hash equals the before-state
Rejected session state is never promoted
```

## 6. Modules make the middleware extensible without making it fragile

Agent security will keep changing. New model analyzers, MCP policies, database
guards, memory controls and enterprise identity adapters should be addable
without rewriting orchestration.

AEG therefore exposes typed hooks at the fixed checkpoints:

```ts
interface SecurityModule {
  manifest: ModuleManifest;
  configure?(config: unknown): void;
  onIntake?(prompt: string, context: IntakeContext): Signal | null;
  reviewEffect?(effect: Effect, context: EffectContext): Contribution | null;
  onEvent?(event: SecurityEvent): void;
  health(): ModuleHealth;
}
```

The extension rule is intentionally asymmetric:

```text
allow < require_approval < deny

finalDecision = max(kernelDecision, module₁, …, moduleₙ)
```

A module can identify a new risk, request human inspection or deny an effect. It
cannot convert an earlier denial into approval or commit an effect directly.

Module configuration is also governed:

1. Configuration is validated against the module's JSON Schema.
2. The revision becomes part of the policy fingerprint.
3. A signed `module.configured` event is appended.
4. Pending approvals bound to the previous fingerprint expire.

This provides flexibility while preserving monotonic security.

## 7. Defense in depth has distinct jobs

AEG uses several layers because each layer fails differently.

| Layer | Job | When it fails |
| --- | --- | --- |
| Disposable Runtime | Keep proposed state separate from protected state | Kernel discards staging; protected state remains unchanged |
| Deterministic policy | Enforce hard resource and operation boundaries | Locked rules remain authoritative and testable |
| Probabilistic analyzer | Detect risky intent that static rules may miss | Health becomes degraded; deterministic enforcement continues |
| Human approval | Apply judgment to exact high-risk effects | Expiry, denial or mismatch causes rollback |
| Transactional Committer | Apply only revalidated effects | Snapshot restoration returns the workspace to the before-hash |
| Evidence ledger | Make decisions attributable and reviewable | Invalid chain changes system posture to degraded |

The model is useful because it is replaceable. The kernel is trustworthy because
its guarantees do not depend on the model being correct or available.

## 8. Observability is part of the control, not a log viewer

Security Center projects one shared event contract into two experiences:

- The Agent user sees a small action-time notice: protected, awaiting approval,
  blocked or restored.
- The security operator sees Agent → session → Run → checkpoint → event → module
  correlation, exact effects, identity, policy version and ledger evidence.

This separation preserves the original Playground experience while giving
operators enough context to explain a decision. The Activity page does not infer
security from free-form logs; it displays the same structured events produced by
the enforcement path.

## 9. Three moments prove the architecture

### Moment A — useful work still succeeds

The Agent creates a normal source or documentation file. AEG measures the
effect, the policy returns `allow`, the trusted committer applies it and the
workspace hash changes.

**What this proves:** the middleware preserves the Starter Kit's useful Agent
path and does not turn every action into approval friction.

### Moment B — one forbidden effect rejects the complete Run

The Agent creates both `.env` and an otherwise allowed source file. The locked
rule denies `.env`. Strictest-wins arbitration rejects the entire manifest, the
staged Agent session is not promoted, and the real before/after hashes match.

**What this proves:** containment and recovery are real backend behavior. A safe
sibling effect cannot smuggle a prohibited change through a partial commit.

### Moment C — approval cannot become stale authority

A `Dockerfile` waits for human approval. The approval covers the exact digest,
policy version, workspace before-state and TTL. Replacing the staged file or
changing policy invalidates the approval.

**What this proves:** human control is bound to a machine-verifiable object, not
to a vague description of intent.

An optional fourth moment stops SingGuard. The system records degradation while
the `.env` hard deny still works. This demonstrates graceful failure without
claiming that a probabilistic model is the trust boundary.

## 10. Why this is a coherent Agent middleware submission

| Challenge expectation | AEG response |
| --- | --- |
| Preserve the baseline | Agent CRUD, lifecycle, Playground, Ark and sessions remain intact |
| Implement real middleware behavior | Enforcement executes between Runtime staging and persistent effects |
| Define a meaningful boundary | Trusted kernel owns measurement, decision and commit; Runtime remains untrusted |
| Demonstrate failure and recovery | Mixed manifest denial produces exact workspace-hash recovery |
| Provide extensible design | Typed checkpoint modules with tightening-only arbitration |
| Add minimal useful UI | Security notices in Playground; detailed control/evidence in Security Center |
| Verify core behavior | 51 automated tests plus live and fresh real-model verification commands |
| Keep judging reproducible | Local Docker path, one-command startup, optional SingGuard and no ECS dependency |

The submission tells one story across architecture, code, UI and tests:

> **Agents may propose actions. AEG alone decides which measured effects become
> persistent, under which policy, with whose approval, and with what evidence.**

## 11. Honest boundaries strengthen the claim

The POC governs persistent workspace and committed Codex-session effects, plus
HTTP actions declared through AEG. It does not claim universal Runtime egress
interception, production authentication, hardened tenant isolation, distributed
transactions or host-administrator resistance.

The Egress Firewall card reports disabled/degraded until an L3 adapter exists.
The local Human principal is presented as attribution and delegation evidence.
The local HMAC key proves chain integrity within the POC host; production needs
KMS signing and external durable storage.

These boundaries let reviewers distinguish implemented guarantees from the
production roadmap.

## 12. Executable proof

With AEG running:

```bash
# Read-only checks of the current control plane and evidence
npm run verify:live

# Fresh real Ark + Docker Runtime normal/deny/rollback acceptance
npm run verify:e2e

# Type checks, 51 tests, production builds and strict prepared-demo evidence
npm run verify:submission
```

The full test mapping is in [VALIDATION.md](VALIDATION.md), the live cases are in
[CASEBOOK.md](CASEBOOK.md), and the three-minute presentation sequence is in
[DEMO.md](DEMO.md).
