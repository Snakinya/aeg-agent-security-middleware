# AEG v3 Submission Guide

## Middleware problem

An Agent can produce useful source changes and dangerous side effects in the
same turn. Runtime logs describe what the Agent claims it did, but they do not
authorize persistent effects. Agent Effect Gateway (AEG) places a trusted,
transactional decision boundary between an untrusted Agent Runtime and durable
workspace, session, and declared HTTP state.

AEG stages each Run, measures its effects, applies versioned per-Agent policy
and pluggable analyzers, pauses exact high-risk manifests for human approval,
and then atomically commits or discards the entire result. Every decision is
correlated in a redacted, HMAC-chained event ledger.

## Submission story

> AEG is an Agent security middleware Runtime: a non-bypassable transactional
> effect kernel surrounded by configurable modules that may observe or tighten
> decisions but cannot weaken the kernel.

The kernel owns staging, measured diffs, hard-deny rules, manifest digests,
atomic commit, rollback, and session promotion. Modules add per-Agent policy,
Intake scanning, local SingGuard-NSFA analysis, scoped Run delegation, approval,
declared HTTP mediation, trace correlation, and evidence.

## Evaluation alignment

| Category | Weight | Repository evidence |
| --- | ---: | --- |
| End-to-end middleware behavior | 40% | Playground → Intake → disposable Runtime → measured manifest → policy/approval → commit or rollback; Security Center shows the correlated Run. |
| Technical design and integration | 25% | Typed module contract, five fixed checkpoints, most-restrictive decision ordering, per-Agent profiles, trusted/untrusted boundary, Architecture page. |
| Verification and robustness | 20% | Automated normal, denial, approval, digest replacement, policy invalidation, symlink, HTTP and degradation tests; redaction, cleanup, hash proof and HMAC verification. |
| Demo and reproducibility | 15% | `npm run poc`, `npm run check`, three-minute script, casebook, one-page interactive architecture diagram and explicit limits. |

## Required deliverables

- Three-minute live demo: [DEMO.md](DEMO.md)
- One-page architecture diagram: [interactive HTML](../apps/web/public/diagrams/aeg-architecture.html)
- Reproducible repository: README, automated checks, [casebook](CASEBOOK.md),
  [validation evidence](VALIDATION.md), design documents and declared limitations

## Implemented checkpoints

1. **Intake** — secret-pattern and optional Guardrail Model analysis runs before
   the Agent Runtime. A signal may allow, require approval, or deny.
2. **Runtime** — Codex receives Run-specific workspace and session copies. The
   real workspace is never mounted into the Runtime path.
3. **Effect Review** — the control plane measures file and declared HTTP effects,
   then applies hard-deny rules and enabled modules with deny-first precedence.
4. **Approval** — the human reviews the exact canonical manifest. Approval is
   bound to digest, policy version, before-state and TTL.
5. **Execute / Commit** — trusted code revalidates and atomically commits files,
   promotes the session, or executes an approved declared HTTP request.

## Reproducibility

```bash
cp .env.example .env
# Set ARK_API_KEY and ARK_MODEL in .env without committing the file.
npm run check
npm run poc
```

Open <http://localhost:3000>, select or create an Agent, run the baseline task,
then follow [CASEBOOK.md](CASEBOOK.md). The optional local classifier runs in a
second terminal:

```bash
npm run guardrail:singguard
```

The model file is intentionally excluded from Git. The module can also be
configured to an operator-managed endpoint in Security Center → Modules.

## Security boundary and limitations

- The local Human principal provides attribution, delegation and revocation
  evidence. It is not production authentication or multi-tenant authorization.
- The container is a disposable development isolation boundary, not a hardened
  tenant sandbox.
- AEG fully governs persistent workspace and committed Codex-session effects.
- The HTTP gateway governs actions declared through `.aeg/external-effects.json`.
  Per-Agent HTTP hosts may only narrow the platform `AEG_HTTP_ALLOWLIST`; the
  effective-policy simulator displays the stricter platform result.
  Universal Runtime egress interception is not implemented; the Egress Firewall
  module is disabled and reports degraded until an L3 proxy is attached.
- Local SingGuard-NSFA is a probabilistic Intake signal. Its outage is visible;
  deterministic hard-deny, policy, approval and transactional controls continue.
- JSON persistence and the local HMAC key support one POC control-plane process.
  Production evidence needs external identity, KMS signing and durable storage.

## Final pre-submission gate

- [ ] Baseline create, chat, follow-up, stop and restart flow passes in a real container.
- [ ] The live Run uses the configured Ark model and produces a real effect.
- [ ] One normal case and one denial/recovery case are visible in Security Center.
- [ ] `npm run check` and `npm audit --omit=dev` pass.
- [ ] The architecture HTML opens and all six Security Center pages are usable.
- [ ] Repository and Git history contain no credential or local model artifact.
- [ ] Video contains no terminal environment, `.env`, browser storage or real secret.
- [ ] Repository URL is accessible to judges and setup requires no private dependency.
