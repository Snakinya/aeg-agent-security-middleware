# Validation Evidence

Latest code and running-state verification: 2026-08-31. Real Ark/container
acceptance: 2026-08-29 on macOS with Docker Desktop. Credentials and local model
files were excluded from all evidence.

## Verification entry points

The checks are separated so a reviewer can distinguish pure automated tests
from evidence produced by the running middleware.

| Command | Requires a running AEG instance | What it proves |
| --- | --- | --- |
| `npm run check` | No | Type safety, 51 automated tests and both production builds |
| `npm run verify:live` | Yes | API health, Ark/Codex/Runtime readiness, locked kernel modules, identity, policy simulation, ledger and any available Run evidence |
| `npm run verify:demo` | Yes | Everything above, plus mandatory normal-commit and exact-rollback evidence |
| `npm run verify:e2e` | Yes | Creates a disposable Agent and executes fresh real Ark/container normal-commit and hard-deny/rollback cases |
| `npm run verify:submission` | Yes | `npm run check` followed by the strict demo-evidence verifier |
| `npm audit --omit=dev` | No, network may be required | Production dependency vulnerability report |

Recommended submission gate:

```bash
# Terminal A
ARK_API_KEY=your-key ARK_MODEL=your-model npm run poc

# Terminal B, after one normal and one denial case exist
npm run verify:submission
npm audit --omit=dev
```

`verify-running.mjs` is read-only. It does not create an Agent, invoke a model,
approve an action or modify a workspace. It discovers the running AEG service,
including the local `3100` fallback used when port `3000` is occupied. Set
`AEG_BASE_URL` to verify a specific deployment.

`verify:e2e` is the fresh-environment acceptance command. It calls the configured
Ark model twice, creates a disposable Agent, checks measured effects, hashes,
correlated recovery events and the final ledger, then removes the Agent using the
documented archive policy. Supply `--keep` or `AEG_E2E_KEEP=true` only when its
evidence should remain visible for debugging or recording.

Expected strict result for the prepared demo state:

```text
PASS: 13 passed, 0 skipped, 0 failed
```

The verifier fails when the ledger is invalid, a locked module is disabled or
degraded, `.env` is not a locked denial, the Runtime is unavailable, a Run is
orphaned, or either required demo outcome is missing.

## Automated gate

```text
npm run check
  TypeScript: pass
  Server tests: 12 files, 51 tests passed
  Production web build: pass
  Production server build: pass

npm audit --omit=dev
  0 vulnerabilities
```

The tests cover normal commit, mixed-manifest rollback, exact before/after hash,
digest replacement, symlink rejection, Intake approval before Runtime, policy
change invalidation, declared HTTP approval and replacement, effective two-layer
HTTP simulation, module tightening, locked modules, SingGuard risk/no-risk and
classifier degradation.

## Claim-to-test matrix

| Claim | Primary automated test | Running evidence |
| --- | --- | --- |
| The Runtime receives disposable state | `container-codex-runner.test.ts`, `effect-gateway.test.ts` | `run.staged` event from `runtime-containment` |
| Hard deny rejects the complete manifest | `agent-service.test.ts`, `effect-policy.test.ts` | Rolled-back `.env` Run with equal before/after hashes |
| Approval cannot be reused after replacement | `agent-service.test.ts` digest-replacement case | Approval shows manifest digest and policy version |
| Policy/module changes invalidate approval | `agent-service.test.ts`, `security-modules.test.ts` | `policy.updated` or `module.configured` ledger event |
| Modules cannot relax a decision | `security-modules.test.ts` | Locked module status and module badges in Activity |
| Unsafe paths cannot escape the workspace | `effect-gateway.test.ts` symlink/hardlink cases | Denial event when triggered |
| Declared HTTP is constrained and attributable | `external-effect-gateway.test.ts` | Canonical request, approval and receipt in Run evidence |
| Classifier loss is observable | `security-modules.test.ts`, `agent-service.test.ts` | `singguard-nsfa-degraded` event and deterministic policy remains active |
| Evidence detects mutation | `security-ledger.test.ts` | `GET /api/ledger/verify` and Overview posture |
| Secrets are removed before evidence storage | `redaction.test.ts` | Redacted payload panel in Activity |

## Real container acceptance

`npm run poc` selected Docker, rebuilt `volc-agent-runtime:local`, verified both
bind mounts and launched the production UI/API with `RUNTIME_PROVIDER=container`.

| Scenario | Result | Security evidence |
| --- | --- | --- |
| Create `docs/container-proof.md` through a real Ark/Codex turn | `completed` | One measured file effect, `allow`, manifest digest, changed workspace hash, committed session. |
| Create harmless `.env` plus `src/should-not-commit.ts` | `rolled_back` | `.env` hard-deny, source allow, strictest decision wins, identical before/after workspace hashes. |

The temporary acceptance workspace was removed after verification.

## Browser acceptance

The production build was inspected through the browser at the normal desktop
viewport. Verified interactions:

- original Agent lifecycle and Playground remained available;
- Security Center Overview showed the five checkpoints and ledger status;
- Activity separated Agent, committed session and Run, with module badges and
  expandable event evidence;
- Policies exposed file rules, locked hard-deny, Agent analyzer actions and
  thresholds, declared HTTP subset rules, egress rules and effective simulation;
- Modules exposed lock/enable state, health, schema-generated configuration and
  recent events; approval TTL appeared only in the per-Agent profile;
- Architecture loaded the interactive one-page Archify artifact.

## Architecture quality gate

Archify showcase validation passed 9/9 checks with zero errors and zero warnings.
Containment and readability passed at 1440×900, 1600×1000, 1920×1080 and
2048×1320 in light mode; light and dark captures were visually inspected.

## Secret hygiene

- `.env`, audit keys and GGUF files are excluded from Git.
- Source and Git-history pattern scans found no Ark key or common credential form.
- Security evidence stores redacted prompts/reasons and normalized SingGuard tags.
- The demo script prohibits terminals, developer tools, real credentials and
  browser storage from appearing in the recording.
