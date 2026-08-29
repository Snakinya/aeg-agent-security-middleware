# Validation Evidence

Last full local verification: 2026-08-29, macOS with Docker Desktop and a real
Ark endpoint. Credentials and local model files were excluded from all evidence.

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
