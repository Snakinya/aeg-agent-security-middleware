# Security module integration

AEG modules are explicit, typed control-plane extensions. They do not run in
the untrusted Agent Runtime and they never receive Ark credentials.

## Contract

Each module declares a manifest and may implement two independent hooks:

- `reviewEffect` contributes a decision before commit or external execution;
- `onEvent` receives the redacted correlated security-event stream.

The registry applies most-restrictive precedence. A module can tighten
`allow` to `require_approval` or `deny`; it cannot relax an earlier decision.
Active module IDs and versions form the approval-bound policy version.

## Example policy module

```ts
const releaseGuard: SecurityModule = {
  manifest: {
    id: "release-guard",
    name: "Release Guard",
    version: "1.0.0",
    kind: "effect",
    description: "Reserves release artifacts for the deployment service.",
    capabilities: ["policy"],
    status: "active",
    statusReason: "Enabled by the platform operator.",
  },
  reviewEffect(effect) {
    if (!effect.resource.startsWith("release/")) return null;
    return {
      decision: "deny",
      ruleId: "deny-release-path",
      reason: "Release paths are owned by the deployment service",
    };
  },
};

const service = new AgentService(config, store, workspaces, runner)
  .registerSecurityModule(releaseGuard);
await service.initialize();
```

An AgentArmor adapter can use `reviewEffect` for a deterministic risk result or
`onEvent` to add analysis evidence. MCP, database, memory and provider adapters
use the same contract. External services should return structured decisions;
credentials remain in the trusted adapter and event payloads must be redacted.

## Observability

Every module appears in `GET /api/security/overview`. Events are queryable with
`GET /api/security/events` and are projected into the Security Center. A module
does not need UI-specific code to become visible.
