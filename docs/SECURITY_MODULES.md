# Security module integration

AEG modules are explicit, typed control-plane extensions. They do not run in
the untrusted Agent Runtime and they never receive Ark credentials.

## Contract

Each module declares a manifest and may implement lifecycle/configuration hooks:

- `configure` validates and hot-applies settings generated from `configSchema`;
- `onIntake` inspects a prompt before Runtime access and returns an observable signal;
- `reviewEffect` contributes a decision before commit or external execution;
- `onEvent` receives the redacted correlated security-event stream;
- `health` reports `active` or `degraded`; disabled state belongs to the registry.

The registry applies most-restrictive precedence. A module can tighten
`allow` to `require_approval` or `deny`; it cannot relax an earlier decision.
Active module IDs, versions and configuration revisions form the approval-bound
policy version. Locked kernel modules cannot be disabled. Every module change is
a ledger event and invalidates pending approvals.

## Example policy module

```ts
const releaseGuard: SecurityModule = {
  manifest: {
    id: "release-guard",
    name: "Release Guard",
    version: "1.0.0",
    kind: "policy",
    description: "Reserves release artifacts for the deployment service.",
    capabilities: ["policy"],
    locked: false,
  },
  defaultEnabled: true,
  defaultConfig: {},
  health: () => ({ status: "active", reason: "Release policy is available." }),
  reviewEffect(effect) {
    if (!effect.resource.startsWith("release/")) return null;
    return {
      decision: "deny",
      ruleId: "deny-release-path",
      reason: "Release paths are owned by the deployment service",
    };
  },
};

const registry = new SecurityModuleRegistry().register(releaseGuard);
```

An AgentArmor adapter can use `reviewEffect` for a deterministic risk result or
`onEvent` to add analysis evidence. MCP, database, memory and provider adapters
use the same contract. External services should return structured decisions;
credentials remain in the trusted adapter and event payloads must be redacted.

## SingGuard-NSFA adapter

The built-in `guardrail-model` module supports the official SingGuard-NSFA
0.8B GGUF model through a loopback llama.cpp endpoint. It XML-escapes the query,
wraps it in `<untrusted_input>`, and maps every risk tag other than `No_Risk` to
the configured `deny` or `require_approval` Intake action. Only the normalized
risk names enter the ledger; model reasoning and the original prompt are not
copied into module evidence. `No_Risk` and endpoint degradation also produce
explicit events so operators can distinguish a clean classification from an
unavailable classifier.

The local GGUF path uses SingGuard's generative mode. The approximately 50 ms
classification-head path described by the project requires a compatible
GPU/vLLM deployment and is outside the local Mac profile.

## Observability

Every module appears in `GET /api/security/modules` and the Overview projection.
Events are queryable with `GET /api/security/events` and projected into Activity.
Configuration forms are generated from module JSON schemas, so a new module can
be configured and observed without a module-specific page.
