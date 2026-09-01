# Security policy

AEG extends the Agent Launchpad hackathon proof of concept. Only the latest revision
on the default branch is supported.

## Report a vulnerability

Send the repository owner or event organizer the affected revision,
reproduction steps, impact, and suggested mitigation. Do not publish
credentials, personal data, or exploit details in an issue.

## Known limitations

- Shared demo token plus one local Human attribution principal; no production
  authentication, multi-user RBAC, or tenant isolation
- No CSRF protection
- No per-Agent container boundary in ECS mode
- Ordinary local containers, not hardened multi-tenant sandboxes
- Broad outbound network access
- Prompt-triggered command execution inside the Runtime boundary
- Ark key available to the server and active Runtime container
- Ark key stored in Terraform POC state
- File policy protects persistent state integrity, not confidentiality
- HMAC evidence detects rewriting by actors without the audit key; a host
  administrator holding that key remains trusted
- Declared external HTTP actions are mediated; universal Runtime egress
  enforcement and data-loss prevention are not implemented

## Safe use

- Use a dedicated development machine or disposable ECS instance.
- Use a scoped, revocable Ark key and a unique `APP_AUTH_TOKEN`.
- Keep local use on loopback and restrict ECS Web and SSH CIDRs.
- Add HTTPS before sending the shared token over an untrusted network.
- Never mount production data or provide Volcengine account AK/SK to Agents.
- Stop the POC, destroy test resources, and revoke keys after the event.

Codex uses `workspace-write` when Landlock is available. On unsupported kernels,
startup warns and relies on the outer Docker or rootless Podman boundary. This
fallback is not tenant isolation.

The Runtime receives a disposable workspace and Codex Home. Real workspace
changes are applied by the trusted control plane only after effect review. A
process with host-level access can still attack the control plane, staging area,
or audit key and remains outside the POC threat model.

The external HTTP gateway accepts one JSON request per Run, blocks credentials
and secret-like fields, checks a host allowlist and private-address policy, and
requires approval for state-changing methods. `AEG_HTTP_ALLOW_PRIVATE_NETWORKS`
exists for the loopback demo service and should stay disabled in deployments.
