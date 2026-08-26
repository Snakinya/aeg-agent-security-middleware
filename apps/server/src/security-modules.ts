import type { AppConfig } from "./config.js";
import type { SecurityEventInput, SecurityLedger } from "./security-ledger.js";
import type {
  EffectDecision,
  ExternalHttpEffect,
  FileEffect,
  RunSecurityContext,
} from "./types.js";

export type SecurityModuleKind =
  | "identity"
  | "runtime"
  | "effect"
  | "approval"
  | "evidence";

export interface SecurityModuleManifest {
  id: string;
  name: string;
  version: string;
  kind: SecurityModuleKind;
  description: string;
  capabilities: string[];
  status: "active" | "disabled";
  statusReason: string;
}

export interface SecurityModule {
  readonly manifest: SecurityModuleManifest;
  onEvent?(event: SecurityEventInput): Promise<void> | void;
  reviewEffect?(
    effect: FileEffect | ExternalHttpEffect,
    context: RunSecurityContext,
  ):
    | Promise<PolicyContribution | null>
    | PolicyContribution
    | null;
}

export interface PolicyContribution {
  decision: EffectDecision;
  ruleId: string;
  reason: string;
}

export class SecurityModuleRegistry {
  private readonly modules = new Map<string, SecurityModule>();

  register(module: SecurityModule): this {
    if (this.modules.has(module.manifest.id)) {
      throw new Error("Security module already registered: " + module.manifest.id);
    }
    this.modules.set(module.manifest.id, module);
    return this;
  }

  list(): SecurityModuleManifest[] {
    return [...this.modules.values()].map((module) => structuredClone(module.manifest));
  }

  get(id: string): SecurityModule {
    const module = this.modules.get(id);
    if (!module) throw new Error("Unknown security module: " + id);
    return module;
  }

  policyVersion(): string {
    return this.list()
      .filter((module) => module.status === "active")
      .map((module) => module.id + "@" + module.version)
      .sort()
      .join("+");
  }

  async reviewEffect<T extends FileEffect | ExternalHttpEffect>(
    effect: T,
    context: RunSecurityContext,
  ): Promise<T> {
    const rank: Record<EffectDecision, number> = {
      allow: 0,
      require_approval: 1,
      deny: 2,
    };
    let result: T = structuredClone(effect);
    for (const module of this.modules.values()) {
      if (module.manifest.status !== "active" || !module.reviewEffect) continue;
      const contribution = await module.reviewEffect(result, context);
      if (contribution && rank[contribution.decision] > rank[result.decision]) {
        result = { ...result, ...contribution };
        if ("status" in result && contribution.decision === "deny") {
          result = { ...result, status: "denied" };
        }
      }
    }
    return result;
  }

  async notify(event: SecurityEventInput): Promise<void> {
    await Promise.all(
      [...this.modules.values()].map((module) => module.onEvent?.(event)),
    );
  }
}

function module(
  manifest: Omit<SecurityModuleManifest, "version">,
  hooks: Pick<SecurityModule, "onEvent" | "reviewEffect"> = {},
): SecurityModule {
  return { ...hooks, manifest: { ...manifest, version: "1.0.0" } };
}

export function createSecurityModuleRegistry(config: AppConfig): SecurityModuleRegistry {
  const externalEnabled = config.httpEffectAllowlist.length > 0;
  return new SecurityModuleRegistry()
    .register(
      module(
        {
          id: "identity-delegation",
          name: "Identity & Delegation",
          kind: "identity",
          description: "Binds a Human, Agent principal and time-limited capability to every Run.",
          capabilities: ["principal-attribution", "run-capability", "scope-enforcement", "revocation"],
          status: "active",
          statusReason: "Local operator identity is derived by the trusted control plane.",
        },
        {
          reviewEffect: (effect, context) => {
            const expired = Date.parse(context.expiresAt) <= Date.now();
            const requiredScope = effect.type === "http.request"
              ? "external:http:declared"
              : "workspace:**";
            if (context.revokedAt || expired || !context.scopes.includes(requiredScope)) {
              return {
                decision: "deny",
                ruleId: "deny-missing-run-capability",
                reason: "The Run capability is revoked, expired, or missing the required scope",
              };
            }
            return null;
          },
        },
      ),
    )
    .register(
      module({
        id: "runtime-containment",
        name: "Runtime Containment",
        kind: "runtime",
        description: "Runs Codex against disposable workspace and session copies.",
        capabilities: ["staging", "container-boundary", "cleanup"],
        status: "active",
        statusReason: config.runtimeProvider + " runtime is configured.",
      }),
    )
    .register(
      module({
        id: "filesystem-effects",
        name: "Filesystem Effect Gateway",
        kind: "effect",
        description: "Measures persistent file effects and applies deterministic policy.",
        capabilities: ["diff", "policy", "atomic-commit", "rollback"],
        status: "active",
        statusReason: "All persistent workspace mutations pass through trusted commit.",
      }),
    )
    .register(
      module({
        id: "external-http",
        name: "External HTTP Gateway",
        kind: "effect",
        description: "Mediates declared HTTP actions with SSRF, DLP and approval controls.",
        capabilities: ["allowlist", "ssrf", "dlp", "idempotency", "receipt"],
        status: externalEnabled ? "active" : "disabled",
        statusReason: externalEnabled
          ? "Allowlisted hosts: " + config.httpEffectAllowlist.join(", ")
          : "No AEG_HTTP_ALLOWLIST is configured.",
      }),
    )
    .register(
      module({
        id: "approval-manager",
        name: "Digest-bound Approval",
        kind: "approval",
        description: "Binds human approval to exact effects, policy version and expiry.",
        capabilities: ["human-approval", "digest-binding", "ttl"],
        status: "active",
        statusReason: "Operational file and state-changing HTTP policies are enabled.",
      }),
    )
    .register(
      module({
        id: "trace-correlation",
        name: "Trace Correlation",
        kind: "evidence",
        description: "Correlates untrusted Runtime trace with platform-measured effects.",
        capabilities: ["trace", "diff-correlation", "mismatch-detection"],
        status: "active",
        statusReason: "Runtime trace is recorded as evidence and never used as authority.",
      }),
    )
    .register(
      module({
        id: "audit-ledger",
        name: "Tamper-evident Ledger",
        kind: "evidence",
        description: "Stores redacted security events in an HMAC-chained append-only ledger.",
        capabilities: ["event-integrity", "verification", "query"],
        status: "active",
        statusReason: "Ledger verification is enforced during startup.",
      }),
    );
}

export class SecurityEventBus {
  constructor(
    private readonly registry: SecurityModuleRegistry,
    private readonly ledger: SecurityLedger,
  ) {}

  async publish(input: SecurityEventInput): Promise<void> {
    this.registry.get(input.moduleId ?? "audit-ledger");
    await this.registry.notify(input);
    await this.ledger.append(input);
  }
}
