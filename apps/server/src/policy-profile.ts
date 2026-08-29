import type {
  EffectDecision,
  PolicyProfile,
  PolicyTemplate,
} from "./types.js";

export const HARD_DENY_RULES = [
  ".env",
  ".env.* (except examples)",
  ".git/**",
  ".launchpad/**",
  "AGENTS.md",
] as const;

const now = () => new Date().toISOString();

const unique = (values: string[]) => [...new Set(values.map((value) => value.trim()).filter(Boolean))];

const base = (allowHosts: string[]): Omit<PolicyProfile, "version" | "template" | "updatedAt"> => ({
  fileRules: {
    autoAllow: ["src/**", "tests/**", "*.md"],
    requireApproval: [".github/workflows/**", "infra/**", "Dockerfile", "docker-compose*.yml", "docker-compose*.yaml"],
    deny: [],
  },
  external: {
    allowHosts: unique(allowHosts),
    requireApprovalMethods: ["POST", "PUT", "PATCH"],
  },
  egress: {
    allow: ["domain=ark.cn-beijing.volces.com"],
  },
  approval: { ttlMinutes: 15 },
  analyzers: {
    "guardrail-model": {
      enabled: false,
      denyThreshold: 0.9,
      reviewThreshold: 0.6,
    },
    "secret-scanner": {
      enabled: true,
      action: "deny",
    },
  },
});

export function policyTemplate(
  template: Exclude<PolicyTemplate, "custom">,
  allowHosts: string[] = [],
): PolicyProfile {
  const profile = base(allowHosts);
  if (template === "relaxed") {
    profile.fileRules.autoAllow = ["**"];
    profile.fileRules.requireApproval = [".github/workflows/**", "infra/**"];
    profile.analyzers["secret-scanner"].action = "require_approval";
  }
  if (template === "strict") {
    profile.fileRules.autoAllow = ["src/**", "tests/**", "docs/**", "*.md"];
    profile.fileRules.requireApproval = ["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"];
    profile.fileRules.deny = ["secrets/**", ".github/workflows/**", "infra/**", "Dockerfile", "docker-compose*.yml", "docker-compose*.yaml"];
    profile.analyzers["guardrail-model"].enabled = true;
    profile.analyzers["guardrail-model"].denyThreshold = 0.82;
    profile.analyzers["guardrail-model"].reviewThreshold = 0.48;
  }
  return {
    ...profile,
    version: 1,
    template,
    updatedAt: now(),
  };
}

export function defaultPolicyProfile(allowHosts: string[] = []): PolicyProfile {
  return policyTemplate("balanced", allowHosts);
}

export function normalizePolicyProfile(
  profile: PolicyProfile,
  nextVersion = profile.version,
): PolicyProfile {
  const thresholds = profile.analyzers["guardrail-model"];
  const ttlMinutes = Math.max(1, Math.min(60, Math.round(profile.approval.ttlMinutes)));
  const reviewThreshold = Math.max(0, Math.min(1, thresholds.reviewThreshold));
  const denyThreshold = Math.max(reviewThreshold, Math.min(1, thresholds.denyThreshold));
  return {
    version: Math.max(1, Math.round(nextVersion)),
    template: profile.template,
    fileRules: {
      autoAllow: unique(profile.fileRules.autoAllow).slice(0, 100),
      requireApproval: unique(profile.fileRules.requireApproval).slice(0, 100),
      deny: unique(profile.fileRules.deny).slice(0, 100),
    },
    external: {
      allowHosts: unique(profile.external.allowHosts.map((host) => host.toLowerCase())).slice(0, 100),
      requireApprovalMethods: [...new Set(profile.external.requireApprovalMethods)].filter(
        (method): method is "POST" | "PUT" | "PATCH" => ["POST", "PUT", "PATCH"].includes(method),
      ),
    },
    egress: { allow: unique(profile.egress.allow).slice(0, 100) },
    approval: { ttlMinutes },
    analyzers: {
      "guardrail-model": {
        enabled: Boolean(thresholds.enabled),
        denyThreshold,
        reviewThreshold,
      },
      "secret-scanner": {
        enabled: Boolean(profile.analyzers["secret-scanner"].enabled),
        action: profile.analyzers["secret-scanner"].action === "require_approval"
          ? "require_approval"
          : "deny",
      },
    },
    updatedAt: now(),
  };
}

function globExpression(glob: string): RegExp {
  let expression = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*") {
      if (glob[index + 1] === "*") {
        expression += ".*";
        index += 1;
      } else {
        expression += "[^/]*";
      }
    } else if (character === "?") {
      expression += "[^/]";
    } else {
      expression += character?.replace(/[|\\{}()[\]^$+?.]/g, "\\$&") ?? "";
    }
  }
  return new RegExp(expression + "$");
}

export function matchesGlob(resource: string, pattern: string): boolean {
  return globExpression(pattern).test(resource);
}

export function isKernelHardDenied(resource: string): boolean {
  const segments = resource.split("/");
  const basename = segments.at(-1) ?? resource;
  const protectedEnvironmentFile =
    basename === ".env" ||
    (basename.startsWith(".env.") &&
      ![".env.example", ".env.sample", ".env.template"].includes(basename));
  return (
    segments.includes(".git") ||
    resource.startsWith(".launchpad/") ||
    basename === "AGENTS.md" ||
    protectedEnvironmentFile
  );
}

export interface PolicySimulation {
  decision: EffectDecision;
  moduleId: string;
  ruleId: string;
  reason: string;
  matchedRule: string | null;
  locked: boolean;
}

export function decideFileResource(resource: string, profile: PolicyProfile): PolicySimulation {
  if (isKernelHardDenied(resource)) {
    return {
      decision: "deny",
      moduleId: "filesystem-effects",
      ruleId: "hard-deny-platform-and-secrets",
      reason: "Kernel-protected platform metadata and environment secrets cannot be overridden",
      matchedRule: HARD_DENY_RULES.find((rule) => matchesGlob(resource, rule.replace(" (except examples)", ""))) ?? resource,
      locked: true,
    };
  }
  const groups: Array<[EffectDecision, string, string[]]> = [
    ["deny", "profile-deny", profile.fileRules.deny],
    ["require_approval", "profile-require-approval", profile.fileRules.requireApproval],
    ["allow", "profile-auto-allow", profile.fileRules.autoAllow],
  ];
  for (const [decision, ruleId, patterns] of groups) {
    const matchedRule = patterns.find((pattern) => matchesGlob(resource, pattern));
    if (matchedRule) {
      return {
        decision,
        moduleId: "policy-profile",
        ruleId,
        reason: `Policy profile v${profile.version} matched ${matchedRule}`,
        matchedRule,
        locked: false,
      };
    }
  }
  return {
    decision: "allow",
    moduleId: "policy-profile",
    ruleId: "profile-default-allow",
    reason: "No stricter profile rule matched the workspace resource",
    matchedRule: null,
    locked: false,
  };
}

function hostMatches(hostname: string, rule: string): boolean {
  return rule.startsWith("*.")
    ? hostname.endsWith(rule.slice(1)) && hostname !== rule.slice(2)
    : hostname === rule;
}

export function simulatePolicy(
  profile: PolicyProfile,
  input: { kind: "file"; resource: string } | { kind: "http"; resource: string; method: string },
): PolicySimulation {
  if (input.kind === "file") return decideFileResource(input.resource, profile);
  let url: URL;
  try {
    url = new URL(input.resource);
  } catch {
    return { decision: "deny", moduleId: "external-http", ruleId: "deny-invalid-url", reason: "URL is invalid", matchedRule: null, locked: true };
  }
  const method = input.method.toUpperCase();
  if (method === "DELETE") {
    return { decision: "deny", moduleId: "external-http", ruleId: "deny-destructive-http", reason: "DELETE is outside the delegated action scope", matchedRule: "DELETE", locked: true };
  }
  const matchedHost = profile.external.allowHosts.find((rule) => hostMatches(url.hostname.toLowerCase(), rule));
  if (!matchedHost) {
    return { decision: "deny", moduleId: "policy-profile", ruleId: "profile-deny-host", reason: "Destination is outside the Agent policy profile", matchedRule: null, locked: false };
  }
  if (profile.external.requireApprovalMethods.includes(method as "POST" | "PUT" | "PATCH")) {
    return { decision: "require_approval", moduleId: "policy-profile", ruleId: "profile-review-http-method", reason: `${method} requires a digest-bound approval`, matchedRule: method, locked: false };
  }
  return { decision: "allow", moduleId: "policy-profile", ruleId: "profile-allow-http", reason: "Host and method are allowed by the Agent policy profile", matchedRule: matchedHost, locked: false };
}
