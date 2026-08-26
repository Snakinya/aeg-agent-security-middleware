import { createHash } from "node:crypto";
import type { EffectDecision, FileEffect } from "./types.js";

export const POLICY_VERSION = "builtin-v2";

export function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return (
      "{" +
      Object.keys(record)
        .sort()
        .map((key) => JSON.stringify(key) + ":" + stableStringify(record[key]))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function effectPayload(effect: FileEffect): Record<string, unknown> {
  return {
    type: effect.type,
    resource: effect.resource,
    beforeHash: effect.beforeHash,
    afterHash: effect.afterHash,
    size: effect.size,
  };
}

export function computeManifestDigest(effects: FileEffect[]): string {
  return sha256(
    stableStringify(
      [...effects]
        .sort((left, right) => left.resource.localeCompare(right.resource))
        .map(effectPayload),
    ),
  );
}

function isHardDenied(resource: string): boolean {
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

function requiresApproval(resource: string): boolean {
  const basename = resource.split("/").at(-1) ?? resource;
  return (
    resource.startsWith(".github/workflows/") ||
    resource.startsWith("infra/") ||
    basename === "Dockerfile" ||
    /^docker-compose(?:\..+)?\.ya?ml$/i.test(basename)
  );
}

export function decideEffect(effect: FileEffect): Pick<FileEffect, "decision" | "ruleId" | "reason"> {
  if (isHardDenied(effect.resource)) {
    return {
      decision: "deny",
      ruleId: "hard-deny-platform-and-secrets",
      reason: "Platform metadata, policy, VCS internals, and environment secrets are protected",
    };
  }
  if (requiresApproval(effect.resource)) {
    return {
      decision: "require_approval",
      ruleId: "approve-operational-files",
      reason: "Operational and deployment files require an exact, digest-bound approval",
    };
  }
  return {
    decision: "allow",
    ruleId: "allow-workspace-change",
    reason: "Change is inside the delegated workspace scope",
  };
}

export function evaluateEffects(effects: FileEffect[]): {
  effects: FileEffect[];
  decision: EffectDecision;
  manifestDigest: string;
} {
  const evaluated = effects.map((effect) => ({ ...effect, ...decideEffect(effect) }));
  const decision = evaluated.some((effect) => effect.decision === "deny")
    ? "deny"
    : evaluated.some((effect) => effect.decision === "require_approval")
      ? "require_approval"
      : "allow";
  return {
    effects: evaluated,
    decision,
    manifestDigest: computeManifestDigest(evaluated),
  };
}

export function createEffectId(runId: string, effect: FileEffect): string {
  return sha256(runId + ":" + stableStringify(effectPayload(effect))).slice(0, 32);
}
