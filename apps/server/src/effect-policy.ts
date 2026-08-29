import { createHash } from "node:crypto";
import type { EffectDecision, FileEffect } from "./types.js";
import type { PolicyProfile } from "./types.js";
import { decideFileResource, defaultPolicyProfile } from "./policy-profile.js";

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

export function decideEffect(
  effect: FileEffect,
  profile: PolicyProfile = defaultPolicyProfile(),
): Pick<FileEffect, "decision" | "ruleId" | "reason"> {
  const result = decideFileResource(effect.resource, profile);
  return { decision: result.decision, ruleId: result.ruleId, reason: result.reason };
}

export function evaluateEffects(effects: FileEffect[], profile: PolicyProfile = defaultPolicyProfile()): {
  effects: FileEffect[];
  decision: EffectDecision;
  manifestDigest: string;
} {
  const evaluated = effects.map((effect) => ({ ...effect, ...decideEffect(effect, profile) }));
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
