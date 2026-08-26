import { describe, expect, it } from "vitest";
import { computeManifestDigest, evaluateEffects } from "./effect-policy.js";
import type { FileEffect } from "./types.js";

function effect(resource: string): FileEffect {
  return {
    id: resource,
    runId: "run",
    type: "file.create",
    resource,
    beforeHash: null,
    afterHash: "after",
    size: 5,
    decision: "deny",
    ruleId: "unreviewed",
    reason: "unreviewed",
  };
}

describe("deterministic effect policy", () => {
  it("uses the most restrictive decision across a manifest", () => {
    const result = evaluateEffects([
      effect("src/index.ts"),
      effect("Dockerfile"),
      effect(".env"),
    ]);
    expect(result.decision).toBe("deny");
    expect(result.effects.map((item) => item.decision)).toEqual([
      "allow",
      "require_approval",
      "deny",
    ]);
  });

  it("binds the digest to exact paths, operations, and content hashes", () => {
    const original = [effect("Dockerfile")];
    const replacement = [{ ...effect("Dockerfile"), afterHash: "replaced" }];
    expect(computeManifestDigest(original)).not.toBe(computeManifestDigest(replacement));
  });
});
