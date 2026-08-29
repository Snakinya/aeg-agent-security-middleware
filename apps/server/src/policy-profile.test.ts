import { describe, expect, it } from "vitest";
import {
  decideFileResource,
  normalizePolicyProfile,
  policyTemplate,
  simulatePolicy,
} from "./policy-profile.js";

describe("versioned Agent policy profiles", () => {
  it("keeps kernel hard-deny above a relaxed profile", () => {
    const profile = policyTemplate("relaxed");
    expect(decideFileResource(".env", profile)).toMatchObject({
      decision: "deny",
      moduleId: "filesystem-effects",
      locked: true,
    });
    expect(decideFileResource("nested/.git/config", profile).decision).toBe("deny");
  });

  it("applies strictest profile group before allow rules", () => {
    const profile = policyTemplate("balanced");
    profile.fileRules.autoAllow.push("infra/**");
    profile.fileRules.deny.push("infra/**");
    expect(decideFileResource("infra/main.tf", profile)).toMatchObject({
      decision: "deny",
      ruleId: "profile-deny",
      matchedRule: "infra/**",
    });
  });

  it("normalizes TTL, duplicates and model thresholds", () => {
    const profile = policyTemplate("balanced");
    profile.fileRules.autoAllow = ["src/**", "src/**", "  docs/**  "];
    profile.approval.ttlMinutes = 200;
    profile.analyzers["guardrail-model"].reviewThreshold = 0.8;
    profile.analyzers["guardrail-model"].denyThreshold = 0.3;
    const normalized = normalizePolicyProfile(profile, 7);
    expect(normalized.version).toBe(7);
    expect(normalized.fileRules.autoAllow).toEqual(["src/**", "docs/**"]);
    expect(normalized.approval.ttlMinutes).toBe(60);
    expect(normalized.analyzers["guardrail-model"].denyThreshold).toBe(0.8);
  });

  it("simulates digest-bound HTTP review", () => {
    const profile = policyTemplate("balanced", ["api.github.com"]);
    expect(simulatePolicy(profile, {
      kind: "http",
      resource: "https://api.github.com/repos/owner/repo",
      method: "POST",
    })).toMatchObject({ decision: "require_approval", matchedRule: "POST" });
  });

  it("denies invalid and non-allowlisted HTTP destinations", () => {
    const profile = policyTemplate("balanced", ["api.github.com"]);
    expect(simulatePolicy(profile, { kind: "http", resource: "not-a-url", method: "GET" }).locked).toBe(true);
    expect(simulatePolicy(profile, { kind: "http", resource: "https://evil.example", method: "GET" }).decision).toBe("deny");
  });
});
