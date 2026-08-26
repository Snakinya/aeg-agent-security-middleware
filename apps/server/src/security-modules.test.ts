import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "./config.js";
import {
  createSecurityModuleRegistry,
  SecurityEventBus,
  SecurityModuleRegistry,
} from "./security-modules.js";
import type { SecurityLedger } from "./security-ledger.js";
import type { FileEffect, RunSecurityContext } from "./types.js";

describe("pluggable security module registry", () => {
  it("registers built-in modules and reflects external gateway configuration", () => {
    const disabled = createSecurityModuleRegistry(loadConfig({ NODE_ENV: "test" }));
    expect(disabled.get("external-http").manifest.status).toBe("disabled");

    const enabled = createSecurityModuleRegistry(
      loadConfig({ NODE_ENV: "test", AEG_HTTP_ALLOWLIST: "api.example.com" }),
    );
    expect(enabled.get("external-http").manifest.status).toBe("active");
    expect(enabled.list().map((module) => module.id)).toContain("identity-delegation");
  });

  it("enforces the Run capability scope through the identity module", async () => {
    const registry = createSecurityModuleRegistry(loadConfig({ NODE_ENV: "test" }));
    const context: RunSecurityContext = {
      id: "context",
      runId: "run",
      humanId: "human",
      agentId: "agent",
      agentPrincipalId: "agent:agent",
      scopes: [],
      policyProfile: "test",
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 10_000).toISOString(),
      revokedAt: null,
    };
    const effect: FileEffect = {
      id: "effect",
      runId: "run",
      type: "file.create",
      resource: "src/index.ts",
      beforeHash: null,
      afterHash: "hash",
      size: 10,
      decision: "allow",
      ruleId: "allow-workspace-change",
      reason: "allowed",
    };
    expect(await registry.reviewEffect(effect, context)).toMatchObject({
      decision: "deny",
      ruleId: "deny-missing-run-capability",
    });
  });

  it("rejects duplicate modules and fans events out before persistence", async () => {
    const observer = vi.fn();
    const registry = new SecurityModuleRegistry().register({
      manifest: {
        id: "test-module",
        name: "Test module",
        version: "1.0.0",
        kind: "effect",
        description: "Test extension",
        capabilities: ["test"],
        status: "active",
        statusReason: "test",
      },
      onEvent: observer,
    });
    expect(() => registry.register(registry.get("test-module"))).toThrow(/already registered/);

    const append = vi.fn(async () => ({}));
    const bus = new SecurityEventBus(registry, { append } as unknown as SecurityLedger);
    await bus.publish({ type: "test.observed", moduleId: "test-module" });
    expect(observer).toHaveBeenCalledOnce();
    expect(append).toHaveBeenCalledOnce();
  });

  it("lets a plug-in tighten an Effect decision without relaxing built-in policy", async () => {
    const registry = new SecurityModuleRegistry().register({
      manifest: {
        id: "custom-policy",
        name: "Custom policy",
        version: "2.1.0",
        kind: "effect",
        description: "Protect release files",
        capabilities: ["policy"],
        status: "active",
        statusReason: "test",
      },
      reviewEffect: (effect) =>
        effect.resource.startsWith("release/")
          ? {
              decision: "deny",
              ruleId: "deny-release-path",
              reason: "Release paths are owned by the deployment service",
            }
          : { decision: "allow", ruleId: "cannot-relax", reason: "ignored" },
    });
    const context = {
      id: "context",
      runId: "run",
      humanId: "human",
      agentId: "agent",
      agentPrincipalId: "agent:agent",
      scopes: ["workspace:**"],
      policyProfile: "test",
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 10_000).toISOString(),
      revokedAt: null,
    } satisfies RunSecurityContext;
    const base = {
      id: "effect",
      runId: "run",
      type: "file.create",
      resource: "release/manifest.json",
      beforeHash: null,
      afterHash: "hash",
      size: 10,
      decision: "allow",
      ruleId: "allow-workspace-change",
      reason: "allowed",
    } satisfies FileEffect;
    expect(await registry.reviewEffect(base, context)).toMatchObject({
      decision: "deny",
      ruleId: "deny-release-path",
    });
    expect(registry.policyVersion()).toContain("custom-policy@2.1.0");
  });
});
