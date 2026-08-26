import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import {
  EXTERNAL_EFFECT_OUTBOX,
  ExternalEffectGateway,
} from "./external-effect-gateway.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function workspaceWithOutbox(request: Record<string, unknown>): Promise<string> {
  const workspace = await mkdtemp(path.join(tmpdir(), "external-effect-test-"));
  temporaryDirectories.push(workspace);
  const outbox = path.join(workspace, ...EXTERNAL_EFFECT_OUTBOX.split("/"));
  await mkdir(path.dirname(outbox), { recursive: true });
  await writeFile(
    outbox,
    JSON.stringify({ version: 1, requests: [request] }),
    "utf8",
  );
  return workspace;
}

describe("ExternalEffectGateway", () => {
  it("holds a state-changing request for approval and records execution evidence", async () => {
    let calls = 0;
    let idempotencyKey = "";
    const server = createServer((request, response) => {
      calls += 1;
      idempotencyKey = String(request.headers["idempotency-key"] ?? "");
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ created: true, token: "must-not-persist" }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    try {
      const config = loadConfig({
        NODE_ENV: "test",
        AEG_HTTP_ALLOWLIST: "127.0.0.1",
        AEG_HTTP_ALLOW_PRIVATE_NETWORKS: "true",
      });
      const workspace = await workspaceWithOutbox({
        method: "POST",
        url: `http://127.0.0.1:${port}/tickets`,
        headers: { "content-type": "application/json" },
        body: { title: "review me" },
      });
      const gateway = new ExternalEffectGateway(config);
      const plan = await gateway.collect("run-1", workspace);
      expect(plan.decision).toBe("require_approval");
      expect(calls).toBe(0);
      expect(gateway.denyMixedDomains(plan).effects[0]).toMatchObject({
        decision: "deny",
        ruleId: "deny-mixed-effect-domains",
      });

      const [result] = await gateway.execute(plan);
      expect(calls).toBe(1);
      expect(idempotencyKey).toBe("aeg-" + plan.effects[0]!.requestDigest.slice(0, 32));
      expect(result).toMatchObject({
        status: "executed",
        receipt: { statusCode: 200 },
      });
      expect(result?.receipt?.responseHash).toHaveLength(64);
      expect(result?.receipt?.bodyPreview).toContain("[REDACTED]");
      expect(result?.receipt?.bodyPreview).not.toContain("must-not-persist");
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });

  it("denies agent-supplied credentials before making a request", async () => {
    const config = loadConfig({
      NODE_ENV: "test",
      AEG_HTTP_ALLOWLIST: "example.com",
    });
    const workspace = await workspaceWithOutbox({
      method: "POST",
      url: "https://example.com/tickets",
      headers: { authorization: "Bearer secret" },
      body: { title: "blocked" },
    });
    const plan = await new ExternalEffectGateway(config).collect("run-2", workspace);
    expect(plan.decision).toBe("deny");
    expect(plan.effects[0]).toMatchObject({
      ruleId: "deny-untrusted-http-header",
      status: "denied",
    });
  });

  it("denies a destination outside the configured host allowlist", async () => {
    const config = loadConfig({
      NODE_ENV: "test",
      AEG_HTTP_ALLOWLIST: "api.example.com",
    });
    const workspace = await workspaceWithOutbox({
      method: "GET",
      url: "https://untrusted.example/status",
    });
    const plan = await new ExternalEffectGateway(config).collect("run-3", workspace);
    expect(plan.effects[0]?.ruleId).toBe("deny-host-outside-allowlist");
  });
});
