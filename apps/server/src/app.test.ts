import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";

const service = {
  listAgents: () => [],
  systemInfo: async () => ({}),
  identityInfo: () => ({ currentHuman: null, agents: [] }),
  securityOverview: async () => ({ posture: "protected" }),
  securityEvents: async () => [],
} as unknown as AgentService;

describe("HTTP boundary", () => {
  it("protects API routes with the configured shared token", async () => {
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
      service,
    );
    const denied = await app.inject({ method: "GET", url: "/api/agents" });
    expect(denied.statusCode).toBe(401);

    const allowed = await app.inject({
      method: "GET",
      url: "/api/agents",
      headers: { authorization: "Bearer a-strong-test-token" },
    });
    expect(allowed.statusCode).toBe(200);
    await app.close();
  });

  it("preserves Fastify client error status codes", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const malformed = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: "{not-json",
    });
    expect(malformed.statusCode).toBe(400);

    const oversized = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ name: "x".repeat(1_100_000) }),
    });
    expect(oversized.statusCode).toBe(413);
    await app.close();
  });

  it("exposes the operator security projection through validated queries", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const overview = await app.inject({ method: "GET", url: "/api/security/overview" });
    expect(overview.statusCode).toBe(200);
    expect(overview.json()).toMatchObject({ posture: "protected" });

    const events = await app.inject({
      method: "GET",
      url: "/api/security/events?limit=20&moduleId=filesystem-effects",
    });
    expect(events.statusCode).toBe(200);
    expect(events.json()).toEqual({ events: [] });

    const invalid = await app.inject({
      method: "GET",
      url: "/api/security/events?limit=2000",
    });
    expect(invalid.statusCode).toBe(400);
    await app.close();
  });
});
