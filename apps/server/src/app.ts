import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import Fastify, { type FastifyInstance } from "fastify";
import { timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { AppConfig } from "./config.js";
import { HttpError } from "./errors.js";
import type { AgentService } from "./agent-service.js";
import type { PolicyProfile } from "./types.js";

const agentIdParams = z.object({ id: z.string().uuid() });
const runIdParams = z.object({ id: z.string().uuid() });
const approvalIdParams = z.object({ approvalId: z.string().uuid() });
const moduleIdParams = z.object({ moduleId: z.string().trim().min(1).max(80) });
const approvalQuery = z.object({
  status: z.enum(["pending", "approved", "denied", "expired"]).optional(),
});
const createAgentBody = z.object({
  name: z.string().trim().min(1).max(80),
  description: z.string().max(500).optional(),
  instructions: z.string().max(10_000).optional(),
});
const updateAgentBody = createAgentBody.partial().refine(
  (value) => Object.keys(value).length > 0,
  "At least one field is required",
);
const messageBody = z.object({
  content: z.string().trim().min(1).max(50_000),
});
const securityEventQuery = z.object({
  afterSequence: z.coerce.number().int().nonnegative().optional(),
  agentId: z.string().uuid().optional(),
  runId: z.string().uuid().optional(),
  moduleId: z.string().trim().min(1).max(80).optional(),
  decision: z.string().trim().min(1).max(40).optional(),
  limit: z.coerce.number().int().min(1).max(1_000).optional(),
});
const policyProfileBody = z.object({
  version: z.number().int().positive(),
  template: z.enum(["relaxed", "balanced", "strict", "custom"]),
  fileRules: z.object({
    autoAllow: z.array(z.string().trim().min(1).max(240)).max(100),
    requireApproval: z.array(z.string().trim().min(1).max(240)).max(100),
    deny: z.array(z.string().trim().min(1).max(240)).max(100),
  }),
  external: z.object({
    allowHosts: z.array(z.string().trim().min(1).max(253)).max(100),
    requireApprovalMethods: z.array(z.enum(["POST", "PUT", "PATCH"])),
  }),
  egress: z.object({ allow: z.array(z.string().trim().min(1).max(500)).max(100) }),
  approval: z.object({ ttlMinutes: z.number().min(1).max(60) }),
  analyzers: z.object({
    "guardrail-model": z.object({
      enabled: z.boolean(),
      denyThreshold: z.number().min(0).max(1),
      reviewThreshold: z.number().min(0).max(1),
    }),
    "secret-scanner": z.object({
      enabled: z.boolean(),
      action: z.enum(["deny", "require_approval"]),
    }),
  }),
  updatedAt: z.string(),
});
const policyTemplateBody = z.object({ template: z.enum(["relaxed", "balanced", "strict"]) });
const policySimulationBody = z.object({
  kind: z.enum(["file", "http"]),
  resource: z.string().trim().min(1).max(4_000),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).optional(),
  profile: z.unknown().optional(),
});
const moduleConfigurationBody = z.object({
  enabled: z.boolean().optional(),
  config: z.record(z.string(), z.unknown()).optional(),
}).refine((value) => value.enabled !== undefined || value.config !== undefined, "No module change supplied");

export async function createApp(
  config: AppConfig,
  service: AgentService,
): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      redact: ["req.headers.authorization", "req.headers.cookie"],
    },
    bodyLimit: 1_048_576,
  });

  await app.register(cors, {
    origin:
      config.nodeEnv === "development"
        ? ["http://localhost:5173", "http://127.0.0.1:5173"]
        : false,
  });

  app.addHook("onRequest", async (request, reply) => {
    if (
      !config.authToken ||
      !request.url.startsWith("/api/") ||
      request.url === "/api/health" ||
      request.url === "/api/auth"
    ) {
      return;
    }
    const header = request.headers.authorization ?? "";
    const candidate = header.startsWith("Bearer ") ? header.slice(7) : "";
    const expectedBuffer = Buffer.from(config.authToken);
    const candidateBuffer = Buffer.from(candidate);
    const valid =
      candidateBuffer.length === expectedBuffer.length &&
      timingSafeEqual(candidateBuffer, expectedBuffer);
    if (!valid) {
      return reply.code(401).send({ error: "Authentication required" });
    }
  });

  app.get("/api/health", async () => ({
    ok: true,
    service: "volc-agent-launchpad",
  }));

  app.get("/api/auth", async () => ({ required: config.authToken.length > 0 }));

  app.get("/api/system", async () => service.systemInfo());

  app.get("/api/agents", async () => ({ agents: service.listAgents() }));

  app.post("/api/agents", async (request, reply) => {
    const body = createAgentBody.parse(request.body);
    const agent = await service.createAgent(body);
    return reply.code(201).send({ agent });
  });

  app.get("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: service.getAgent(id) };
  });

  app.patch("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    const body = updateAgentBody.parse(request.body);
    return { agent: await service.updateAgent(id, body) };
  });

  app.delete("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return service.deleteAgent(id);
  });

  app.post("/api/agents/:id/start", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: await service.startAgent(id) };
  });

  app.post("/api/agents/:id/stop", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: await service.stopAgent(id) };
  });

  app.get("/api/agents/:id/messages", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { messages: service.getMessages(id) };
  });

  app.get("/api/agents/:id/runs", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { runs: service.getRuns(id) };
  });

  app.get("/api/agents/:id/policy", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return service.policyProfile(id);
  });

  app.put("/api/agents/:id/policy", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    const body = policyProfileBody.parse(request.body) as PolicyProfile;
    return service.updatePolicyProfile(id, body);
  });

  app.post("/api/agents/:id/policy/template", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    const { template } = policyTemplateBody.parse(request.body);
    return service.applyPolicyTemplate(id, template);
  });

  app.post("/api/agents/:id/policy/simulate", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    const body = policySimulationBody.parse(request.body);
    const profile = body.profile === undefined
      ? undefined
      : policyProfileBody.parse(body.profile) as PolicyProfile;
    const input = body.kind === "file"
      ? { kind: "file" as const, resource: body.resource }
      : { kind: "http" as const, resource: body.resource, method: body.method ?? "GET" };
    return { result: await service.simulateAgentPolicy(id, input, profile) };
  });

  app.post("/api/agents/:id/messages", async (request, reply) => {
    const { id } = agentIdParams.parse(request.params);
    const body = messageBody.parse(request.body);
    const result = await service.sendMessage(id, body.content);
    return reply.code(202).send(result);
  });

  app.get("/api/runs/:id", async (request) => {
    const { id } = runIdParams.parse(request.params);
    return { run: service.getRun(id) };
  });

  app.get("/api/approvals", async (request) => {
    const { status } = approvalQuery.parse(request.query);
    return { approvals: service.getApprovals(status) };
  });

  app.get("/api/approvals/:approvalId", async (request) => {
    const { approvalId } = approvalIdParams.parse(request.params);
    return service.getApprovalDetails(approvalId);
  });

  app.post("/api/approvals/:approvalId/approve", async (request) => {
    const { approvalId } = approvalIdParams.parse(request.params);
    return service.approveApproval(approvalId);
  });

  app.post("/api/approvals/:approvalId/deny", async (request) => {
    const { approvalId } = approvalIdParams.parse(request.params);
    return service.denyApproval(approvalId);
  });

  app.get("/api/ledger/verify", async () => service.verifyLedger());

  app.get("/api/identity", async () => service.identityInfo());

  app.get("/api/security/overview", async () => service.securityOverview());

  app.get("/api/security/modules", async () => ({ modules: await service.securityModules() }));

  app.patch("/api/security/modules/:moduleId", async (request) => {
    const { moduleId } = moduleIdParams.parse(request.params);
    const body = moduleConfigurationBody.parse(request.body);
    return service.configureSecurityModule(moduleId, {
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      ...(body.config !== undefined ? { config: body.config } : {}),
    });
  });

  app.get("/api/security/events", async (request) => {
    const query = securityEventQuery.parse(request.query);
    return { events: await service.securityEvents(query) };
  });

  if (config.nodeEnv === "production") {
    const webRoot = fileURLToPath(new URL("../../web/dist", import.meta.url));
    await app.register(fastifyStatic, {
      root: webRoot,
      prefix: "/",
    });
    app.setNotFoundHandler((request, reply) => {
      if (request.url.startsWith("/api/")) {
        return reply.code(404).send({ error: "API route not found" });
      }
      return reply.sendFile("index.html");
    });
  }

  app.setErrorHandler((error, request, reply) => {
    const appError = error instanceof Error ? error : new Error(String(error));
    const validationError = error instanceof z.ZodError;
    const frameworkStatus =
      typeof (error as { statusCode?: unknown }).statusCode === "number"
        ? (error as { statusCode: number }).statusCode
        : null;
    const statusCode =
      error instanceof HttpError
        ? error.statusCode
        : validationError
          ? 400
          : frameworkStatus && frameworkStatus >= 400 && frameworkStatus <= 599
            ? frameworkStatus
            : 500;
    if (statusCode >= 500) {
      request.log.error(appError);
    }
    return reply.code(statusCode).send({
      error: appError.message,
      ...(validationError ? { details: error.issues } : {}),
    });
  });

  return app;
}
