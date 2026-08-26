import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { lstat, readFile, rm } from "node:fs/promises";
import { isIP } from "node:net";
import path from "node:path";
import { z } from "zod";
import type { AppConfig } from "./config.js";
import { effectPayload, stableStringify } from "./effect-policy.js";
import type {
  EffectDecision,
  ExternalHttpEffect,
  ExternalHttpReceipt,
  FileEffect,
} from "./types.js";

export const EXTERNAL_EFFECT_OUTBOX = ".aeg/external-effects.json";

const maximumOutboxBytes = 65_536;
const maximumRequestBodyBytes = 32_768;
const allowedHeaders = new Set(["accept", "content-type", "idempotency-key"]);
const sensitiveHeaders = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
  "x-api-key",
]);
const sensitiveNames = /(?:^|[_-])(api[_-]?key|authorization|cookie|password|secret|token)(?:$|[_-])/i;

const requestSchema = z
  .object({
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
    url: z.string().url().max(2_048),
    headers: z.record(z.string(), z.string().max(2_048)).optional(),
    body: z.unknown().optional(),
  })
  .strict();

const outboxSchema = z
  .object({
    version: z.literal(1),
    requests: z.array(requestSchema).min(1).max(1),
  })
  .strict();

type HttpRequestIntent = z.infer<typeof requestSchema>;

interface NormalizedRequest {
  method: ExternalHttpEffect["method"];
  url: string;
  headers: Record<string, string>;
  body: unknown | null;
  serializedBody: string | null;
}

export interface ExternalEffectPlan {
  effects: ExternalHttpEffect[];
  requests: NormalizedRequest[];
  decision: EffectDecision;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function externalPayload(effect: ExternalHttpEffect): Record<string, unknown> {
  return {
    type: effect.type,
    method: effect.method,
    url: effect.url,
    headerNames: effect.headerNames,
    bodyHash: effect.bodyHash,
    bodyBytes: effect.bodyBytes,
    requestDigest: effect.requestDigest,
  };
}

export function computeRunManifestDigest(
  fileEffects: FileEffect[],
  externalEffects: ExternalHttpEffect[],
): string {
  return sha256(
    stableStringify({
      files: [...fileEffects]
        .sort((left, right) => left.resource.localeCompare(right.resource))
        .map(effectPayload),
      external: [...externalEffects]
        .sort((left, right) => left.requestDigest.localeCompare(right.requestDigest))
        .map(externalPayload),
    }),
  );
}

export function combineDecision(
  fileEffects: FileEffect[],
  externalEffects: ExternalHttpEffect[],
): EffectDecision {
  const effects = [...fileEffects, ...externalEffects];
  if (effects.some((effect) => effect.decision === "deny")) return "deny";
  if (effects.some((effect) => effect.decision === "require_approval")) {
    return "require_approval";
  }
  return "allow";
}

function bodyContainsSensitiveName(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(bodyContainsSensitiveName);
  if (value === null || typeof value !== "object") return false;
  return Object.entries(value as Record<string, unknown>).some(
    ([key, child]) => sensitiveNames.test(key) || bodyContainsSensitiveName(child),
  );
}

function redactSensitiveValues(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSensitiveValues);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, child]) => [
      key,
      sensitiveNames.test(key) ? "[REDACTED]" : redactSensitiveValues(child),
    ]),
  );
}

function safeResponsePreview(bodyPreview: string, contentType: string | null): string {
  if (!bodyPreview) return "";
  if (!contentType?.toLowerCase().includes("json")) {
    return "[Non-JSON response body hidden]";
  }
  try {
    return JSON.stringify(redactSensitiveValues(JSON.parse(bodyPreview)));
  } catch {
    return "[Invalid or truncated JSON response body hidden]";
  }
}

function isPrivateAddress(address: string): boolean {
  if (address.startsWith("::ffff:")) return isPrivateAddress(address.slice(7));
  if (isIP(address) === 6) {
    const normalized = address.toLowerCase();
    return (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      /^fe[89ab]/.test(normalized)
    );
  }
  if (isIP(address) !== 4) return true;
  const octets = address.split(".").map(Number);
  const first = octets[0] ?? 0;
  const second = octets[1] ?? 0;
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19)) ||
    first >= 224
  );
}

function hostMatches(hostname: string, rule: string): boolean {
  if (rule.startsWith("*.")) {
    const suffix = rule.slice(1);
    return hostname.endsWith(suffix) && hostname !== rule.slice(2);
  }
  return hostname === rule;
}

function normalizeRequest(intent: HttpRequestIntent): NormalizedRequest {
  const headers = Object.fromEntries(
    Object.entries(intent.headers ?? {})
      .map(([name, value]) => [name.trim().toLowerCase(), value.trim()] as const)
      .sort(([left], [right]) => left.localeCompare(right)),
  );
  const body = intent.body === undefined ? null : intent.body;
  let serializedBody: string | null = null;
  if (body !== null) {
    serializedBody = stableStringify(body);
    if (Buffer.byteLength(serializedBody) > maximumRequestBodyBytes) {
      throw new Error("External HTTP request body exceeds 32 KB");
    }
  }
  return {
    method: intent.method,
    url: new URL(intent.url).toString(),
    headers,
    body,
    serializedBody,
  };
}

function requestDigest(request: NormalizedRequest): string {
  return sha256(
    stableStringify({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: request.body,
    }),
  );
}

async function readResponse(
  response: Response,
  maximumBytes: number,
): Promise<Pick<ExternalHttpReceipt, "responseBytes" | "responseHash" | "bodyPreview" | "truncated">> {
  if (!response.body) {
    return {
      responseBytes: 0,
      responseHash: sha256(""),
      bodyPreview: "",
      truncated: false,
    };
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = maximumBytes - size;
      if (remaining <= 0) {
        truncated = true;
        await reader.cancel();
        break;
      }
      const selected = value.byteLength > remaining ? value.slice(0, remaining) : value;
      chunks.push(selected);
      size += selected.byteLength;
      if (selected.byteLength !== value.byteLength) {
        truncated = true;
        await reader.cancel();
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }
  const body = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
  return {
    responseBytes: body.byteLength,
    responseHash: sha256(body),
    bodyPreview: body.subarray(0, 2_048).toString("utf8"),
    truncated: truncated || body.byteLength > 2_048,
  };
}

export class ExternalEffectGateway {
  constructor(private readonly config: AppConfig) {}

  async collect(runId: string, stagedWorkspacePath: string): Promise<ExternalEffectPlan> {
    const outboxPath = path.join(stagedWorkspacePath, ...EXTERNAL_EFFECT_OUTBOX.split("/"));
    let raw: string;
    try {
      const stats = await lstat(outboxPath);
      if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink > 1) {
        throw new Error("External effect outbox must be a regular, unlinked file");
      }
      if (stats.size > maximumOutboxBytes) {
        throw new Error("External effect outbox exceeds 64 KB");
      }
      raw = await readFile(outboxPath, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return { effects: [], requests: [], decision: "allow" };
      }
      throw error;
    }

    let parsed: z.infer<typeof outboxSchema>;
    try {
      parsed = outboxSchema.parse(JSON.parse(raw));
    } catch (error) {
      throw new Error(
        "Invalid external effect outbox: " +
          (error instanceof Error ? error.message : String(error)),
      );
    }

    const requests = parsed.requests.map(normalizeRequest);
    const effects = await Promise.all(
      requests.map((request) => this.evaluate(runId, request)),
    );
    return { effects, requests, decision: combineDecision([], effects) };
  }

  denyMixedDomains(plan: ExternalEffectPlan): ExternalEffectPlan {
    const effects = plan.effects.map((effect) => ({
      ...effect,
      decision: "deny" as const,
      ruleId: "deny-mixed-effect-domains",
      reason: "A Run may change files or invoke an external service, but cannot do both atomically",
      status: "denied" as const,
    }));
    return { ...plan, effects, decision: "deny" };
  }

  async execute(plan: ExternalEffectPlan): Promise<ExternalHttpEffect[]> {
    const results: ExternalHttpEffect[] = [];
    for (const [index, effect] of plan.effects.entries()) {
      const request = plan.requests[index];
      if (!request || requestDigest(request) !== effect.requestDigest) {
        throw new Error("External effect request changed before execution");
      }
      if (effect.decision === "deny") {
        results.push({ ...effect, status: "denied" });
        continue;
      }
      try {
        const headers = new Headers(request.headers);
        if (request.serializedBody !== null && !headers.has("content-type")) {
          headers.set("content-type", "application/json");
        }
        if (request.method !== "GET" && !headers.has("idempotency-key")) {
          headers.set("idempotency-key", "aeg-" + effect.requestDigest.slice(0, 32));
        }
        const response = await fetch(request.url, {
          method: request.method,
          headers,
          body: request.method === "GET" ? null : request.serializedBody,
          redirect: "manual",
          signal: AbortSignal.timeout(this.config.httpEffectTimeoutMs),
        });
        const evidence = await readResponse(response, this.config.httpEffectMaxResponseBytes);
        const contentType = response.headers.get("content-type");
        results.push({
          ...effect,
          status: "executed",
          receipt: {
            statusCode: response.status,
            contentType,
            ...evidence,
            bodyPreview: safeResponsePreview(evidence.bodyPreview, contentType),
            executedAt: new Date().toISOString(),
          },
          error: null,
        });
      } catch (error) {
        results.push({
          ...effect,
          status: "uncertain",
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return results;
  }

  async removeOutbox(stagedWorkspacePath: string): Promise<void> {
    const outboxPath = path.join(stagedWorkspacePath, ...EXTERNAL_EFFECT_OUTBOX.split("/"));
    await rm(outboxPath, { force: true });
    await rm(path.dirname(outboxPath)).catch(() => undefined);
  }

  private async evaluate(
    runId: string,
    request: NormalizedRequest,
  ): Promise<ExternalHttpEffect> {
    const url = new URL(request.url);
    const digest = requestDigest(request);
    let decision: EffectDecision = "allow";
    let ruleId = "allow-read-only-http";
    let reason = "Allowlisted read-only HTTP request";

    const headerNames = Object.keys(request.headers);
    const unsafeHeader = headerNames.find(
      (name) => sensitiveHeaders.has(name) || !allowedHeaders.has(name),
    );
    const sensitiveQuery = [...url.searchParams.keys()].find((name) => sensitiveNames.test(name));
    if (url.username || url.password) {
      decision = "deny";
      ruleId = "deny-url-credentials";
      reason = "Credentials embedded in URLs are prohibited";
    } else if (unsafeHeader) {
      decision = "deny";
      ruleId = "deny-untrusted-http-header";
      reason = "Agent-supplied credentials and unapproved HTTP headers are prohibited";
    } else if (sensitiveQuery || bodyContainsSensitiveName(request.body)) {
      decision = "deny";
      ruleId = "deny-sensitive-http-data";
      reason = "Potential secret-bearing query or body fields are prohibited";
    } else if (!this.config.httpEffectAllowlist.some((rule) => hostMatches(url.hostname, rule))) {
      decision = "deny";
      ruleId = "deny-host-outside-allowlist";
      reason = "Destination host is outside AEG_HTTP_ALLOWLIST";
    } else if (!(await this.isNetworkDestinationAllowed(url))) {
      decision = "deny";
      ruleId = "deny-private-network-ssrf";
      reason = "Private, local, unresolved, or non-HTTPS destinations are prohibited";
    } else if (request.method === "DELETE") {
      decision = "deny";
      ruleId = "deny-destructive-http";
      reason = "DELETE is outside the delegated external action scope";
    } else if (["POST", "PUT", "PATCH"].includes(request.method)) {
      decision = "require_approval";
      ruleId = "approve-state-changing-http";
      reason = "State-changing external requests require exact digest-bound approval";
    }

    const serializedBody = request.serializedBody;
    const effect: ExternalHttpEffect = {
      id: "",
      runId,
      type: "http.request",
      resource: request.method + " " + request.url,
      method: request.method,
      url: request.url,
      headerNames,
      bodyHash: serializedBody === null ? null : sha256(serializedBody),
      bodyBytes: serializedBody === null ? 0 : Buffer.byteLength(serializedBody),
      bodyPreview:
        serializedBody === null ? null : serializedBody.slice(0, 2_048),
      requestDigest: digest,
      decision,
      ruleId,
      reason,
      status: decision === "deny" ? "denied" : "planned",
      receipt: null,
      error: null,
    };
    effect.id = sha256(runId + ":external:" + stableStringify(externalPayload(effect))).slice(0, 32);
    return effect;
  }

  private async isNetworkDestinationAllowed(url: URL): Promise<boolean> {
    if (!["http:", "https:"].includes(url.protocol)) return false;
    if (url.protocol === "http:" && !this.config.httpEffectAllowPrivateNetworks) return false;
    if (
      url.port &&
      !this.config.httpEffectAllowPrivateNetworks &&
      !((url.protocol === "https:" && url.port === "443") ||
        (url.protocol === "http:" && url.port === "80"))
    ) {
      return false;
    }
    try {
      const addresses = isIP(url.hostname)
        ? [{ address: url.hostname }]
        : await lookup(url.hostname, { all: true, verbatim: true });
      return (
        addresses.length > 0 &&
        (this.config.httpEffectAllowPrivateNetworks ||
          addresses.every(({ address }) => !isPrivateAddress(address)))
      );
    } catch {
      return false;
    }
  }
}
