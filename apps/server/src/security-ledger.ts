import { createHmac, randomBytes } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { AppConfig } from "./config.js";
import { stableStringify } from "./effect-policy.js";

export interface SecurityEventInput {
  type: string;
  moduleId?: string;
  stage?:
    | "identity"
    | "runtime"
    | "observe"
    | "policy"
    | "approval"
    | "execute"
    | "recover"
    | "verify";
  severity?: "info" | "low" | "medium" | "high" | "critical";
  humanId?: string | null;
  agentPrincipalId?: string | null;
  agentId?: string | null;
  runId?: string | null;
  effectId?: string | null;
  decision?: string | null;
  ruleId?: string | null;
  reason?: string | null;
  payload?: Record<string, unknown>;
}

export interface SecurityEvent extends SecurityEventInput {
  sequence: number;
  createdAt: string;
  previousMac: string;
  eventMac: string;
}

export interface LedgerVerification {
  valid: boolean;
  events: number;
  brokenAt: number | null;
  head: string;
}

export interface SecurityEventQuery {
  afterSequence?: number | undefined;
  agentId?: string | undefined;
  runId?: string | undefined;
  moduleId?: string | undefined;
  decision?: string | undefined;
  limit?: number | undefined;
}

function eventDefaults(input: SecurityEventInput): SecurityEventInput {
  const type = input.type;
  const moduleId =
    input.moduleId ??
    (type.startsWith("identity.")
      ? "identity-delegation"
      : type.startsWith("approval.")
        ? "approval-manager"
        : type.startsWith("external_effect.") || type.includes("external_outcome")
          ? "external-http"
          : type.startsWith("trace.") || type.startsWith("runtime.")
            ? "trace-correlation"
            : type.startsWith("effect.") || type === "run.committed" || type === "run.rolled_back"
              ? "filesystem-effects"
              : type === "run.staged" || type.startsWith("service.") || type === "run.failed"
                ? "runtime-containment"
                : "audit-ledger");
  const stage =
    input.stage ??
    (type.startsWith("identity.")
      ? "identity"
      : type === "run.staged" || type.startsWith("runtime.")
        ? "runtime"
        : type.endsWith("reviewed")
          ? "policy"
          : type.startsWith("approval.")
            ? "approval"
            : type.includes("executed")
              ? "execute"
              : type.includes("rolled_back") || type.includes("failed") || type.includes("uncertain")
                ? "recover"
                : "verify");
  const severity =
    input.severity ??
    (input.decision === "deny" || type === "trace.mismatch"
      ? "high"
      : input.decision === "require_approval" || input.decision === "expired"
        ? "medium"
        : input.decision === "uncertain"
          ? "critical"
          : "info");
  return { ...input, moduleId, stage, severity };
}

export class SecurityLedger {
  private readonly directory: string;
  private readonly ledgerPath: string;
  private readonly keyPath: string;
  private key: Uint8Array = new Uint8Array();
  private head = "GENESIS";
  private sequence = 0;
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly config: AppConfig) {
    this.directory = path.join(config.dataDirectory, "security", "ledger");
    this.ledgerPath = path.join(this.directory, "events.jsonl");
    this.keyPath = path.join(this.directory, "audit.key");
  }

  async initialize(): Promise<void> {
    await mkdir(this.directory, { recursive: true });
    this.key = await this.loadKey();
    const verification = await this.verify();
    if (!verification.valid) {
      throw new Error("Security ledger integrity check failed at event " + verification.brokenAt);
    }
    this.sequence = verification.events;
    this.head = verification.head;
  }

  async append(input: SecurityEventInput): Promise<SecurityEvent> {
    let result!: SecurityEvent;
    const operation = this.queue.then(async () => {
      const eventWithoutMac = {
        ...eventDefaults(input),
        sequence: this.sequence + 1,
        createdAt: new Date().toISOString(),
        previousMac: this.head,
      };
      const eventMac = this.mac(eventWithoutMac);
      result = { ...eventWithoutMac, eventMac };
      await appendFile(this.ledgerPath, JSON.stringify(result) + "\n", {
        encoding: "utf8",
        mode: 0o600,
      });
      this.sequence = result.sequence;
      this.head = eventMac;
    });
    this.queue = operation.catch(() => undefined);
    await operation;
    return result;
  }

  async verify(): Promise<LedgerVerification> {
    await this.queue;
    let raw = "";
    try {
      raw = await readFile(this.ledgerPath, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return { valid: true, events: 0, brokenAt: null, head: "GENESIS" };
      }
      throw error;
    }
    let previousMac = "GENESIS";
    let events = 0;
    for (const line of raw.split(/\r?\n/).filter(Boolean)) {
      events += 1;
      let event: SecurityEvent;
      try {
        event = JSON.parse(line) as SecurityEvent;
      } catch {
        return { valid: false, events, brokenAt: events, head: previousMac };
      }
      const { eventMac, ...eventWithoutMac } = event;
      if (
        event.sequence !== events ||
        event.previousMac !== previousMac ||
        eventMac !== this.mac(eventWithoutMac)
      ) {
        return { valid: false, events, brokenAt: events, head: previousMac };
      }
      previousMac = eventMac;
    }
    return { valid: true, events, brokenAt: null, head: previousMac };
  }

  async list(query: SecurityEventQuery = {}): Promise<SecurityEvent[]> {
    await this.queue;
    let raw = "";
    try {
      raw = await readFile(this.ledgerPath, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    const limit = Math.min(Math.max(query.limit ?? 200, 1), 1_000);
    return raw
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => {
        const event = JSON.parse(line) as SecurityEvent;
        return { ...event, ...eventDefaults(event) } as SecurityEvent;
      })
      .filter((event) => query.afterSequence === undefined || event.sequence > query.afterSequence)
      .filter((event) => !query.agentId || event.agentId === query.agentId)
      .filter((event) => !query.runId || event.runId === query.runId)
      .filter((event) => !query.moduleId || event.moduleId === query.moduleId)
      .filter((event) => !query.decision || event.decision === query.decision)
      .slice(-limit)
      .reverse();
  }

  private mac(value: unknown): string {
    return createHmac("sha256", this.key).update(stableStringify(value)).digest("hex");
  }

  private async loadKey(): Promise<Uint8Array> {
    if (this.config.auditHmacKey) {
      return Buffer.from(this.config.auditHmacKey, "utf8");
    }
    try {
      return Buffer.from((await readFile(this.keyPath, "utf8")).trim(), "hex");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const key = randomBytes(32);
      await writeFile(this.keyPath, key.toString("hex") + "\n", { mode: 0o600 });
      return key;
    }
  }
}
