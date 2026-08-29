import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { agentPrincipalId, localOperator, LOCAL_OPERATOR_ID } from "./identity-delegation.js";
import type { Database } from "./types.js";
import { defaultPolicyProfile } from "./policy-profile.js";

const emptyDatabase = (): Database => ({
  version: 5,
  humans: [localOperator()],
  runSecurityContexts: [],
  agents: [],
  messages: [],
  runs: [],
  approvals: [],
  securityModuleConfigurations: [],
});

export class JsonStore {
  private data: Database = emptyDatabase();
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  async initialize(): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as Database & { version: 1 | 2 | 3 | 4 | 5 };
      if (![1, 2, 3, 4, 5].includes(parsed.version) || !Array.isArray(parsed.agents)) {
        throw new Error("Unsupported database format");
      }
      this.data = {
        ...parsed,
        version: 5,
        humans:
          "humans" in parsed && Array.isArray(parsed.humans) && parsed.humans.length > 0
            ? parsed.humans
            : [localOperator()],
        runSecurityContexts:
          "runSecurityContexts" in parsed && Array.isArray(parsed.runSecurityContexts)
            ? parsed.runSecurityContexts
            : [],
        agents: parsed.agents.map((agent) => ({
          ...agent,
          ownerHumanId: agent.ownerHumanId ?? LOCAL_OPERATOR_ID,
          principalId: agent.principalId ?? agentPrincipalId(agent.id),
          principalStatus: agent.principalStatus ?? (agent.status === "stopped" ? "revoked" : "active"),
          policyProfile: agent.policyProfile ?? defaultPolicyProfile(),
        })),
        approvals:
          "approvals" in parsed && Array.isArray(parsed.approvals)
              ? parsed.approvals.map((approval) => ({
                ...approval,
                approvedBy: approval.approvedBy ?? null,
                scope: approval.scope ?? "manifest",
              }))
            : [],
        runs: parsed.runs.map((run) => ({
          ...run,
          effects: "effects" in run && Array.isArray(run.effects) ? run.effects : [],
          externalEffects:
            "externalEffects" in run && Array.isArray(run.externalEffects)
              ? run.externalEffects
              : [],
          trace: "trace" in run && Array.isArray(run.trace) ? run.trace : [],
          manifestDigest: "manifestDigest" in run ? run.manifestDigest : null,
          policyVersion: "policyVersion" in run ? run.policyVersion : null,
          approvalId: "approvalId" in run ? run.approvalId : null,
          securityContextId:
            run.securityContextId ?? "legacy:" + run.id,
          securitySummary: "securitySummary" in run ? run.securitySummary : null,
          workspaceHashBefore:
            "workspaceHashBefore" in run ? run.workspaceHashBefore : null,
          workspaceHashAfter: "workspaceHashAfter" in run ? run.workspaceHashAfter : null,
          pendingThreadId: "pendingThreadId" in run ? run.pendingThreadId : null,
        })),
        securityModuleConfigurations:
          "securityModuleConfigurations" in parsed && Array.isArray(parsed.securityModuleConfigurations)
            ? parsed.securityModuleConfigurations
            : [],
      } as Database;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
      await this.persist();
    }
  }

  snapshot(): Database {
    return structuredClone(this.data);
  }

  async mutate<T>(mutation: (database: Database) => T | Promise<T>): Promise<T> {
    let result!: T;
    const operation = this.queue.then(async () => {
      const next = structuredClone(this.data);
      result = await mutation(next);
      await this.persist(next);
      this.data = next;
    });
    this.queue = operation.catch(() => undefined);
    await operation;
    return result;
  }

  private async persist(data: Database = this.data): Promise<void> {
    const temporaryPath = this.filePath + ".tmp";
    await writeFile(temporaryPath, JSON.stringify(data, null, 2) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryPath, this.filePath);
  }
}
