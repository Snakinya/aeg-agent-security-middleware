import { access, mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "./agent-service.js";
import { loadConfig } from "./config.js";
import { JsonStore } from "./store.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";
import { WorkspaceManager } from "./workspace.js";

class FakeRunner implements AgentRunner {
  async run(request: RunnerRequest): Promise<RunnerResult> {
    return {
      output: "Completed: " + request.prompt,
      threadId: request.threadId ?? "fake-thread",
      usage: { inputTokens: 12, outputTokens: 5 },
      trace: [],
    };
  }
  async cancel(): Promise<boolean> {
    return false;
  }
  async isAvailable(): Promise<boolean> {
    return true;
  }
}

const temporaryDirectories: string[] = [];

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function makeService(
  runner: AgentRunner = new FakeRunner(),
  environment: NodeJS.ProcessEnv = {},
): Promise<AgentService> {
  const root = await mkdtemp(path.join(tmpdir(), "launchpad-test-"));
  temporaryDirectories.push(root);
  const config = loadConfig({
    NODE_ENV: "test",
    APP_DATA_DIR: path.join(root, "data"),
    AGENT_WORKSPACE_ROOT: path.join(root, "workspaces"),
    CODEX_HOME: path.join(root, "codex"),
    ARK_API_KEY: "test-key",
    ARK_MODEL: "ep-test",
    ...environment,
  });
  const service = new AgentService(
    config,
    new JsonStore(path.join(root, "data", "db.json")),
    new WorkspaceManager(path.join(root, "workspaces")),
    runner,
  );
  await service.initialize();
  return service;
}

describe("Agent lifecycle", () => {
  it("binds a Human, Agent principal and capability to each observable Run", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Attributed Agent" });
    expect(agent.ownerHumanId).toBe("human:local-operator");
    expect(agent.principalId).toBe("agent:" + agent.id);

    const { run } = await service.sendMessage(agent.id, "observe identity");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");

    const overview = await service.securityOverview();
    expect(overview.identity.issuedCapabilities).toBe(1);
    expect(overview.modules.find((module) => module.id === "identity-delegation")).toMatchObject({
      status: "active",
    });
    const identityEvents = await service.securityEvents({ moduleId: "identity-delegation" });
    expect(identityEvents.some((event) => event.type === "identity.delegation_issued")).toBe(true);
    expect(identityEvents[0]).toMatchObject({
      humanId: "human:local-operator",
      agentPrincipalId: "agent:" + agent.id,
    });
  });

  it("revokes and reactivates the Agent principal with lifecycle state", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Revocable Agent" });
    expect((await service.stopAgent(agent.id)).principalStatus).toBe("revoked");
    await expect(service.sendMessage(agent.id, "must fail")).rejects.toMatchObject({
      statusCode: 409,
    });
    expect((await service.startAgent(agent.id)).principalStatus).toBe("active");
  });

  it("creates, updates, stops, starts and deletes an Agent", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Builder" });
    expect(service.listAgents()).toHaveLength(1);
    expect((await service.updateAgent(agent.id, { description: "Builds apps" })).description)
      .toBe("Builds apps");
    expect((await service.stopAgent(agent.id)).status).toBe("stopped");
    expect((await service.startAgent(agent.id)).status).toBe("ready");
    await service.deleteAgent(agent.id);
    expect(service.listAgents()).toHaveLength(0);
  });

  it("persists a playground conversation", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Coder" });
    const { run } = await service.sendMessage(agent.id, "write hello world");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
    const messages = service.getMessages(agent.id);
    expect(messages.map((message) => message.role)).toEqual(["user", "assistant"]);
    expect(messages[1]?.content).toContain("write hello world");
    expect(service.getAgent(agent.id).codexThreadId).toBe("fake-thread");
  });

  it("atomically accepts only one concurrent run per Agent", async () => {
    let finish!: (result: RunnerResult) => void;
    const pending = new Promise<RunnerResult>((resolve) => {
      finish = resolve;
    });
    const runner: AgentRunner = {
      run: () => pending,
      cancel: async () => false,
      isAvailable: async () => true,
    };
    const service = await makeService(runner);
    const agent = await service.createAgent({ name: "Concurrent" });
    const attempts = await Promise.allSettled([
      service.sendMessage(agent.id, "first"),
      service.sendMessage(agent.id, "second"),
    ]);

    expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
    const rejected = attempts.find((attempt) => attempt.status === "rejected");
    expect(rejected).toMatchObject({ reason: { statusCode: 409 } });
    expect(service.getMessages(agent.id)).toHaveLength(1);

    finish({ output: "done", threadId: "thread", usage: null, trace: [] });
    const accepted = attempts.find((attempt) => attempt.status === "fulfilled");
    if (accepted?.status === "fulfilled") {
      await expect.poll(() => service.getRun(accepted.value.run.id).status).toBe("completed");
    }
  });

  it("does not let start reset a busy Agent and admit a second run", async () => {
    let finish!: (result: RunnerResult) => void;
    const pending = new Promise<RunnerResult>((resolve) => {
      finish = resolve;
    });
    const service = await makeService({
      run: () => pending,
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Busy" });
    const { run } = await service.sendMessage(agent.id, "first");

    await expect(service.startAgent(agent.id)).rejects.toMatchObject({ statusCode: 409 });
    await expect(service.sendMessage(agent.id, "second")).rejects.toMatchObject({
      statusCode: 409,
    });

    finish({ output: "done", threadId: "thread", usage: null, trace: [] });
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
  });

  it("commits ordinary staged workspace effects without approval", async () => {
    const service = await makeService({
      run: async (request) => {
        await writeFile(path.join(request.workspacePath, "hello.ts"), "export const hello = true;\n");
        return { output: "created hello.ts", threadId: "safe-thread", usage: null, trace: [] };
      },
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Safe writer" });
    const { run } = await service.sendMessage(agent.id, "create hello.ts");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
    expect(await readFile(path.join(agent.workspacePath, "hello.ts"), "utf8")).toContain(
      "hello = true",
    );
    expect(service.getRun(run.id).effects[0]?.decision).toBe("allow");
    expect(service.getRun(run.id).workspaceHashBefore).not.toBe(
      service.getRun(run.id).workspaceHashAfter,
    );
    expect(service.getAgent(agent.id).codexThreadId).toBe("safe-thread");
  });

  it("rolls back a hard-denied secret effect and does not advance the session", async () => {
    const service = await makeService({
      run: async (request) => {
        await writeFile(path.join(request.workspacePath, ".env"), "SECRET=stolen\n");
        await writeFile(path.join(request.workspacePath, "otherwise-safe.ts"), "export {};\n");
        return { output: "changed env", threadId: "tainted-thread", usage: null, trace: [] };
      },
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Denied writer" });
    const { run } = await service.sendMessage(agent.id, "change env");
    await expect.poll(() => service.getRun(run.id).status).toBe("rolled_back");
    await expect(access(path.join(agent.workspacePath, ".env"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(
      access(path.join(agent.workspacePath, "otherwise-safe.ts")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    expect(service.getAgent(agent.id).codexThreadId).toBeNull();
    expect(service.getRun(run.id).workspaceHashBefore).toBe(
      service.getRun(run.id).workspaceHashAfter,
    );
    expect(service.getRun(run.id).effects.find((effect) => effect.resource === ".env")?.ruleId).toBe(
      "hard-deny-platform-and-secrets",
    );
  });

  it("holds operational effects for approval and commits the exact manifest", async () => {
    const service = await makeService({
      run: async (request) => {
        await writeFile(path.join(request.workspacePath, "Dockerfile"), "FROM scratch\n");
        return { output: "created image", threadId: "approved-thread", usage: null, trace: [] };
      },
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Deploy writer" });
    const { run } = await service.sendMessage(agent.id, "create Dockerfile");
    await expect.poll(() => service.getRun(run.id).status).toBe("awaiting_approval");
    await expect(access(path.join(agent.workspacePath, "Dockerfile"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    const approval = service.getApprovals("pending")[0];
    expect(approval).toBeDefined();
    const details = await service.getApprovalDetails(approval!.id);
    expect(details.previews[0]).toMatchObject({
      before: null,
      after: "FROM scratch\n",
      binary: false,
    });
    await service.approveApproval(approval!.id);
    expect(await readFile(path.join(agent.workspacePath, "Dockerfile"), "utf8")).toBe(
      "FROM scratch\n",
    );
    expect(service.getRun(run.id).status).toBe("completed");
    expect(service.getRun(run.id).workspaceHashBefore).not.toBe(
      service.getRun(run.id).workspaceHashAfter,
    );
  });

  it("rejects approval when staged content changes after review", async () => {
    let stagedWorkspace = "";
    const service = await makeService({
      run: async (request) => {
        stagedWorkspace = request.workspacePath;
        await writeFile(path.join(request.workspacePath, "Dockerfile"), "FROM scratch\n");
        return { output: "created image", threadId: "tainted-thread", usage: null, trace: [] };
      },
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Digest writer" });
    const { run } = await service.sendMessage(agent.id, "create Dockerfile");
    await expect.poll(() => service.getRun(run.id).status).toBe("awaiting_approval");
    await writeFile(path.join(stagedWorkspace, "Dockerfile"), "FROM replaced\n");
    const approval = service.getApprovals("pending")[0];
    await expect(service.approveApproval(approval!.id)).rejects.toMatchObject({
      statusCode: 409,
    });
    expect(service.getRun(run.id).status).toBe("rolled_back");
    expect(service.getRun(run.id).workspaceHashBefore).toBe(
      service.getRun(run.id).workspaceHashAfter,
    );
    await expect(access(path.join(agent.workspacePath, "Dockerfile"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("denies linked staged files at policy review and rolls the run back", async () => {
    const service = await makeService({
      run: async (request) => {
        await symlink("/etc/passwd", path.join(request.workspacePath, "linked.txt"));
        return { output: "created link", threadId: "link-thread", usage: null, trace: [] };
      },
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Link writer" });
    const { run } = await service.sendMessage(agent.id, "create a link");
    await expect.poll(() => service.getRun(run.id).status).toBe("rolled_back");
    await expect(access(path.join(agent.workspacePath, "linked.txt"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    const stored = service.getRun(run.id);
    expect(stored.securitySummary).toContain("Policy denied the manifest");
    expect(stored.effects.find((effect) => effect.resource === "linked.txt")?.ruleId).toBe(
      "deny-non-regular-file",
    );
  });

  it("waits for approval before executing an external HTTP effect", async () => {
    let calls = 0;
    const server = createServer((_request, response) => {
      calls += 1;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ ticketId: "T-42" }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    try {
      const service = await makeService(
        {
          run: async (request) => {
            const directory = path.join(request.workspacePath, ".aeg");
            await mkdir(directory, { recursive: true });
            await writeFile(
              path.join(directory, "external-effects.json"),
              JSON.stringify({
                version: 1,
                requests: [
                  {
                    method: "POST",
                    url: `http://127.0.0.1:${port}/tickets`,
                    body: { title: "Agent request" },
                  },
                ],
              }),
              "utf8",
            );
            return {
              output: "requested ticket creation",
              threadId: "external-thread",
              usage: null,
              trace: [],
            };
          },
          cancel: async () => false,
          isAvailable: async () => true,
        },
        {
          AEG_HTTP_ALLOWLIST: "127.0.0.1",
          AEG_HTTP_ALLOW_PRIVATE_NETWORKS: "true",
        },
      );
      const agent = await service.createAgent({ name: "Service Agent" });
      const { run } = await service.sendMessage(agent.id, "create a ticket through AEG");
      await expect.poll(() => service.getRun(run.id).status).toBe("awaiting_approval");
      expect(calls).toBe(0);
      expect(service.getRun(run.id).effects).toHaveLength(0);
      expect(service.getRun(run.id).externalEffects[0]).toMatchObject({
        decision: "require_approval",
        status: "planned",
      });

      const approval = service.getApprovals("pending")[0];
      await service.approveApproval(approval!.id);
      const completed = service.getRun(run.id);
      expect(calls).toBe(1);
      expect(completed.status).toBe("completed");
      expect(completed.externalEffects[0]).toMatchObject({
        status: "executed",
        receipt: { statusCode: 200 },
      });
      expect(completed.workspaceHashBefore).toBe(completed.workspaceHashAfter);
      await expect(
        access(path.join(agent.workspacePath, ".aeg", "external-effects.json")),
      ).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });

  it("rejects a changed external request after approval was requested", async () => {
    let stagedOutbox = "";
    const service = await makeService(
      {
        run: async (request) => {
          const directory = path.join(request.workspacePath, ".aeg");
          await mkdir(directory, { recursive: true });
          stagedOutbox = path.join(directory, "external-effects.json");
          await writeFile(
            stagedOutbox,
            JSON.stringify({
              version: 1,
              requests: [{ method: "POST", url: "http://127.0.0.1:1/a", body: { n: 1 } }],
            }),
            "utf8",
          );
          return { output: "planned", threadId: "thread", usage: null, trace: [] };
        },
        cancel: async () => false,
        isAvailable: async () => true,
      },
      {
        AEG_HTTP_ALLOWLIST: "127.0.0.1",
        AEG_HTTP_ALLOW_PRIVATE_NETWORKS: "true",
      },
    );
    const agent = await service.createAgent({ name: "Bound request" });
    const { run } = await service.sendMessage(agent.id, "plan external request");
    await expect.poll(() => service.getRun(run.id).status).toBe("awaiting_approval");
    await writeFile(
      stagedOutbox,
      JSON.stringify({
        version: 1,
        requests: [{ method: "POST", url: "http://127.0.0.1:1/b", body: { n: 2 } }],
      }),
      "utf8",
    );
    const approval = service.getApprovals("pending")[0];
    await expect(service.approveApproval(approval!.id)).rejects.toMatchObject({
      statusCode: 409,
    });
    expect(service.getRun(run.id).status).toBe("rolled_back");
  });
});
