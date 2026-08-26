import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { SecurityLedger } from "./security-ledger.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("HMAC security ledger", () => {
  it("detects event rewriting without the audit key", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "aeg-ledger-test-"));
    temporaryDirectories.push(root);
    const config = loadConfig({
      NODE_ENV: "test",
      APP_DATA_DIR: path.join(root, "data"),
      AUDIT_HMAC_KEY: "0123456789abcdef0123456789abcdef",
    });
    const ledger = new SecurityLedger(config);
    await ledger.initialize();
    await ledger.append({ type: "run.staged", runId: "run-1" });
    await ledger.append({
      type: "run.committed",
      moduleId: "filesystem-effects",
      runId: "run-1",
      decision: "allow",
    });
    expect(await ledger.verify()).toMatchObject({ valid: true, events: 2 });
    expect(await ledger.list({ moduleId: "filesystem-effects" })).toMatchObject([
      { sequence: 2, decision: "allow" },
    ]);

    const ledgerPath = path.join(root, "data", "security", "ledger", "events.jsonl");
    const rewritten = (await readFile(ledgerPath, "utf8")).replace(
      '"decision":"allow"',
      '"decision":"deny"',
    );
    await writeFile(ledgerPath, rewritten, "utf8");
    expect(await ledger.verify()).toMatchObject({ valid: false, brokenAt: 2 });
  });
});
