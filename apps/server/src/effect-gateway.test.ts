import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { EffectGateway, isIgnoredResource } from "./effect-gateway.js";
import type { AppConfig } from "./config.js";

let root: string;
let gateway: EffectGateway;
let workspace: string;
let staging: string;

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), "aeg-gateway-"));
  workspace = path.join(root, "workspace");
  staging = path.join(root, "staged-workspace");
  await mkdir(workspace, { recursive: true });
  await mkdir(staging, { recursive: true });
  gateway = new EffectGateway({ dataDirectory: path.join(root, "data") } as AppConfig);
  await gateway.initialize();
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("EffectGateway manifest collection", () => {
  it("excludes ephemeral tool directories from the protected manifest", async () => {
    await writeFile(path.join(workspace, "app.ts"), "before");
    await writeFile(path.join(staging, "app.ts"), "after");
    await mkdir(path.join(staging, "node_modules", ".bin"), { recursive: true });
    await writeFile(path.join(staging, "node_modules", "left-pad.js"), "module");
    await symlink("../left-pad.js", path.join(staging, "node_modules", ".bin", "left-pad"));
    await mkdir(path.join(staging, ".git"), { recursive: true });
    await writeFile(path.join(staging, ".git", "config"), "[core]");
    await mkdir(path.join(staging, "dist"), { recursive: true });
    await writeFile(path.join(staging, "dist", "bundle.js"), "built");

    const manifest = await gateway.collectManifest("run-1", workspace, staging);

    expect(manifest.effects.map((effect) => effect.resource)).toEqual(["app.ts"]);
    expect(manifest.decision).toBe("allow");
  });

  it("keeps a benign npm-style run committable end to end", async () => {
    const stagedRoot = path.join(root, "staged-run");
    const stagedWorkspace = path.join(stagedRoot, "workspace");
    const stagedCodexHome = path.join(stagedRoot, "codex-home");
    await mkdir(stagedWorkspace, { recursive: true });
    await mkdir(stagedCodexHome, { recursive: true });
    await writeFile(path.join(stagedWorkspace, "index.ts"), "console.log(1);");
    await mkdir(path.join(stagedWorkspace, "node_modules", ".bin"), { recursive: true });
    await symlink("../tsc.js", path.join(stagedWorkspace, "node_modules", ".bin", "tsc"));

    const manifest = await gateway.collectManifest("run-2", workspace, stagedWorkspace);
    expect(manifest.decision).toBe("allow");

    await gateway.commit(
      "run-2",
      "agent-1",
      workspace,
      { root: stagedRoot, workspacePath: stagedWorkspace, codexHomePath: stagedCodexHome },
      manifest.effects,
    );
    const after = await gateway.collectManifest("run-2", workspace, workspace);
    expect(after.effects).toHaveLength(0);
    const committed = await gateway.collectManifest("run-2", workspace, workspace);
    expect(committed.decision).toBe("allow");
  });

  it("denies symlinks outside ignored directories at policy time", async () => {
    await symlink("/etc/passwd", path.join(staging, "escape"));

    const manifest = await gateway.collectManifest("run-3", workspace, staging);

    expect(manifest.decision).toBe("deny");
    const effect = manifest.effects.find((item) => item.resource === "escape");
    expect(effect?.decision).toBe("deny");
    expect(effect?.ruleId).toBe("deny-non-regular-file");
  });

  it("still allows deleting a previously committed symlink", async () => {
    await symlink("./real.txt", path.join(workspace, "old-link"));
    await writeFile(path.join(workspace, "real.txt"), "keep");
    await writeFile(path.join(staging, "real.txt"), "keep");

    const manifest = await gateway.collectManifest("run-4", workspace, staging);

    const effect = manifest.effects.find((item) => item.resource === "old-link");
    expect(effect?.type).toBe("file.delete");
    expect(effect?.decision).toBe("allow");
  });

  it("classifies ignored resources for trace correlation", () => {
    expect(isIgnoredResource("node_modules/.bin/tsc")).toBe(true);
    expect(isIgnoredResource("src/node_modules_helper.ts")).toBe(false);
    expect(isIgnoredResource(".git/config")).toBe(true);
    expect(isIgnoredResource("src/app.ts")).toBe(false);
  });
});
