import { createHash } from "node:crypto";
import {
  access,
  chmod,
  copyFile,
  cp,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  readlink,
  rename,
  rm,
} from "node:fs/promises";
import path from "node:path";
import type { AppConfig } from "./config.js";
import { computeManifestDigest, createEffectId, evaluateEffects } from "./effect-policy.js";
import { SecurityLedger } from "./security-ledger.js";
import type { EffectDecision, EffectPreview, FileEffect } from "./types.js";

interface ScannedEntry {
  hash: string;
  size: number;
}

export interface StagedRun {
  root: string;
  workspacePath: string;
  codexHomePath: string;
}

export interface EvaluatedManifest {
  effects: FileEffect[];
  decision: EffectDecision;
  manifestDigest: string;
}

export class EffectGateway {
  readonly ledger: SecurityLedger;
  private readonly securityRoot: string;
  private readonly stagingRoot: string;
  private readonly snapshotRoot: string;
  private readonly committedCodexRoot: string;

  constructor(private readonly config: AppConfig) {
    this.securityRoot = path.join(config.dataDirectory, "security");
    this.stagingRoot = path.join(this.securityRoot, "staging");
    this.snapshotRoot = path.join(this.securityRoot, "snapshots");
    this.committedCodexRoot = path.join(this.securityRoot, "codex");
    this.ledger = new SecurityLedger(config);
  }

  async initialize(): Promise<void> {
    await Promise.all([
      mkdir(this.stagingRoot, { recursive: true }),
      mkdir(this.snapshotRoot, { recursive: true }),
      mkdir(this.committedCodexRoot, { recursive: true }),
    ]);
    await this.ledger.initialize();
  }

  pathsFor(runId: string): StagedRun {
    const safeRunId = this.safeSegment(runId);
    const root = path.join(this.stagingRoot, safeRunId);
    return {
      root,
      workspacePath: path.join(root, "workspace"),
      codexHomePath: path.join(root, "codex-home"),
    };
  }

  async prepareRun(runId: string, agentId: string, workspacePath: string): Promise<StagedRun> {
    const staged = this.pathsFor(runId);
    await rm(staged.root, { recursive: true, force: true });
    await mkdir(staged.root, { recursive: true });
    await cp(workspacePath, staged.workspacePath, { recursive: true, preserveTimestamps: true });

    const committedCodex = this.committedCodexPath(agentId);
    if (await this.exists(committedCodex)) {
      await cp(committedCodex, staged.codexHomePath, {
        recursive: true,
        preserveTimestamps: true,
      });
    } else {
      await mkdir(staged.codexHomePath, { recursive: true });
      const baseConfig = path.join(this.config.codexHome, "config.toml");
      if (await this.exists(baseConfig)) {
        await copyFile(baseConfig, path.join(staged.codexHomePath, "config.toml"));
      }
    }
    return staged;
  }

  async collectManifest(
    runId: string,
    workspacePath: string,
    stagedWorkspacePath: string,
    ignoredResources: readonly string[] = [],
  ): Promise<EvaluatedManifest> {
    const [before, after] = await Promise.all([
      this.scanWorkspace(workspacePath),
      this.scanWorkspace(stagedWorkspacePath),
    ]);
    const ignored = new Set(ignoredResources);
    const resources = [...new Set([...before.keys(), ...after.keys()])]
      .filter((resource) => !ignored.has(resource))
      .sort();
    const effects: FileEffect[] = [];
    for (const resource of resources) {
      const previous = before.get(resource);
      const next = after.get(resource);
      if (previous?.hash === next?.hash) continue;
      const type = !previous
        ? "file.create"
        : !next
          ? "file.delete"
          : "file.modify";
      const base: FileEffect = {
        id: "",
        runId,
        type,
        resource,
        beforeHash: previous?.hash ?? null,
        afterHash: next?.hash ?? null,
        size: next?.size ?? previous?.size ?? 0,
        decision: "deny",
        ruleId: "unreviewed",
        reason: "Effect has not been reviewed",
      };
      base.id = createEffectId(runId, base);
      effects.push(base);
    }
    return evaluateEffects(effects);
  }

  async workspaceDigest(workspacePath: string): Promise<string> {
    const entries = await this.scanWorkspace(workspacePath);
    return createHash("sha256")
      .update(JSON.stringify([...entries.entries()]))
      .digest("hex");
  }

  async commit(
    runId: string,
    agentId: string,
    workspacePath: string,
    staged: StagedRun,
    effects: FileEffect[],
    ignoredResources: readonly string[] = [],
  ): Promise<void> {
    const currentManifest = await this.collectManifest(
      runId,
      workspacePath,
      staged.workspacePath,
      ignoredResources,
    );
    if (currentManifest.manifestDigest !== computeManifestDigest(effects)) {
      throw new Error("Effect manifest changed before trusted commit");
    }
    const snapshot = path.join(this.snapshotRoot, this.safeSegment(runId));
    const workspaceSnapshot = path.join(snapshot, "workspace");
    const codexSnapshot = path.join(snapshot, "codex-home");
    const committedCodex = this.committedCodexPath(agentId);
    await rm(snapshot, { recursive: true, force: true });
    await mkdir(snapshot, { recursive: true });
    await cp(workspacePath, workspaceSnapshot, { recursive: true, preserveTimestamps: true });
    const hadCommittedCodex = await this.exists(committedCodex);
    if (hadCommittedCodex) {
      await cp(committedCodex, codexSnapshot, { recursive: true, preserveTimestamps: true });
    }

    try {
      for (const effect of effects) {
        if (effect.type !== "file.delete") {
          await this.validateStagedFile(staged.workspacePath, effect.resource);
        }
        await this.validateTargetParents(workspacePath, effect.resource);
      }
      for (const effect of effects) {
        const target = this.resolveInside(workspacePath, effect.resource);
        if (effect.type === "file.delete") {
          await rm(target, { force: true });
          await this.removeEmptyParents(path.dirname(target), workspacePath);
          continue;
        }
        const source = this.resolveInside(staged.workspacePath, effect.resource);
        const sourceStat = await lstat(source);
        await mkdir(path.dirname(target), { recursive: true });
        const temporaryTarget = target + ".aeg-" + runId;
        await copyFile(source, temporaryTarget);
        await chmod(temporaryTarget, sourceStat.mode & 0o777);
        await rename(temporaryTarget, target);
      }
      const verified = await this.collectManifest(
        runId,
        workspacePath,
        staged.workspacePath,
        ignoredResources,
      );
      if (verified.effects.length !== 0) {
        throw new Error("Trusted commit verification failed: workspace differs from staging");
      }
      await this.replaceDirectory(staged.codexHomePath, committedCodex, runId);
      await rm(snapshot, { recursive: true, force: true });
      await rm(staged.root, { recursive: true, force: true });
    } catch (error) {
      await rm(workspacePath, { recursive: true, force: true });
      await cp(workspaceSnapshot, workspacePath, { recursive: true, preserveTimestamps: true });
      await rm(committedCodex, { recursive: true, force: true });
      if (hadCommittedCodex) {
        await cp(codexSnapshot, committedCodex, { recursive: true, preserveTimestamps: true });
      }
      await rm(snapshot, { recursive: true, force: true });
      throw error;
    }
  }

  async createEffectPreviews(
    workspacePath: string,
    stagedWorkspacePath: string,
    effects: FileEffect[],
  ): Promise<EffectPreview[]> {
    return Promise.all(
      effects.map(async (effect) => {
        const before = effect.beforeHash
          ? await this.readPreview(workspacePath, effect.resource)
          : { text: null, truncated: false, binary: false };
        const after = effect.afterHash
          ? await this.readPreview(stagedWorkspacePath, effect.resource)
          : { text: null, truncated: false, binary: false };
        return {
          effectId: effect.id,
          before: before.text,
          after: after.text,
          truncated: before.truncated || after.truncated,
          binary: before.binary || after.binary,
        };
      }),
    );
  }

  async rollback(runId: string): Promise<void> {
    await Promise.all([
      rm(this.pathsFor(runId).root, { recursive: true, force: true }),
      rm(path.join(this.snapshotRoot, this.safeSegment(runId)), {
        recursive: true,
        force: true,
      }),
    ]);
  }

  async cleanupAllStaging(): Promise<void> {
    await rm(this.stagingRoot, { recursive: true, force: true });
    await rm(this.snapshotRoot, { recursive: true, force: true });
    await mkdir(this.stagingRoot, { recursive: true });
    await mkdir(this.snapshotRoot, { recursive: true });
  }

  private committedCodexPath(agentId: string): string {
    return path.join(this.committedCodexRoot, this.safeSegment(agentId));
  }

  private async scanWorkspace(root: string): Promise<Map<string, ScannedEntry>> {
    const entries = new Map<string, ScannedEntry>();
    const walk = async (directory: string, relativeDirectory: string): Promise<void> => {
      const children = await readdir(directory, { withFileTypes: true });
      children.sort((left, right) => left.name.localeCompare(right.name));
      for (const child of children) {
        const relative = relativeDirectory
          ? relativeDirectory + "/" + child.name
          : child.name;
        const absolute = path.join(directory, child.name);
        if (child.isDirectory()) {
          await walk(absolute, relative);
          continue;
        }
        const stats = await lstat(absolute);
        if (stats.isFile()) {
          entries.set(relative, {
            hash: createHash("sha256").update(await readFile(absolute)).digest("hex"),
            size: stats.size,
          });
        } else if (stats.isSymbolicLink()) {
          const target = await readlink(absolute);
          entries.set(relative, {
            hash: createHash("sha256").update("symlink:" + target).digest("hex"),
            size: Buffer.byteLength(target),
          });
        } else {
          entries.set(relative, {
            hash: createHash("sha256").update("special:" + stats.mode).digest("hex"),
            size: stats.size,
          });
        }
      }
    };
    await walk(root, "");
    return entries;
  }

  private async validateStagedFile(root: string, resource: string): Promise<void> {
    const source = this.resolveInside(root, resource);
    const stats = await lstat(source);
    if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink > 1) {
      throw new Error("Trusted commit rejected non-regular or linked file: " + resource);
    }
  }

  private async readPreview(
    root: string,
    resource: string,
  ): Promise<{ text: string | null; truncated: boolean; binary: boolean }> {
    const target = this.resolveInside(root, resource);
    const stats = await lstat(target);
    if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink > 1) {
      return { text: null, truncated: false, binary: true };
    }
    const maximumBytes = 24_000;
    const selected = Buffer.alloc(Math.min(stats.size, maximumBytes));
    const handle = await open(target, "r");
    try {
      await handle.read(selected, 0, selected.length, 0);
    } finally {
      await handle.close();
    }
    if (selected.includes(0)) {
      return { text: null, truncated: stats.size > maximumBytes, binary: true };
    }
    return {
      text: selected.toString("utf8"),
      truncated: stats.size > maximumBytes,
      binary: false,
    };
  }

  private async validateTargetParents(root: string, resource: string): Promise<void> {
    const parts = resource.split("/").slice(0, -1);
    let current = root;
    for (const part of parts) {
      current = path.join(current, part);
      try {
        const stats = await lstat(current);
        if (stats.isSymbolicLink() || !stats.isDirectory()) {
          throw new Error("Trusted commit rejected unsafe path component: " + resource);
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
        throw error;
      }
    }
  }

  private resolveInside(root: string, resource: string): string {
    if (!resource || resource.includes("\\") || path.posix.normalize(resource) !== resource) {
      throw new Error("Invalid effect resource: " + resource);
    }
    const resolvedRoot = path.resolve(root);
    const resolved = path.resolve(resolvedRoot, ...resource.split("/"));
    if (!resolved.startsWith(resolvedRoot + path.sep)) {
      throw new Error("Effect escaped workspace: " + resource);
    }
    return resolved;
  }

  private async removeEmptyParents(directory: string, root: string): Promise<void> {
    const resolvedRoot = path.resolve(root);
    let current = path.resolve(directory);
    while (current.startsWith(resolvedRoot + path.sep)) {
      try {
        await rm(current);
      } catch {
        return;
      }
      current = path.dirname(current);
    }
  }

  private async replaceDirectory(source: string, destination: string, runId: string): Promise<void> {
    const temporary = destination + ".next-" + this.safeSegment(runId);
    const backup = destination + ".previous-" + this.safeSegment(runId);
    await rm(temporary, { recursive: true, force: true });
    await rm(backup, { recursive: true, force: true });
    await mkdir(path.dirname(destination), { recursive: true });
    await cp(source, temporary, { recursive: true, preserveTimestamps: true });
    if (await this.exists(destination)) await rename(destination, backup);
    try {
      await rename(temporary, destination);
      await rm(backup, { recursive: true, force: true });
    } catch (error) {
      if (await this.exists(backup)) await rename(backup, destination);
      throw error;
    }
  }

  private async exists(target: string): Promise<boolean> {
    try {
      await access(target);
      return true;
    } catch {
      return false;
    }
  }

  private safeSegment(value: string): string {
    if (!/^[a-zA-Z0-9_.-]+$/.test(value)) throw new Error("Unsafe identifier");
    return value;
  }
}
