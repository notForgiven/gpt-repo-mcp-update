import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readlink } from "node:fs/promises";
import { join } from "node:path";
import { clampEffectiveLimits, type EffectiveLimits } from "../policies/limits.js";
import { delegationControlArtifactGitExcludes, isDelegationControlArtifact } from "../policies/delegation-control-artifacts.js";
import { isNotFoundError } from "../runtime/fs-helpers.js";
import { IgnoreEngine } from "./ignore-engine.js";
import { validateRepoPath } from "./path-sandbox.js";
import { runGitReadOnly } from "./git-exec.js";
import {
  assertGitRepoConfined,
  buildSafeDiffArgs,
  filterAndRedactUnifiedDiff,
  isHiddenGitReadPath,
  validateGitReadPath,
  validateGitRef
} from "./git-read-safety.js";

const STATUS_LIMIT = 16 * 1024 * 1024;
const SMALL_GIT_LIMIT = 1024 * 1024;

export type GitPathState = {
  path: string;
  exists: boolean;
  kind: "file" | "symlink" | "missing" | "other";
  head_blob_sha256?: string;
  content_sha256: string;
};

export class GitService {
  private readonly ignoreEngine = new IgnoreEngine();
  private readonly maxDiffBytes: number;

  constructor(
    private readonly root: string,
    limits: Partial<Pick<EffectiveLimits, "max_diff_bytes">> = {}
  ) {
    this.maxDiffBytes = clampEffectiveLimits(limits).max_diff_bytes;
  }

  async status() {
    const rootReal = await assertGitRepoConfined(this.root);
    const [branch, headSha, porcelain] = await Promise.all([
      this.gitReadOnlyText(rootReal, ["rev-parse", "--abbrev-ref", "HEAD"], SMALL_GIT_LIMIT),
      this.gitReadOnlyText(rootReal, ["rev-parse", "HEAD"], SMALL_GIT_LIMIT),
      this.gitReadOnlyText(
        rootReal,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--", ".", ...delegationControlArtifactGitExcludes()],
        STATUS_LIMIT
      )
    ]);
    const files = parseStatusPorcelainZ(porcelain)
      .filter((file) => !isDelegationControlArtifact(file.path) && !isDelegationControlArtifact(file.original_path ?? ""));
    const counts: Record<string, number> = {};
    for (const file of files) {
      const key = `${file.index}${file.worktree}`.trim() || "clean";
      counts[key] = (counts[key] ?? 0) + 1;
    }
    return { branch: branch.trim(), head_sha: headSha.trim(), clean: files.length === 0, files, counts };
  }

  async diff(options: {
    base?: string;
    compare?: string;
    staged?: boolean;
    unstaged?: boolean;
    paths?: string[];
    max_bytes?: number;
    context_lines?: number;
    max_files?: number;
  }) {
    const rootReal = await assertGitRepoConfined(this.root);
    if (options.base !== undefined) validateGitRef(options.base, "base");
    if (options.compare !== undefined) validateGitRef(options.compare, "compare");

    if (options.staged === false && options.unstaged === false && !options.base && !options.compare) {
      return {
        base: options.base,
        compare: options.compare,
        staged: options.staged,
        unstaged: options.unstaged,
        files: [],
        total_file_count: 0,
        truncated: false,
        truncation_reason: undefined,
        warnings: []
      };
    }

    const requestedPaths = options.paths
      ? await Promise.all(options.paths.map((path) => validateGitReadPath(rootReal, path, this.ignoreEngine)))
      : undefined;

    let omittedSecretFiles = 0;
    let candidatePaths: string[];
    if (requestedPaths) {
      candidatePaths = requestedPaths;
    } else {
      const discovered = await this.diffPathNames(rootReal, options);
      candidatePaths = discovered.paths;
      omittedSecretFiles += discovered.omittedSecretFiles;
    }

    const totalFileCount = candidatePaths.length;
    const selectedPaths = options.max_files ? candidatePaths.slice(0, options.max_files) : candidatePaths;
    const fileLimitTruncated = selectedPaths.length < totalFileCount;
    if (selectedPaths.length === 0) {
      return {
        base: options.base,
        compare: options.compare,
        staged: options.staged,
        unstaged: options.unstaged,
        files: [],
        total_file_count: totalFileCount,
        truncated: fileLimitTruncated,
        truncation_reason: fileLimitTruncated ? "max_files" as const : undefined,
        warnings: [
          ...(fileLimitTruncated ? [`Diff limited to ${selectedPaths.length} of ${totalFileCount} changed paths by max_files.`] : []),
          ...(omittedSecretFiles > 0 ? [`Omitted ${omittedSecretFiles} secret candidate file(s) from diff output.`] : [])
        ]
      };
    }

    const diffPaths = requestedPaths || fileLimitTruncated || omittedSecretFiles > 0
      ? await this.expandRenamePaths(selectedPaths)
      : undefined;
    const args = buildSafeDiffArgs({
      base: options.base,
      compare: options.compare,
      staged: options.staged,
      unstaged: options.unstaged,
      context_lines: options.context_lines,
      paths: diffPaths
    });
    if (!diffPaths) {
      args.push("--", ".", ...delegationControlArtifactGitExcludes());
    }

    const maxBytes = Math.min(options.max_bytes ?? this.maxDiffBytes, this.maxDiffBytes);
    const result = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args,
      max_stdout_bytes: maxBytes,
      allow_stdout_truncation: true
    });

    const filtered = filterAndRedactUnifiedDiff(result.stdout, this.ignoreEngine);
    omittedSecretFiles += filtered.omitted_secret_files;
    const files: DiffFile[] = filtered.files.map((file) => ({
      path: file.path,
      ...(file.original_path ? { original_path: file.original_path } : {}),
      ...(file.status ? { status: file.status } : {}),
      hunks: file.hunks
    }));

    const truncated = fileLimitTruncated || result.stdout_truncated;
    const reasons = [fileLimitTruncated ? "max_files" : undefined, result.stdout_truncated ? "max_bytes" : undefined].filter(Boolean);
    return {
      base: options.base,
      compare: options.compare,
      staged: options.staged,
      unstaged: options.unstaged,
      files,
      total_file_count: totalFileCount,
      truncated,
      truncation_reason: reasons.length === 0 ? undefined : reasons.join("+") as "max_files" | "max_bytes" | "max_files+max_bytes",
      warnings: [
        ...(fileLimitTruncated ? [`Diff limited to ${selectedPaths.length} of ${totalFileCount} changed paths by max_files.`] : []),
        ...(result.stdout_truncated ? [`Diff content truncated by max_bytes (${maxBytes}); Git completed successfully.`] : []),
        ...(omittedSecretFiles > 0 ? [`Omitted ${omittedSecretFiles} secret candidate file(s) from diff output.`] : []),
        ...(filtered.redacted_secrets ? ["Redacted secret-like value(s) from diff output."] : [])
      ]
    };
  }

  async pathStates(paths: readonly string[]): Promise<GitPathState[]> {
    const normalized = [...new Set(paths.map(validateRepoPath))].sort((a, b) => a.localeCompare(b));
    const states: GitPathState[] = [];
    for (const path of normalized) states.push(await this.pathState(path));
    return states;
  }

  async contentFingerprint(paths: readonly string[]): Promise<string> {
    const states = await this.pathStates(paths);
    if (states.length === 0) return "clean";
    const hash = createHash("sha256");
    for (const state of states) hash.update(JSON.stringify(state)).update("\0");
    return hash.digest("hex");
  }

  async reviewStateFingerprint(paths?: readonly string[]): Promise<string> {
    const selected = paths ? [...paths] : await this.changedProjectPaths(true);
    return this.contentFingerprint(selected);
  }

  async worktreeFingerprint(): Promise<string> {
    return this.contentFingerprint(await this.changedProjectPaths(true));
  }

  private async changedProjectPaths(excludeChatgpt: boolean): Promise<string[]> {
    const status = await this.status();
    return [...new Set(status.files.flatMap((file) => [file.original_path, file.path])
      .filter((path): path is string => Boolean(path))
      .filter((path) => !excludeChatgpt || !path.startsWith(".chatgpt/")))]
      .sort((a, b) => a.localeCompare(b));
  }

  private async pathState(path: string): Promise<GitPathState> {
    const absolute = join(this.root, path);
    let exists = true;
    let kind: GitPathState["kind"] = "file";
    let contentSha: string;
    try {
      const stat = await lstat(absolute);
      if (stat.isSymbolicLink()) {
        kind = "symlink";
        contentSha = createHash("sha256").update(await readlink(absolute)).digest("hex");
      } else if (stat.isFile()) {
        contentSha = await hashFile(absolute);
      } else {
        kind = "other";
        contentSha = createHash("sha256").update(`other:${stat.mode}:${stat.size}`).digest("hex");
      }
    } catch (error) {
      if (!isNotFoundError(error)) throw error;
      exists = false;
      kind = "missing";
      contentSha = createHash("sha256").update("missing").digest("hex");
    }
    return {
      path,
      exists,
      kind,
      content_sha256: contentSha
    };
  }

  private async expandRenamePaths(paths: readonly string[]): Promise<string[]> {
    const selected = new Set(paths);
    const status = await this.status();
    return [...new Set(status.files.flatMap((entry) => {
      if (selected.has(entry.path) || (entry.original_path && selected.has(entry.original_path))) {
        return [entry.original_path, entry.path]
          .filter((path): path is string => Boolean(path))
          .filter((path) => !isHiddenGitReadPath(path, this.ignoreEngine).hidden);
      }
      return selected.has(entry.path) ? [entry.path] : [];
    }).concat([...selected]))].sort((left, right) => left.localeCompare(right));
  }

  private async diffPathNames(
    rootReal: string,
    options: { base?: string; compare?: string; staged?: boolean; unstaged?: boolean }
  ): Promise<{ paths: string[]; omittedSecretFiles: number }> {
    const args = buildSafeDiffArgs({
      base: options.base,
      compare: options.compare,
      staged: options.staged,
      unstaged: options.unstaged,
      names_only: true
    });
    args.push("--", ".", ...delegationControlArtifactGitExcludes());
    const text = await this.gitReadOnlyText(rootReal, args, STATUS_LIMIT);
    const paths: string[] = [];
    let omittedSecretFiles = 0;
    for (const path of [...new Set(text.split("\0").filter(Boolean))].sort((a, b) => a.localeCompare(b))) {
      const hidden = isHiddenGitReadPath(path, this.ignoreEngine);
      if (hidden.hidden) {
        if (hidden.reason === "secret_candidate") omittedSecretFiles += 1;
        continue;
      }
      paths.push(path);
    }
    return { paths, omittedSecretFiles };
  }

  private async gitReadOnlyText(rootReal: string, args: string[], maxBytes: number): Promise<string> {
    const result = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args,
      max_stdout_bytes: maxBytes
    });
    return result.stdout;
  }
}

async function hashFile(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

type StatusFile = { path: string; original_path?: string; index: string; worktree: string };
type DiffFile = { path: string; original_path?: string; status?: string; hunks: string[] };

function parseStatusPorcelainZ(raw: string): StatusFile[] {
  const entries = raw.split("\0");
  const files: StatusFile[] = [];
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (!entry || entry.length < 4) continue;
    const index = entry.slice(0, 1);
    const worktree = entry.slice(1, 2);
    const path = entry.slice(3);
    if (index === "R" || index === "C" || worktree === "R" || worktree === "C") {
      const originalPath = entries[i + 1];
      i += 1;
      files.push({
        index,
        worktree,
        path,
        ...(originalPath ? { original_path: originalPath } : {})
      });
    } else {
      files.push({ index, worktree, path });
    }
  }
  return files;
}
