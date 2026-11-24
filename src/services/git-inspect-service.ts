import { access, lstat } from "node:fs/promises";
import { join, posix } from "node:path";
import type {
  GitInspectInput,
  GitInspectResult
} from "../contracts/git-inspect.contract.js";
import { delegationControlArtifactGitExcludes, isDelegationControlArtifact } from "../policies/delegation-control-artifacts.js";
import { DEFAULT_LIMITS } from "../policies/limits.js";
import { RepoReaderError } from "../runtime/errors.js";
import { decodeUtf8Safe, runGitReadOnly, runGitReadOnlyBuffer } from "./git-exec.js";
import {
  assertGitRepoConfined,
  buildSafeDiffArgs,
  filterAndRedactUnifiedDiff,
  hasEnvTemplateSecret,
  isBinaryBuffer,
  isHiddenGitReadPath,
  redactGitText,
  truncateUtf8Bytes,
  validateGitDateSpec,
  validateGitFilterText,
  validateGitPattern,
  validateGitReadPath,
  validateGitRef
} from "./git-read-safety.js";
import { IgnoreEngine } from "./ignore-engine.js";

const SMALL_OUTPUT_LIMIT = 256 * 1024;
const METADATA_OUTPUT_LIMIT = 4 * 1024 * 1024;
const DEFAULT_BRANCH_TAG_LIMIT = 100;
const DEFAULT_LOG_LIMIT = 20;
const DEFAULT_COMMIT_TREE_LIMIT = 30;
const DEFAULT_FILE_TREE_LIMIT = 500;
const DEFAULT_SHORTLOG_LIMIT = 50;
const DEFAULT_BLAME_WINDOW = 200;

type NumstatEntry = {
  path: string;
  original_path?: string;
  status?: string;
  insertions?: number;
  deletions?: number;
  is_binary?: boolean;
};

type ParsedStatusEntry = {
  path: string;
  original_path?: string;
  index: string;
  worktree: string;
  status: "modified" | "added" | "deleted" | "renamed" | "copied" | "untracked" | "unmerged" | "unknown";
  staged: boolean;
  unstaged: boolean;
};

export class GitInspectService {
  private readonly ignoreEngine = new IgnoreEngine();

  constructor(private readonly root: string) {}

  async inspect(input: GitInspectInput): Promise<GitInspectResult> {
    const rootReal = await assertGitRepoConfined(this.root);

    switch (input.command) {
      case "status":
        return this.inspectStatus(rootReal, input);
      case "branch":
        return this.inspectBranches(rootReal, input);
      case "tag":
        return this.inspectTags(rootReal, input);
      case "log":
        return this.inspectLog(rootReal, input);
      case "diff":
        return this.inspectDiff(rootReal, input);
      case "commit_tree":
        return this.inspectCommitTree(rootReal, input);
      case "file_tree":
        return this.inspectFileTree(rootReal, input);
      case "show":
        return this.inspectShow(rootReal, input);
      case "blame":
        return this.inspectBlame(rootReal, input);
      case "rev_parse":
        return this.inspectRevParse(rootReal, input);
      case "merge_base":
        return this.inspectMergeBase(rootReal, input);
      case "shortlog":
        return this.inspectShortlog(rootReal, input);
    }
  }

  private async inspectStatus(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const validatedPaths = await this.validateOptionalPaths(rootReal, input.paths);
    const args = ["status", "--porcelain=v2", "--branch", "-z", "--untracked-files=all", "--"];
    if (validatedPaths && validatedPaths.length > 0) {
      args.push(...validatedPaths);
    } else {
      args.push(".", ...delegationControlArtifactGitExcludes());
    }

    const [statusResult, opState] = await Promise.all([
      runGitReadOnly({
        root: rootReal,
        root_real: rootReal,
        args,
        max_stdout_bytes: METADATA_OUTPUT_LIMIT
      }),
      detectRepoOperationState(rootReal)
    ]);

    const parsed = parsePorcelainV2Status(statusResult.stdout);
    const visibleFiles: ParsedStatusEntry[] = [];
    let omittedSecretPaths = 0;

    for (const entry of parsed.files) {
      const pathHidden = isHiddenGitReadPath(entry.path, this.ignoreEngine);
      const origHidden = entry.original_path
        ? isHiddenGitReadPath(entry.original_path, this.ignoreEngine)
        : { hidden: false as const };

      if (pathHidden.reason === "internal_artifact" || origHidden.reason === "internal_artifact") {
        continue;
      }
      if (pathHidden.reason === "secret_candidate" || origHidden.reason === "secret_candidate") {
        omittedSecretPaths += 1;
        continue;
      }
      visibleFiles.push(entry);
    }

    const limit = clampPositive(input.limit, DEFAULT_LIMITS.max_git_status_entries, DEFAULT_LIMITS.max_git_status_entries);
    const truncated = visibleFiles.length > limit;
    const files = truncated ? visibleFiles.slice(0, limit) : visibleFiles;

    const counts: Record<string, number> = {};
    for (const file of visibleFiles) {
      counts[file.status] = (counts[file.status] ?? 0) + 1;
    }

    const clean = visibleFiles.length === 0 && omittedSecretPaths === 0;
    const state = opState ?? (clean ? "clean" : "dirty");
    const warnings: string[] = [];
    if (omittedSecretPaths > 0) {
      warnings.push(`Omitted ${omittedSecretPaths} secret-candidate path(s) from status.`);
    }
    if (truncated) {
      warnings.push(`Status entries truncated to ${limit} of ${visibleFiles.length} changed entries.`);
    }

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "status",
      truncated,
      ...(truncated ? { truncation_reason: "limit" } : {}),
      warnings,
      status: {
        branch: parsed.branch,
        head_sha: parsed.head_sha,
        detached: parsed.detached,
        ...(parsed.upstream ? { upstream: parsed.upstream } : {}),
        ahead: parsed.ahead,
        behind: parsed.behind,
        state,
        clean,
        counts,
        total_file_count: visibleFiles.length,
        files
      }
    };
  }

  private async inspectBranches(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const scope = input.scope ?? "local";
    const pattern = input.pattern !== undefined ? validateGitPattern(input.pattern, "pattern") : undefined;
    const contains = input.contains !== undefined ? validateGitRef(input.contains, "contains") : undefined;
    const merged = input.merged !== undefined ? validateGitRef(input.merged, "merged") : undefined;
    const noMerged = input.no_merged !== undefined ? validateGitRef(input.no_merged, "no_merged") : undefined;
    const sort = input.sort ?? "refname";
    const limit = clampPositive(input.limit, DEFAULT_BRANCH_TAG_LIMIT, DEFAULT_LIMITS.max_git_refs);

    const refPrefixes = scope === "local"
      ? ["refs/heads"]
      : scope === "remote"
        ? ["refs/remotes"]
        : ["refs/heads", "refs/remotes"];

    const args = [
      "for-each-ref",
      `--sort=${sort}`,
      "--format=%(HEAD)%1f%(refname)%1f%(refname:short)%1f%(objectname)%1f%(objectname:short)%1f%(upstream:short)%1f%(upstream:trackshort)%1f%(committerdate:iso-strict)%1f%(symref)%1f%(contents:subject)%00"
    ];
    if (contains) args.push(`--contains=${contains}`);
    if (merged) args.push(`--merged=${merged}`);
    if (noMerged) args.push(`--no-merged=${noMerged}`);
    args.push(...refPrefixes);

    const result = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args,
      max_stdout_bytes: METADATA_OUTPUT_LIMIT
    });

    let redactedSecrets = false;
    let currentBranch: string | undefined;

    const matched: NonNullable<GitInspectResult["branches"]>["items"] = [];
    for (const record of result.stdout.split("\0")) {
      if (!record) continue;
      const trimmedRecord = record.replace(/^\r?\n/, "");
      if (!trimmedRecord) continue;
      const parts = trimmedRecord.split("\x1f");
      if (parts.length < 10) continue;
      const [headMarker, fullRef, shortName, headSha, shortSha, upstream, trackShort, committerDate, symref, ...subjectParts] = parts;
      if (symref && fullRef!.startsWith("refs/remotes/") && fullRef!.endsWith("/HEAD")) {
        continue;
      }
      const isCurrent = headMarker === "*";
      if (isCurrent && fullRef!.startsWith("refs/heads/")) {
        currentBranch = shortName!;
      }
      if (pattern && !matchGlob(pattern, shortName!)) {
        continue;
      }
      const subjectRedacted = redactGitText(subjectParts.join("\x1f").trim());
      if (subjectRedacted.redacted) redactedSecrets = true;

      matched.push({
        name: shortName!,
        full_ref: fullRef!,
        scope: fullRef!.startsWith("refs/remotes/") ? "remote" : "local",
        is_current: isCurrent,
        head_sha: headSha!,
        short_sha: shortSha!,
        ...(upstream ? { upstream } : {}),
        ...(trackShort ? { track_short: trackShort } : {}),
        subject: subjectRedacted.text,
        committer_date: committerDate!
      });
    }

    const truncated = matched.length > limit;
    const items = truncated ? matched.slice(0, limit) : matched;
    const warnings: string[] = [];
    if (redactedSecrets) warnings.push("Redacted secret-like values in branch commit subjects.");
    if (truncated) warnings.push(`Branch list truncated to ${limit} of ${matched.length} matching branches.`);

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "branch",
      truncated,
      ...(truncated ? { truncation_reason: "limit" } : {}),
      warnings,
      branches: {
        scope,
        ...(currentBranch ? { current_branch: currentBranch } : {}),
        total_count: matched.length,
        items
      }
    };
  }

  private async inspectTags(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const pattern = input.pattern !== undefined ? validateGitPattern(input.pattern, "pattern") : undefined;
    const contains = input.contains !== undefined ? validateGitRef(input.contains, "contains") : undefined;
    const sort = input.sort ?? "-creatordate";
    const limit = clampPositive(input.limit, DEFAULT_BRANCH_TAG_LIMIT, DEFAULT_LIMITS.max_git_refs);

    const args = [
      "for-each-ref",
      `--sort=${sort}`,
      "--format=%(refname:short)%1f%(objecttype)%1f%(objectname)%1f%(*objectname)%1f%(creatordate:iso-strict)%1f%(contents:subject)%00"
    ];
    if (contains) args.push(`--contains=${contains}`);
    args.push("refs/tags");

    const result = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args,
      max_stdout_bytes: METADATA_OUTPUT_LIMIT
    });

    let redactedSecrets = false;

    const matched: NonNullable<GitInspectResult["tags"]>["items"] = [];
    for (const record of result.stdout.split("\0")) {
      if (!record) continue;
      const trimmedRecord = record.replace(/^\r?\n/, "");
      if (!trimmedRecord) continue;
      const parts = trimmedRecord.split("\x1f");
      if (parts.length < 6) continue;
      const [name, objectType, sha, targetSha, date, ...subjectParts] = parts;
      if (pattern && !matchGlob(pattern, name!)) {
        continue;
      }
      const subjectRedacted = redactGitText(subjectParts.join("\x1f").trim());
      if (subjectRedacted.redacted) redactedSecrets = true;

      matched.push({
        name: name!,
        object_type: objectType!,
        sha: sha!,
        ...(targetSha ? { target_sha: targetSha } : {}),
        date: date!,
        subject: subjectRedacted.text,
        is_annotated: objectType === "tag"
      });
    }

    const truncated = matched.length > limit;
    const items = truncated ? matched.slice(0, limit) : matched;
    const warnings: string[] = [];
    if (redactedSecrets) warnings.push("Redacted secret-like values in tag subjects.");
    if (truncated) warnings.push(`Tag list truncated to ${limit} of ${matched.length} matching tags.`);

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "tag",
      truncated,
      ...(truncated ? { truncation_reason: "limit" } : {}),
      warnings,
      tags: {
        total_count: matched.length,
        items
      }
    };
  }

  private async inspectLog(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const ref = input.ref !== undefined ? validateGitRef(input.ref, "ref") : undefined;
    const compareRef = input.compare_ref !== undefined ? validateGitRef(input.compare_ref, "compare_ref") : undefined;
    const rangeMode = compareRef ? (input.range_mode ?? "two_dot") : undefined;
    const author = input.author !== undefined ? validateGitFilterText(input.author, "author") : undefined;
    const grep = input.grep !== undefined ? validateGitFilterText(input.grep, "grep") : undefined;
    const since = input.since !== undefined ? validateGitDateSpec(input.since, "since") : undefined;
    const until = input.until !== undefined ? validateGitDateSpec(input.until, "until") : undefined;
    const validatedPaths = await this.validateOptionalPaths(rootReal, input.paths);
    const limit = clampPositive(input.limit, DEFAULT_LOG_LIMIT, DEFAULT_LIMITS.max_git_log_commits);
    const skip = Math.max(0, Math.min(input.skip ?? 0, 10_000));
    const maxBytes = clampPositive(input.max_bytes, DEFAULT_LIMITS.max_git_show_bytes, DEFAULT_LIMITS.max_git_show_bytes);

    const args = [
      "log",
      "--no-ext-diff",
      "--no-textconv",
      "--no-color",
      "--fixed-strings",
      "-n",
      String(limit + 1),
      "--format=%x1e%H%x1f%h%x1f%P%x1f%D%x1f%an%x1f%aI%x1f%cI%x1f%s%x1f%b%x1d"
    ];
    if (skip > 0) args.push(`--skip=${skip}`);
    if (author) args.push(`--author=${author}`);
    if (grep) args.push(`--grep=${grep}`);
    if (since) args.push(`--since=${since}`);
    if (until) args.push(`--until=${until}`);
    if (input.first_parent) args.push("--first-parent");
    if (input.merges === "only") args.push("--merges");
    else if (input.merges === "exclude") args.push("--no-merges");
    if (input.include_stat) args.push("--numstat", "--find-renames", "-z");

    if (ref && compareRef) {
      args.push(`${ref}${rangeMode === "three_dot" ? "..." : ".."}${compareRef}`);
    } else if (ref) {
      args.push(ref);
    }

    if (validatedPaths && validatedPaths.length > 0) {
      args.push("--", ...validatedPaths);
    }

    const result = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args,
      max_stdout_bytes: maxBytes,
      allow_stdout_truncation: true,
      allow_non_zero_exit: true
    });

    if (result.exit_code !== 0) {
      if (isUnbornHeadError(result.stderr) && !ref) {
        return {
          ok: true,
          repo_id: input.repo_id,
          command: "log",
          truncated: false,
          warnings: ["Repository has no commits yet."],
          commits: {
            skip,
            total_returned: 0,
            items: []
          }
        };
      }
      throw new RepoReaderError("GIT_ERROR", result.stderr.trim() || `Git exited with ${result.exit_code}.`);
    }

    const rawRecords = result.stdout.split("\x1e").filter((segment) => segment.length > 0);
    const items: NonNullable<GitInspectResult["commits"]>["items"] = [];
    let redactedSecrets = false;
    let totalOmittedSecretFiles = 0;

    for (const rawRecord of rawRecords) {
      const groupEnd = rawRecord.indexOf("\x1d");
      if (groupEnd === -1) {
        // Truncated mid-commit header by max_bytes; stop cleanly.
        break;
      }
      const header = rawRecord.slice(0, groupEnd);
      const statTail = rawRecord.slice(groupEnd + 1);
      const fields = header.split("\x1f");
      if (fields.length < 9) continue;

      const [sha, shortSha, parentsRaw, refsRaw, authorName, authorDate, committerDate, subjectRaw, ...bodyParts] = fields;
      const subjectRes = redactGitText(subjectRaw!.trim());
      const bodyRaw = bodyParts.join("\x1f").trim();
      const bodyRes = bodyRaw ? redactGitText(bodyRaw) : { text: "", redacted: false };
      if (subjectRes.redacted || bodyRes.redacted) redactedSecrets = true;

      let files: NumstatEntry[] | undefined;
      let omittedSecretFiles: number | undefined;
      if (input.include_stat) {
        const filteredStats = this.filterNumstatEntries(parseNumstatZ(statTail));
        files = filteredStats.entries;
        omittedSecretFiles = filteredStats.omittedSecretFiles;
        totalOmittedSecretFiles += filteredStats.omittedSecretFiles;
      }

      items.push({
        sha: sha!,
        short_sha: shortSha!,
        parents: parentsRaw ? parentsRaw.split(" ").filter(Boolean) : [],
        refs: parseDecorations(refsRaw ?? ""),
        author_name: authorName!,
        author_date: authorDate!,
        committer_date: committerDate!,
        subject: subjectRes.text,
        ...(bodyRes.text ? { body: bodyRes.text } : {}),
        ...(files ? { files } : {}),
        ...(omittedSecretFiles !== undefined ? { omitted_secret_files: omittedSecretFiles } : {})
      });
    }

    const hitLimit = items.length > limit;
    const boundedItems = hitLimit ? items.slice(0, limit) : items;
    const truncated = hitLimit || result.stdout_truncated;
    const reasons = [hitLimit ? "limit" : undefined, result.stdout_truncated ? "max_bytes" : undefined].filter(Boolean);

    const warnings: string[] = [];
    if (redactedSecrets) warnings.push("Redacted secret-like values in commit metadata.");
    if (totalOmittedSecretFiles > 0) warnings.push(`Omitted ${totalOmittedSecretFiles} secret-candidate file(s) from commit stats.`);
    if (hitLimit) warnings.push(`Log limited to ${limit} commits; use skip=${skip + limit} for next page.`);
    if (result.stdout_truncated) warnings.push(`Log output truncated by max_bytes (${maxBytes}).`);

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "log",
      truncated,
      ...(reasons.length > 0 ? { truncation_reason: reasons.join("+") } : {}),
      warnings,
      commits: {
        ...(ref ? { ref } : {}),
        ...(compareRef ? { compare_ref: compareRef } : {}),
        ...(rangeMode ? { range_mode: rangeMode } : {}),
        skip,
        total_returned: boundedItems.length,
        items: boundedItems
      }
    };
  }

  private async inspectDiff(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const ref = input.ref !== undefined ? validateGitRef(input.ref, "ref") : undefined;
    const compareRef = input.compare_ref !== undefined ? validateGitRef(input.compare_ref, "compare_ref") : undefined;
    const rangeMode = compareRef ? (input.range_mode ?? "three_dot") : undefined;
    const validatedPaths = await this.validateOptionalPaths(rootReal, input.paths);
    const statOnly = input.stat_only ?? false;
    const maxFiles = clampPositive(input.max_files, 50, 100);
    const maxBytes = clampPositive(input.max_bytes, DEFAULT_LIMITS.max_diff_bytes, DEFAULT_LIMITS.max_diff_bytes);

    if (!ref && !compareRef && input.staged === false && input.unstaged === false) {
      return {
        ok: true,
        repo_id: input.repo_id,
        command: "diff",
        truncated: false,
        warnings: [],
        diff: {
          staged: false,
          unstaged: false,
          stat_only: statOnly,
          files: [],
          total_file_count: 0,
          omitted_secret_files: 0
        }
      };
    }

    const numstatArgs = buildSafeDiffArgs({
      base: ref,
      compare: compareRef,
      range_mode: rangeMode,
      staged: input.staged,
      unstaged: input.unstaged,
      stat_only: true,
      paths: validatedPaths
    });
    if (!validatedPaths || validatedPaths.length === 0) {
      numstatArgs.push("--", ".", ...delegationControlArtifactGitExcludes());
    }

    const numstatResult = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args: numstatArgs,
      max_stdout_bytes: METADATA_OUTPUT_LIMIT
    });

    const filteredStats = this.filterNumstatEntries(parseNumstatZ(numstatResult.stdout));
    const totalFileCount = filteredStats.entries.length;
    const selectedStats = filteredStats.entries.slice(0, maxFiles);
    const fileLimitTruncated = selectedStats.length < totalFileCount;

    const warnings: string[] = [];
    let omittedSecretFiles = filteredStats.omittedSecretFiles;
    let bytesTruncated = false;
    let files: NonNullable<GitInspectResult["diff"]>["files"] = [];

    if (statOnly || selectedStats.length === 0) {
      files = selectedStats.map((entry) => ({
        ...entry,
        hunks: []
      }));
    } else {
      const selectedPathArgs = [...new Set(
        selectedStats.flatMap((entry) => [entry.original_path, entry.path].filter((p): p is string => Boolean(p)))
      )].sort((a, b) => a.localeCompare(b));

      const diffArgs = buildSafeDiffArgs({
        base: ref,
        compare: compareRef,
        range_mode: rangeMode,
        staged: input.staged,
        unstaged: input.unstaged,
        context_lines: input.context_lines,
        paths: selectedPathArgs
      });

      const diffResult = await runGitReadOnly({
        root: rootReal,
        root_real: rootReal,
        args: diffArgs,
        max_stdout_bytes: maxBytes,
        allow_stdout_truncation: true
      });
      bytesTruncated = diffResult.stdout_truncated;

      const filteredDiff = filterAndRedactUnifiedDiff(diffResult.stdout, this.ignoreEngine);
      omittedSecretFiles += filteredDiff.omitted_secret_files;
      if (filteredDiff.redacted_secrets) {
        warnings.push("Redacted secret-like values in diff hunks.");
      }

      const statsByPath = new Map(selectedStats.map((entry) => [entry.path, entry]));
      files = filteredDiff.files.map((file) => {
        const stat = statsByPath.get(file.path);
        return {
          path: file.path,
          ...(file.original_path ?? stat?.original_path ? { original_path: file.original_path ?? stat?.original_path } : {}),
          ...(file.status ?? stat?.status ? { status: file.status ?? stat?.status } : {}),
          ...(stat?.insertions !== undefined ? { insertions: stat.insertions } : {}),
          ...(stat?.deletions !== undefined ? { deletions: stat.deletions } : {}),
          ...(file.is_binary || stat?.is_binary ? { is_binary: true } : {}),
          hunks: file.hunks
        };
      });
    }

    if (omittedSecretFiles > 0) {
      warnings.push(`Omitted ${omittedSecretFiles} secret-candidate file(s) from diff.`);
    }
    if (fileLimitTruncated) {
      warnings.push(`Diff limited to ${selectedStats.length} of ${totalFileCount} changed files by max_files.`);
    }
    if (bytesTruncated) {
      warnings.push(`Diff content truncated by max_bytes (${maxBytes}).`);
    }

    const truncated = fileLimitTruncated || bytesTruncated;
    const reasons = [fileLimitTruncated ? "max_files" : undefined, bytesTruncated ? "max_bytes" : undefined].filter(Boolean);

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "diff",
      truncated,
      ...(reasons.length > 0 ? { truncation_reason: reasons.join("+") } : {}),
      warnings,
      diff: {
        ...(ref ? { ref } : {}),
        ...(compareRef ? { compare_ref: compareRef } : {}),
        ...(rangeMode ? { range_mode: rangeMode } : {}),
        ...(input.staged !== undefined ? { staged: input.staged } : {}),
        ...(input.unstaged !== undefined ? { unstaged: input.unstaged } : {}),
        stat_only: statOnly,
        files,
        total_file_count: totalFileCount,
        omitted_secret_files: omittedSecretFiles
      }
    };
  }

  private async inspectCommitTree(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const allRefs = input.all_refs ?? false;
    const ref = input.ref !== undefined ? validateGitRef(input.ref, "ref") : undefined;
    const validatedPaths = await this.validateOptionalPaths(rootReal, input.paths);
    const limit = clampPositive(input.limit, DEFAULT_COMMIT_TREE_LIMIT, DEFAULT_LIMITS.max_git_log_commits);
    const maxBytes = clampPositive(input.max_bytes, DEFAULT_LIMITS.max_git_show_bytes, DEFAULT_LIMITS.max_git_show_bytes);

    const commonFilters: string[] = ["--no-ext-diff", "--no-textconv", "--no-color", "--topo-order"];
    if (input.first_parent) commonFilters.push("--first-parent");

    const refArgs: string[] = [];
    if (allRefs) refArgs.push("--all");
    else if (ref) refArgs.push(ref);

    const pathArgs = validatedPaths && validatedPaths.length > 0 ? ["--", ...validatedPaths] : [];

    const nodesArgs = [
      "log",
      ...commonFilters,
      "-n",
      String(limit + 1),
      "--format=%x1e%H%x1f%h%x1f%P%x1f%D%x1f%an%x1f%aI%x1f%s",
      ...refArgs,
      ...pathArgs
    ];

    const graphArgs = [
      "log",
      ...commonFilters,
      "--graph",
      "--decorate",
      "--oneline",
      "-n",
      String(limit),
      ...refArgs,
      ...pathArgs
    ];

    const [nodesResult, graphResult] = await Promise.all([
      runGitReadOnly({
        root: rootReal,
        root_real: rootReal,
        args: nodesArgs,
        max_stdout_bytes: maxBytes,
        allow_stdout_truncation: true,
        allow_non_zero_exit: true
      }),
      runGitReadOnly({
        root: rootReal,
        root_real: rootReal,
        args: graphArgs,
        max_stdout_bytes: maxBytes,
        allow_stdout_truncation: true,
        allow_non_zero_exit: true
      })
    ]);

    if (nodesResult.exit_code !== 0) {
      if (isUnbornHeadError(nodesResult.stderr) && !ref) {
        return {
          ok: true,
          repo_id: input.repo_id,
          command: "commit_tree",
          truncated: false,
          warnings: ["Repository has no commits yet."],
          commit_tree: {
            all_refs: allRefs,
            nodes: [],
            graph_lines: []
          }
        };
      }
      throw new RepoReaderError("GIT_ERROR", nodesResult.stderr.trim() || `Git exited with ${nodesResult.exit_code}.`);
    }

    let redactedSecrets = false;
    const parsedNodes: NonNullable<GitInspectResult["commit_tree"]>["nodes"] = [];
    for (const record of nodesResult.stdout.split("\x1e")) {
      if (!record) continue;
      const fields = record.replace(/[\r\n]+$/, "").split("\x1f");
      if (fields.length < 7) continue;
      const [sha, shortSha, parentsRaw, refsRaw, authorName, authorDate, ...subjectParts] = fields;
      const subjectRes = redactGitText(subjectParts.join("\x1f").trim());
      if (subjectRes.redacted) redactedSecrets = true;
      parsedNodes.push({
        sha: sha!,
        short_sha: shortSha!,
        parents: parentsRaw ? parentsRaw.split(" ").filter(Boolean) : [],
        refs: parseDecorations(refsRaw ?? ""),
        subject: subjectRes.text,
        author_name: authorName!,
        author_date: authorDate!
      });
    }

    const hitLimit = parsedNodes.length > limit;
    const nodes = hitLimit ? parsedNodes.slice(0, limit) : parsedNodes;

    const graphLines = graphResult.exit_code === 0
      ? graphResult.stdout
          .split(/\r?\n/)
          .filter((line) => line.length > 0)
          .map((line) => {
            const res = redactGitText(line);
            if (res.redacted) redactedSecrets = true;
            return res.text;
          })
      : [];

    const bytesTruncated = nodesResult.stdout_truncated || graphResult.stdout_truncated;
    const truncated = hitLimit || bytesTruncated;
    const reasons = [hitLimit ? "limit" : undefined, bytesTruncated ? "max_bytes" : undefined].filter(Boolean);
    const warnings: string[] = [];
    if (redactedSecrets) warnings.push("Redacted secret-like values in commit tree output.");
    if (hitLimit) warnings.push(`Commit tree limited to ${limit} commits.`);
    if (bytesTruncated) warnings.push(`Commit tree output truncated by max_bytes (${maxBytes}).`);

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "commit_tree",
      truncated,
      ...(reasons.length > 0 ? { truncation_reason: reasons.join("+") } : {}),
      warnings,
      commit_tree: {
        ...(ref ? { ref } : {}),
        all_refs: allRefs,
        nodes,
        graph_lines: graphLines
      }
    };
  }

  private async inspectFileTree(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const ref = input.ref !== undefined ? validateGitRef(input.ref, "ref") : "HEAD";
    const normalizedPath = input.path !== undefined
      ? await validateGitReadPath(rootReal, input.path, this.ignoreEngine, { allowDot: true })
      : ".";
    const recursive = input.recursive ?? false;
    const maxDepth = clampPositive(
      input.max_depth,
      recursive ? DEFAULT_LIMITS.max_git_tree_depth : 1,
      DEFAULT_LIMITS.max_git_tree_depth
    );
    const limit = clampPositive(input.limit, DEFAULT_FILE_TREE_LIMIT, DEFAULT_LIMITS.max_git_tree_entries);

    const resolvedRes = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args: ["rev-parse", "--verify", "--quiet", `${ref}^{tree}`],
      max_stdout_bytes: SMALL_OUTPUT_LIMIT
    });
    const resolvedSha = resolvedRes.stdout.trim();
    if (!resolvedSha) {
      throw new RepoReaderError("GIT_ERROR", `Ref did not resolve to a tree: ${ref}`);
    }

    const baseArgs = ["ls-tree", "-z", "-l"];
    if (recursive) {
      baseArgs.push("-r", "-t");
    }
    baseArgs.push(resolvedSha);

    let lsOutput = "";
    let listedDirectory = false;
    if (normalizedPath === ".") {
      const res = await runGitReadOnly({
        root: rootReal,
        root_real: rootReal,
        args: baseArgs,
        max_stdout_bytes: METADATA_OUTPUT_LIMIT
      });
      lsOutput = res.stdout;
    } else {
      const dirRes = await runGitReadOnly({
        root: rootReal,
        root_real: rootReal,
        args: [...baseArgs, "--", `${normalizedPath}/`],
        max_stdout_bytes: METADATA_OUTPUT_LIMIT
      });
      if (dirRes.stdout.length > 0) {
        lsOutput = dirRes.stdout;
        listedDirectory = true;
      } else {
        const exactRes = await runGitReadOnly({
          root: rootReal,
          root_real: rootReal,
          args: [...baseArgs, "--", normalizedPath],
          max_stdout_bytes: METADATA_OUTPUT_LIMIT
        });
        lsOutput = exactRes.stdout;
      }
    }

    const entries: NonNullable<GitInspectResult["file_tree"]>["entries"] = [];
    const excludedSummary: Record<string, number> = {};
    let truncated = false;
    const prefixWithSlash = normalizedPath === "." ? "" : `${normalizedPath}/`;

    for (const record of lsOutput.split("\0")) {
      if (!record) continue;
      const tabIndex = record.indexOf("\t");
      if (tabIndex === -1) continue;
      const meta = record.slice(0, tabIndex).trim().split(/\s+/);
      const entryPath = record.slice(tabIndex + 1);
      if (meta.length < 4 || !entryPath) continue;
      if (listedDirectory && entryPath === normalizedPath) continue;
      const [mode, rawType, sha, rawSize] = meta;
      if (rawType !== "blob" && rawType !== "tree" && rawType !== "commit") continue;

      const relativeDepth = !listedDirectory && entryPath === normalizedPath
        ? 1
        : computeTreeDepth(entryPath, prefixWithSlash);
      if (relativeDepth > maxDepth) {
        continue;
      }

      const hidden = isHiddenGitReadPath(entryPath, this.ignoreEngine);
      if (hidden.reason === "internal_artifact") {
        continue;
      }
      if (hidden.reason === "secret_candidate") {
        excludedSummary.secret_candidates = (excludedSummary.secret_candidates ?? 0) + 1;
        continue;
      }

      if (entries.length >= limit) {
        truncated = true;
        break;
      }

      const parsedSize = rawSize !== "-" && /^\d+$/.test(rawSize!) ? Number(rawSize) : undefined;
      entries.push({
        path: entryPath,
        name: posix.basename(entryPath),
        type: rawType,
        mode: mode!,
        sha: sha!,
        ...(parsedSize !== undefined ? { size_bytes: parsedSize } : {})
      });
    }

    const warnings: string[] = [];
    if ((excludedSummary.secret_candidates ?? 0) > 0) {
      warnings.push(`Excluded ${excludedSummary.secret_candidates} secret-candidate path(s) from file tree.`);
    }
    if (truncated) {
      warnings.push(`File tree truncated to ${limit} entries.`);
    }

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "file_tree",
      truncated,
      ...(truncated ? { truncation_reason: "limit" } : {}),
      warnings,
      file_tree: {
        ref,
        resolved_sha: resolvedSha,
        path: normalizedPath,
        recursive,
        max_depth: maxDepth,
        entries,
        excluded_summary: excludedSummary
      }
    };
  }

  private async inspectShow(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const ref = input.ref !== undefined ? validateGitRef(input.ref, "ref") : "HEAD";
    const maxBytes = clampPositive(input.max_bytes, DEFAULT_LIMITS.max_git_show_bytes, DEFAULT_LIMITS.max_git_show_bytes);

    if (input.file_path !== undefined) {
      return this.inspectShowBlob(rootReal, input, ref, input.file_path, maxBytes);
    }
    return this.inspectShowCommit(rootReal, input, ref, maxBytes);
  }

  private async inspectShowBlob(
    rootReal: string,
    input: GitInspectInput,
    ref: string,
    rawFilePath: string,
    maxBytes: number
  ): Promise<GitInspectResult> {
    const filePath = await validateGitReadPath(rootReal, rawFilePath, this.ignoreEngine);
    const objectMeta = await this.resolveTreeEntryAtRef(rootReal, ref, filePath);

    const blobResult = await runGitReadOnlyBuffer({
      root: rootReal,
      root_real: rootReal,
      args: ["show", "--no-ext-diff", "--no-textconv", "--no-color", `${ref}:${filePath}`],
      max_stdout_bytes: METADATA_OUTPUT_LIMIT,
      allow_stdout_truncation: true
    });

    if (isBinaryBuffer(blobResult.stdout)) {
      throw new RepoReaderError("BINARY_FILE_REJECTED", `Binary file blocked: ${filePath}`);
    }

    const rawText = decodeUtf8Safe(blobResult.stdout, blobResult.stdout_truncated);
    if (hasEnvTemplateSecret(filePath, rawText)) {
      throw new RepoReaderError("SECRET_CANDIDATE_BLOCKED", `Secret candidate blocked: ${filePath}`);
    }

    const redacted = redactGitText(rawText);
    const lines = splitLines(redacted.text);
    const totalLines = lines.length;
    const startLine = input.start_line ?? 1;
    const requestedEndLine = input.end_line ?? totalLines;
    const endLine = totalLines === 0 ? 0 : Math.min(requestedEndLine, totalLines);
    const slicedText = totalLines === 0 || startLine > totalLines
      ? ""
      : lines.slice(startLine - 1, endLine).join("\n");

    const boundedText = truncateUtf8Bytes(slicedText, maxBytes);
    const truncated = blobResult.stdout_truncated || boundedText.truncated;
    const warnings: string[] = [];
    if (redacted.redacted) warnings.push("Redacted secret-like values in blob content.");
    if (truncated) warnings.push(`Blob content truncated by max_bytes (${maxBytes}).`);

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "show",
      truncated,
      ...(truncated ? { truncation_reason: "max_bytes" } : {}),
      warnings,
      show: {
        kind: "blob",
        ref,
        blob: {
          path: filePath,
          sha: objectMeta.sha,
          size_bytes: blobResult.stdout.byteLength,
          total_lines: totalLines,
          start_line: startLine,
          end_line: endLine,
          text: boundedText.text
        }
      }
    };
  }

  private async inspectShowCommit(
    rootReal: string,
    input: GitInspectInput,
    ref: string,
    maxBytes: number
  ): Promise<GitInspectResult> {
    const validatedPaths = await this.validateOptionalPaths(rootReal, input.paths);
    const maxFiles = clampPositive(input.max_files, 50, 100);
    const includePatch = (input.include_patch ?? false) && !(input.stat_only ?? false);

    const resolvedRes = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args: ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`],
      max_stdout_bytes: SMALL_OUTPUT_LIMIT
    });
    const resolvedCommitSha = resolvedRes.stdout.trim();
    if (!resolvedCommitSha) {
      throw new RepoReaderError("GIT_ERROR", `Ref did not resolve to a commit: ${ref}`);
    }

    const metaRes = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args: [
        "log",
        "-n",
        "1",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--format=%H%x1f%h%x1f%P%x1f%D%x1f%an%x1f%aI%x1f%cI%x1f%s%x1f%b",
        resolvedCommitSha
      ],
      max_stdout_bytes: SMALL_OUTPUT_LIMIT
    });

    const fields = metaRes.stdout.split("\x1f");
    if (fields.length < 9) {
      throw new RepoReaderError("GIT_ERROR", `Unable to parse commit metadata for ref: ${ref}`);
    }
    const [sha, shortSha, parentsRaw, refsRaw, authorName, authorDate, committerDate, subjectRaw, ...bodyParts] = fields;
    const subjectRes = redactGitText(subjectRaw!.trim());
    const bodyRes = redactGitText(bodyParts.join("\x1f").trim());

    const numstatArgs = [
      "diff-tree",
      "--root",
      "--no-commit-id",
      "--find-renames",
      "--numstat",
      "-z",
      "-r",
      "--no-ext-diff",
      "--no-textconv",
      "--no-color",
      sha!
    ];
    if (validatedPaths && validatedPaths.length > 0) {
      numstatArgs.push("--", ...validatedPaths);
    }

    const numstatRes = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args: numstatArgs,
      max_stdout_bytes: METADATA_OUTPUT_LIMIT
    });

    const filteredStats = this.filterNumstatEntries(parseNumstatZ(numstatRes.stdout));
    const totalFileCount = filteredStats.entries.length;
    const selectedStats = filteredStats.entries.slice(0, maxFiles);
    const fileLimitTruncated = selectedStats.length < totalFileCount;

    const warnings: string[] = [];
    let omittedSecretFiles = filteredStats.omittedSecretFiles;
    let redactedSecrets = subjectRes.redacted || bodyRes.redacted;
    let bytesTruncated = false;
    let files: NonNullable<NonNullable<GitInspectResult["show"]>["commit"]>["files"] = [];

    if (!includePatch || selectedStats.length === 0) {
      files = selectedStats.map((entry) => ({
        ...entry,
        hunks: []
      }));
    } else {
      const selectedPathArgs = [...new Set(
        selectedStats.flatMap((entry) => [entry.original_path, entry.path].filter((p): p is string => Boolean(p)))
      )].sort((a, b) => a.localeCompare(b));

      const contextLines = Math.max(0, Math.min(20, Math.floor(input.context_lines ?? 3)));
      const patchRes = await runGitReadOnly({
        root: rootReal,
        root_real: rootReal,
        args: [
          "show",
          "--format=",
          "--find-renames",
          "--no-ext-diff",
          "--no-textconv",
          "--no-color",
          `--unified=${contextLines}`,
          sha!,
          "--",
          ...selectedPathArgs
        ],
        max_stdout_bytes: maxBytes,
        allow_stdout_truncation: true
      });
      bytesTruncated = patchRes.stdout_truncated;

      const filteredPatch = filterAndRedactUnifiedDiff(patchRes.stdout, this.ignoreEngine);
      omittedSecretFiles += filteredPatch.omitted_secret_files;
      if (filteredPatch.redacted_secrets) redactedSecrets = true;

      const statsByPath = new Map(selectedStats.map((entry) => [entry.path, entry]));
      files = filteredPatch.files.map((file) => {
        const stat = statsByPath.get(file.path);
        return {
          path: file.path,
          ...(file.original_path ?? stat?.original_path ? { original_path: file.original_path ?? stat?.original_path } : {}),
          ...(file.status ?? stat?.status ? { status: file.status ?? stat?.status } : {}),
          ...(stat?.insertions !== undefined ? { insertions: stat.insertions } : {}),
          ...(stat?.deletions !== undefined ? { deletions: stat.deletions } : {}),
          ...(file.is_binary || stat?.is_binary ? { is_binary: true } : {}),
          hunks: file.hunks
        };
      });
    }

    if (redactedSecrets) warnings.push("Redacted secret-like values in commit details.");
    if (omittedSecretFiles > 0) warnings.push(`Omitted ${omittedSecretFiles} secret-candidate file(s) from commit details.`);
    if (fileLimitTruncated) warnings.push(`Commit files limited to ${selectedStats.length} of ${totalFileCount} by max_files.`);
    if (bytesTruncated) warnings.push(`Commit patch truncated by max_bytes (${maxBytes}).`);

    const truncated = fileLimitTruncated || bytesTruncated;
    const reasons = [fileLimitTruncated ? "max_files" : undefined, bytesTruncated ? "max_bytes" : undefined].filter(Boolean);

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "show",
      truncated,
      ...(reasons.length > 0 ? { truncation_reason: reasons.join("+") } : {}),
      warnings,
      show: {
        kind: "commit",
        ref,
        commit: {
          sha: sha!,
          short_sha: shortSha!,
          parents: parentsRaw ? parentsRaw.split(" ").filter(Boolean) : [],
          refs: parseDecorations(refsRaw ?? ""),
          author_name: authorName!,
          author_date: authorDate!,
          committer_date: committerDate!,
          subject: subjectRes.text,
          body: bodyRes.text,
          files,
          total_file_count: totalFileCount,
          omitted_secret_files: omittedSecretFiles
        }
      }
    };
  }

  private async inspectBlame(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const ref = input.ref !== undefined ? validateGitRef(input.ref, "ref") : "HEAD";
    const filePath = await validateGitReadPath(rootReal, input.file_path!, this.ignoreEngine);
    const maxBytes = clampPositive(input.max_bytes, DEFAULT_LIMITS.max_git_show_bytes, DEFAULT_LIMITS.max_git_show_bytes);

    await this.resolveTreeEntryAtRef(rootReal, ref, filePath);

    const blobCheck = await runGitReadOnlyBuffer({
      root: rootReal,
      root_real: rootReal,
      args: ["show", "--no-ext-diff", "--no-textconv", "--no-color", `${ref}:${filePath}`],
      max_stdout_bytes: METADATA_OUTPUT_LIMIT,
      allow_stdout_truncation: true
    });
    if (isBinaryBuffer(blobCheck.stdout)) {
      throw new RepoReaderError("BINARY_FILE_REJECTED", `Binary file blocked: ${filePath}`);
    }
    const blobText = decodeUtf8Safe(blobCheck.stdout, blobCheck.stdout_truncated);
    if (hasEnvTemplateSecret(filePath, blobText)) {
      throw new RepoReaderError("SECRET_CANDIDATE_BLOCKED", `Secret candidate blocked: ${filePath}`);
    }

    const totalFileLines = countLines(blobText);
    const startLine = input.start_line ?? 1;
    const defaultEnd = startLine + DEFAULT_BLAME_WINDOW - 1;
    const requestedEnd = input.end_line ?? defaultEnd;
    const maxAllowedEnd = startLine + DEFAULT_LIMITS.max_git_blame_lines - 1;
    const cappedEnd = Math.min(requestedEnd, maxAllowedEnd);

    if (totalFileLines === 0 || startLine > totalFileLines) {
      return {
        ok: true,
        repo_id: input.repo_id,
        command: "blame",
        truncated: false,
        warnings: [],
        blame: {
          ref,
          path: filePath,
          start_line: startLine,
          end_line: 0,
          total_lines: 0,
          lines: []
        }
      };
    }

    const effectiveEnd = Math.min(cappedEnd, totalFileLines);
    const blameRes = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args: ["blame", "--porcelain", `-L${startLine},${effectiveEnd}`, ref, "--", filePath],
      max_stdout_bytes: maxBytes,
      allow_stdout_truncation: true
    });

    const parsedBlame = parsePorcelainBlame(blameRes.stdout);
    const windowTruncated = effectiveEnd < totalFileLines && input.end_line === undefined;
    const truncated = windowTruncated || blameRes.stdout_truncated;
    const reasons = [windowTruncated ? "line_limit" : undefined, blameRes.stdout_truncated ? "max_bytes" : undefined].filter(Boolean);

    const warnings: string[] = [];
    if (parsedBlame.redactedSecrets) warnings.push("Redacted secret-like values in blame output.");
    if (windowTruncated) warnings.push(`Blame bounded to lines ${startLine}..${effectiveEnd} of ${totalFileLines}.`);
    if (blameRes.stdout_truncated) warnings.push(`Blame output truncated by max_bytes (${maxBytes}).`);

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "blame",
      truncated,
      ...(reasons.length > 0 ? { truncation_reason: reasons.join("+") } : {}),
      warnings,
      blame: {
        ref,
        path: filePath,
        start_line: startLine,
        end_line: parsedBlame.lines.at(-1)?.line_number ?? effectiveEnd,
        total_lines: parsedBlame.lines.length,
        lines: parsedBlame.lines
      }
    };
  }

  private async inspectRevParse(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const rawRefs = input.refs ?? [];
    if (rawRefs.length > DEFAULT_LIMITS.max_git_rev_parse_refs) {
      throw new RepoReaderError("VALIDATION_ERROR", `At most ${DEFAULT_LIMITS.max_git_rev_parse_refs} refs may be resolved per call.`);
    }
    const validatedRefs = rawRefs.map((ref) => validateGitRef(ref, "refs"));
    const items: NonNullable<GitInspectResult["resolved_refs"]>["items"] = [];

    for (const ref of validatedRefs) {
      const verifyRes = await runGitReadOnly({
        root: rootReal,
        root_real: rootReal,
        args: ["rev-parse", "--verify", "--quiet", `${ref}^{object}`],
        max_stdout_bytes: SMALL_OUTPUT_LIMIT,
        allow_non_zero_exit: true
      });
      const sha = verifyRes.stdout.trim();
      if (verifyRes.exit_code !== 0 || !sha) {
        items.push({ ref, resolved: false, error: "REF_NOT_FOUND" });
        continue;
      }
      const typeRes = await runGitReadOnly({
        root: rootReal,
        root_real: rootReal,
        args: ["cat-file", "-t", sha],
        max_stdout_bytes: SMALL_OUTPUT_LIMIT
      });
      items.push({
        ref,
        resolved: true,
        sha,
        short_sha: sha.slice(0, 7),
        object_type: typeRes.stdout.trim()
      });
    }

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "rev_parse",
      truncated: false,
      warnings: [],
      resolved_refs: { items }
    };
  }

  private async inspectMergeBase(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const ref = validateGitRef(input.ref!, "ref");
    const compareRef = validateGitRef(input.compare_ref!, "compare_ref");

    const baseRes = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args: ["merge-base", ref, compareRef],
      max_stdout_bytes: SMALL_OUTPUT_LIMIT
    });
    const sha = baseRes.stdout.trim().split(/\r?\n/)[0]?.trim();
    if (!sha) {
      throw new RepoReaderError("GIT_ERROR", "No common merge base found between the specified refs.");
    }

    const metaRes = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args: [
        "show",
        "--no-patch",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--format=%H%x1f%h%x1f%an%x1f%aI%x1f%s",
        sha
      ],
      max_stdout_bytes: SMALL_OUTPUT_LIMIT
    });

    const fields = metaRes.stdout.replace(/[\r\n]+$/, "").split("\x1f");
    if (fields.length < 5) {
      throw new RepoReaderError("GIT_ERROR", "Unable to read merge-base commit metadata.");
    }
    const [fullSha, shortSha, authorName, authorDate, ...subjectParts] = fields;
    const subjectRes = redactGitText(subjectParts.join("\x1f").trim());

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "merge_base",
      truncated: false,
      warnings: subjectRes.redacted ? ["Redacted secret-like values in merge-base commit subject."] : [],
      merge_base: {
        ref,
        compare_ref: compareRef,
        sha: fullSha!,
        short_sha: shortSha!,
        subject: subjectRes.text,
        author_name: authorName!,
        author_date: authorDate!
      }
    };
  }

  private async inspectShortlog(rootReal: string, input: GitInspectInput): Promise<GitInspectResult> {
    const ref = input.ref !== undefined ? validateGitRef(input.ref, "ref") : undefined;
    const compareRef = input.compare_ref !== undefined ? validateGitRef(input.compare_ref, "compare_ref") : undefined;
    const rangeMode = compareRef ? (input.range_mode ?? "two_dot") : undefined;
    const since = input.since !== undefined ? validateGitDateSpec(input.since, "since") : undefined;
    const until = input.until !== undefined ? validateGitDateSpec(input.until, "until") : undefined;
    const validatedPaths = await this.validateOptionalPaths(rootReal, input.paths);
    const limit = clampPositive(input.limit, DEFAULT_SHORTLOG_LIMIT, DEFAULT_LIMITS.max_git_refs);

    const args = ["shortlog", "-s", "-n"];
    if (since) args.push(`--since=${since}`);
    if (until) args.push(`--until=${until}`);
    if (input.first_parent) args.push("--first-parent");
    if (input.merges === "only") args.push("--merges");
    else if (input.merges === "exclude") args.push("--no-merges");

    if (ref && compareRef) {
      args.push(`${ref}${rangeMode === "three_dot" ? "..." : ".."}${compareRef}`);
    } else {
      args.push(ref ?? "HEAD");
    }

    if (validatedPaths && validatedPaths.length > 0) {
      args.push("--", ...validatedPaths);
    }

    const res = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args,
      max_stdout_bytes: METADATA_OUTPUT_LIMIT,
      allow_non_zero_exit: true
    });

    if (res.exit_code !== 0) {
      if (isUnbornHeadError(res.stderr) && !ref) {
        return {
          ok: true,
          repo_id: input.repo_id,
          command: "shortlog",
          truncated: false,
          warnings: ["Repository has no commits yet."],
          shortlog: {
            total_commits: 0,
            contributors: []
          }
        };
      }
      throw new RepoReaderError("GIT_ERROR", res.stderr.trim() || `Git exited with ${res.exit_code}.`);
    }

    const allContributors: Array<{ author_name: string; commits: number }> = [];
    for (const line of res.stdout.split(/\r?\n/)) {
      const match = line.match(/^\s*(\d+)\t(.+)$/);
      if (!match) continue;
      allContributors.push({
        author_name: redactGitText(match[2]!.trim()).text,
        commits: Number(match[1])
      });
    }

    const truncated = allContributors.length > limit;
    const contributors = truncated ? allContributors.slice(0, limit) : allContributors;
    const totalCommits = contributors.reduce((sum, entry) => sum + entry.commits, 0);

    return {
      ok: true,
      repo_id: input.repo_id,
      command: "shortlog",
      truncated,
      ...(truncated ? { truncation_reason: "limit" } : {}),
      warnings: truncated ? [`Shortlog truncated to top ${limit} of ${allContributors.length} contributors.`] : [],
      shortlog: {
        ...(ref ? { ref } : {}),
        ...(compareRef ? { compare_ref: compareRef } : {}),
        ...(rangeMode ? { range_mode: rangeMode } : {}),
        total_commits: totalCommits,
        contributors
      }
    };
  }

  private async validateOptionalPaths(rootReal: string, paths: readonly string[] | undefined): Promise<string[] | undefined> {
    if (!paths || paths.length === 0) return undefined;
    const validated: string[] = [];
    for (const rawPath of paths) {
      validated.push(await validateGitReadPath(rootReal, rawPath, this.ignoreEngine));
    }
    return [...new Set(validated)].sort((a, b) => a.localeCompare(b));
  }

  private async resolveTreeEntryAtRef(
    rootReal: string,
    ref: string,
    filePath: string
  ): Promise<{ mode: string; type: string; sha: string }> {
    const lsRes = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args: ["ls-tree", "-z", ref, "--", filePath],
      max_stdout_bytes: SMALL_OUTPUT_LIMIT
    });
    const record = lsRes.stdout.split("\0").find(Boolean);
    if (!record) {
      throw new RepoReaderError("GIT_ERROR", `Path not found at ref ${ref}: ${filePath}`);
    }
    const tabIndex = record.indexOf("\t");
    if (tabIndex === -1) {
      throw new RepoReaderError("GIT_ERROR", `Unable to inspect tree entry at ref ${ref}: ${filePath}`);
    }
    const [mode, type, sha] = record.slice(0, tabIndex).trim().split(/\s+/);
    if (!mode || !type || !sha) {
      throw new RepoReaderError("GIT_ERROR", `Malformed tree entry at ref ${ref}: ${filePath}`);
    }
    if (mode === "120000") {
      throw new RepoReaderError("UNSUPPORTED_FILE_TYPE", `Symlink entries cannot be inspected directly: ${filePath}`);
    }
    if (type !== "blob") {
      throw new RepoReaderError("UNSUPPORTED_FILE_TYPE", `Path is not a regular file blob at ref ${ref}: ${filePath}`);
    }
    return { mode, type, sha };
  }

  private filterNumstatEntries(entries: NumstatEntry[]): { entries: NumstatEntry[]; omittedSecretFiles: number } {
    const safe: NumstatEntry[] = [];
    let omittedSecretFiles = 0;

    for (const entry of entries) {
      const pathHidden = isHiddenGitReadPath(entry.path, this.ignoreEngine);
      const origHidden = entry.original_path
        ? isHiddenGitReadPath(entry.original_path, this.ignoreEngine)
        : { hidden: false as const };

      if (pathHidden.reason === "internal_artifact" || origHidden.reason === "internal_artifact") {
        continue;
      }
      if (pathHidden.reason === "secret_candidate" || origHidden.reason === "secret_candidate") {
        omittedSecretFiles += 1;
        continue;
      }
      safe.push(entry);
    }

    return { entries: safe, omittedSecretFiles };
  }
}

async function detectRepoOperationState(
  rootReal: string
): Promise<"merging" | "rebasing" | "cherry_picking" | "reverting" | "bisecting" | undefined> {
  const dotGit = join(rootReal, ".git");
  try {
    const stat = await lstat(dotGit);
    if (!stat.isDirectory()) {
      return undefined;
    }
  } catch {
    return undefined;
  }

  const checks: Array<[string, "merging" | "rebasing" | "cherry_picking" | "reverting" | "bisecting"]> = [
    ["MERGE_HEAD", "merging"],
    ["rebase-merge", "rebasing"],
    ["rebase-apply", "rebasing"],
    ["CHERRY_PICK_HEAD", "cherry_picking"],
    ["REVERT_HEAD", "reverting"],
    ["BISECT_LOG", "bisecting"]
  ];

  for (const [marker, state] of checks) {
    try {
      await access(join(dotGit, marker));
      return state;
    } catch {
      // Marker not present.
    }
  }
  return undefined;
}

function parsePorcelainV2Status(stdout: string): {
  branch: string;
  head_sha: string;
  detached: boolean;
  upstream?: string;
  ahead: number;
  behind: number;
  files: ParsedStatusEntry[];
} {
  let branch = "HEAD";
  let headSha = "unborn";
  let detached = false;
  let upstream: string | undefined;
  let ahead = 0;
  let behind = 0;
  const files: ParsedStatusEntry[] = [];

  const tokens = stdout.split("\0");
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (!token) continue;

    if (token.startsWith("# ")) {
      if (token.startsWith("# branch.oid ")) {
        const oid = token.slice("# branch.oid ".length).trim();
        headSha = oid === "(initial)" ? "unborn" : oid;
      } else if (token.startsWith("# branch.head ")) {
        const headName = token.slice("# branch.head ".length).trim();
        if (headName === "(detached)") {
          detached = true;
          branch = "HEAD";
        } else {
          detached = false;
          branch = headName;
        }
      } else if (token.startsWith("# branch.upstream ")) {
        upstream = token.slice("# branch.upstream ".length).trim() || undefined;
      } else if (token.startsWith("# branch.ab ")) {
        const match = token.slice("# branch.ab ".length).trim().match(/^\+(\d+)\s+-(\d+)$/);
        if (match) {
          ahead = Number(match[1]);
          behind = Number(match[2]);
        }
      }
      continue;
    }

    if (token.startsWith("1 ")) {
      const split = splitFirstN(token, " ", 8);
      if (split.length < 9) continue;
      const xy = split[1]!;
      const path = split[8]!;
      const index = normalizePorcelainChar(xy[0] ?? ".");
      const worktree = normalizePorcelainChar(xy[1] ?? ".");
      files.push({
        path,
        index,
        worktree,
        status: classifyPorcelainStatus(index, worktree, false),
        staged: index !== " ",
        unstaged: worktree !== " "
      });
      continue;
    }

    if (token.startsWith("2 ")) {
      const split = splitFirstN(token, " ", 9);
      if (split.length < 10) continue;
      const xy = split[1]!;
      const path = split[9]!;
      const origPath = tokens[i + 1];
      if (origPath !== undefined) i += 1;
      const index = normalizePorcelainChar(xy[0] ?? ".");
      const worktree = normalizePorcelainChar(xy[1] ?? ".");
      files.push({
        path,
        ...(origPath ? { original_path: origPath } : {}),
        index,
        worktree,
        status: classifyPorcelainStatus(index, worktree, false),
        staged: index !== " ",
        unstaged: worktree !== " "
      });
      continue;
    }

    if (token.startsWith("u ")) {
      const split = splitFirstN(token, " ", 10);
      if (split.length < 11) continue;
      const xy = split[1]!;
      const path = split[10]!;
      const index = normalizePorcelainChar(xy[0] ?? ".");
      const worktree = normalizePorcelainChar(xy[1] ?? ".");
      files.push({
        path,
        index,
        worktree,
        status: "unmerged",
        staged: index !== " ",
        unstaged: worktree !== " "
      });
      continue;
    }

    if (token.startsWith("? ")) {
      const path = token.slice(2);
      if (isDelegationControlArtifact(path)) continue;
      files.push({
        path,
        index: "?",
        worktree: "?",
        status: "untracked",
        staged: false,
        unstaged: true
      });
    }
  }

  return { branch, head_sha: headSha, detached, upstream, ahead, behind, files };
}

function normalizePorcelainChar(ch: string): string {
  return ch === "." ? " " : ch;
}

function classifyPorcelainStatus(
  index: string,
  worktree: string,
  unmerged: boolean
): ParsedStatusEntry["status"] {
  if (unmerged) return "unmerged";
  if (index === "?" && worktree === "?") return "untracked";
  if (index === "R" || worktree === "R") return "renamed";
  if (index === "C" || worktree === "C") return "copied";
  if (index === "D" || worktree === "D") return "deleted";
  if (index === "A" || worktree === "A") return "added";
  if (index === "M" || worktree === "M") return "modified";
  return "unknown";
}

function splitFirstN(text: string, sep: string, maxSplits: number): string[] {
  const parts: string[] = [];
  let start = 0;
  for (let count = 0; count < maxSplits; count += 1) {
    const idx = text.indexOf(sep, start);
    if (idx === -1) break;
    parts.push(text.slice(start, idx));
    start = idx + sep.length;
  }
  parts.push(text.slice(start));
  return parts;
}

function parseNumstatZ(raw: string): NumstatEntry[] {
  const tokens = raw.split("\0");
  const entries: NumstatEntry[] = [];

  for (let i = 0; i < tokens.length; i += 1) {
    const rawToken = tokens[i];
    if (!rawToken) continue;
    const token = rawToken.replace(/^\r?\n/, "");
    if (!token) continue;
    const firstTab = token.indexOf("\t");
    if (firstTab === -1) continue;
    const secondTab = token.indexOf("\t", firstTab + 1);
    if (secondTab === -1) continue;

    const insRaw = token.slice(0, firstTab);
    const delRaw = token.slice(firstTab + 1, secondTab);
    const pathPart = token.slice(secondTab + 1);
    const isBinary = insRaw === "-" && delRaw === "-";
    const insertions = !isBinary && /^\d+$/.test(insRaw) ? Number(insRaw) : undefined;
    const deletions = !isBinary && /^\d+$/.test(delRaw) ? Number(delRaw) : undefined;

    if (pathPart === "") {
      // Rename/copy format under --numstat -z: "<ins>\t<del>\t\0<old>\0<new>\0"
      const origPath = tokens[i + 1];
      const newPath = tokens[i + 2];
      if (!origPath || !newPath) continue;
      i += 2;
      entries.push({
        path: newPath,
        original_path: origPath,
        status: "renamed",
        ...(insertions !== undefined ? { insertions } : {}),
        ...(deletions !== undefined ? { deletions } : {}),
        ...(isBinary ? { is_binary: true } : {})
      });
    } else {
      entries.push({
        path: pathPart,
        ...(insertions !== undefined ? { insertions } : {}),
        ...(deletions !== undefined ? { deletions } : {}),
        ...(isBinary ? { is_binary: true } : {})
      });
    }
  }

  return entries;
}

function parsePorcelainBlame(raw: string): {
  lines: NonNullable<GitInspectResult["blame"]>["lines"];
  redactedSecrets: boolean;
} {
  const lines: NonNullable<GitInspectResult["blame"]>["lines"] = [];
  const metaBySha = new Map<string, { author_name: string; author_time: string; summary: string }>();
  let redactedSecrets = false;

  let currentSha: string | undefined;
  let currentLineNumber: number | undefined;
  let currentMeta: { author_name: string; author_time: string; summary: string } | undefined;

  for (const rawLine of raw.split(/\r?\n/)) {
    if (!rawLine && currentSha === undefined) continue;

    if (rawLine.startsWith("\t")) {
      if (currentSha && currentLineNumber !== undefined) {
        const meta = currentMeta ?? metaBySha.get(currentSha) ?? {
          author_name: "Unknown",
          author_time: "",
          summary: ""
        };
        metaBySha.set(currentSha, meta);
        const contentRes = redactGitText(rawLine.slice(1));
        if (contentRes.redacted) redactedSecrets = true;
        lines.push({
          line_number: currentLineNumber,
          sha: currentSha,
          short_sha: currentSha.slice(0, 7),
          author_name: meta.author_name,
          author_time: meta.author_time,
          summary: meta.summary,
          content: contentRes.text
        });
      }
      currentSha = undefined;
      currentLineNumber = undefined;
      currentMeta = undefined;
      continue;
    }

    if (!currentSha) {
      const headerMatch = rawLine.match(/^([0-9a-f]{40})\s+\d+\s+(\d+)(?:\s+\d+)?$/);
      if (headerMatch) {
        currentSha = headerMatch[1]!;
        currentLineNumber = Number(headerMatch[2]);
        const cached = metaBySha.get(currentSha);
        currentMeta = cached ? { ...cached } : { author_name: "Unknown", author_time: "", summary: "" };
      }
      continue;
    }

    if (currentMeta) {
      if (rawLine.startsWith("author ")) {
        currentMeta.author_name = rawLine.slice("author ".length).trim();
      } else if (rawLine.startsWith("author-time ")) {
        const epochSec = Number(rawLine.slice("author-time ".length).trim());
        if (Number.isFinite(epochSec)) {
          currentMeta.author_time = new Date(epochSec * 1000).toISOString();
        }
      } else if (rawLine.startsWith("summary ")) {
        const summaryRes = redactGitText(rawLine.slice("summary ".length).trim());
        if (summaryRes.redacted) redactedSecrets = true;
        currentMeta.summary = summaryRes.text;
      }
    }
  }

  return { lines, redactedSecrets };
}

function parseDecorations(raw: string): string[] {
  return raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function matchGlob(pattern: string, value: string): boolean {
  let p = 0;
  let v = 0;
  let starIdx = -1;
  let matchIdx = 0;

  while (v < value.length) {
    if (p < pattern.length && (pattern[p] === "?" || pattern[p] === value[v])) {
      p += 1;
      v += 1;
    } else if (p < pattern.length && pattern[p] === "*") {
      starIdx = p;
      matchIdx = v;
      p += 1;
    } else if (starIdx !== -1) {
      p = starIdx + 1;
      matchIdx += 1;
      v = matchIdx;
    } else {
      return false;
    }
  }

  while (p < pattern.length && pattern[p] === "*") {
    p += 1;
  }
  return p === pattern.length;
}

function computeTreeDepth(entryPath: string, prefixWithSlash: string): number {
  const relative = prefixWithSlash && entryPath.startsWith(prefixWithSlash)
    ? entryPath.slice(prefixWithSlash.length)
    : entryPath;
  return relative.split("/").filter(Boolean).length;
}

function splitLines(text: string): string[] {
  if (text.length === 0) return [];
  const normalized = text.endsWith("\r\n")
    ? text.slice(0, -2)
    : text.endsWith("\n")
      ? text.slice(0, -1)
      : text;
  if (normalized.length === 0) return [""];
  return normalized.split(/\r?\n/);
}

function countLines(text: string): number {
  return splitLines(text).length;
}

function clampPositive(value: number | undefined, fallback: number, max: number): number {
  if (value === undefined || !Number.isFinite(value) || value <= 0) {
    return Math.min(fallback, max);
  }
  return Math.max(1, Math.min(Math.floor(value), max));
}

function isUnbornHeadError(stderr: string): boolean {
  return /does not have any commits yet|ambiguous argument 'HEAD'|unknown revision or path not in the working tree/i.test(stderr);
}
