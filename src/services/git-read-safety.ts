import { lstat, realpath } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { isDelegationControlArtifact } from "../policies/delegation-control-artifacts.js";
import { RepoReaderError } from "../runtime/errors.js";
import { isNotFoundError } from "../runtime/fs-helpers.js";
import { decodeUtf8Safe, runGitReadOnly } from "./git-exec.js";
import { assertExistingParentWithinRoot } from "./git-operation-safety.js";
import { IgnoreEngine, isPublicEnvTemplatePath, normalizeRepoPath } from "./ignore-engine.js";
import { PathSandbox, validateRepoPath } from "./path-sandbox.js";
import { SecretScanner } from "./secret-scanner.js";

const DEFAULT_IGNORE_ENGINE = new IgnoreEngine();
const SECRET_SCANNER = new SecretScanner();

const SAFE_GIT_REF_CHARS = /^[A-Za-z0-9._/@+~^-]+$/;
const SAFE_GIT_PATTERN_CHARS = /^[A-Za-z0-9._/*?+-]+$/;
const ISO_DATE_SPEC_REGEX = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)?$/;
const UNIX_TIMESTAMP_REGEX = /^\d{9,12}$/;
const RELATIVE_DATE_SPEC_REGEX = /^(?:today|yesterday|now|\d{1,4}\s+(?:second|minute|hour|day|week|month|year)s?\s+ago)$/i;

function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function containsDotGitSegment(repoPath: string): boolean {
  return normalizeRepoPath(repoPath)
    .split("/")
    .some((segment) => segment.toLowerCase() === ".git");
}

export type HiddenGitReadPathResult = {
  hidden: boolean;
  reason?: "internal_artifact" | "secret_candidate";
};

export type SafeDiffArgsOptions = {
  base?: string;
  compare?: string;
  range_mode?: "two_dot" | "three_dot";
  staged?: boolean;
  unstaged?: boolean;
  context_lines?: number;
  names_only?: boolean;
  stat_only?: boolean;
  paths?: readonly string[];
};

export type ParsedDiffFile = {
  path: string;
  original_path?: string;
  status?: string;
  is_binary?: boolean;
  hunks: string[];
};

export type FilteredUnifiedDiffResult = {
  files: ParsedDiffFile[];
  omitted_secret_files: number;
  omitted_internal_files: number;
  redacted_secrets: boolean;
};

export async function assertGitRepoConfined(rootPath: string): Promise<string> {
  const rootReal = await realpath(rootPath);
  let topLevelRaw: string;
  try {
    const result = await runGitReadOnly({
      root: rootReal,
      root_real: rootReal,
      args: ["rev-parse", "--show-toplevel"],
      max_stdout_bytes: 64 * 1024
    });
    topLevelRaw = result.stdout.trim();
  } catch {
    throw new RepoReaderError("GIT_ERROR", "Approved repository root is not a Git repository root.");
  }

  if (!topLevelRaw) {
    throw new RepoReaderError("GIT_ERROR", "Approved repository root is not a Git repository root.");
  }

  let topLevelReal: string;
  try {
    topLevelReal = await realpath(topLevelRaw);
  } catch {
    throw new RepoReaderError("GIT_ERROR", "Approved repository root is not a Git repository root.");
  }

  if (normalizePathForCompare(rootReal) !== normalizePathForCompare(topLevelReal)) {
    throw new RepoReaderError(
      "GIT_ERROR",
      "Approved repository root must match the Git repository top-level directory."
    );
  }

  return rootReal;
}

export function validateGitRef(ref: string, fieldName = "ref"): string {
  if (typeof ref !== "string" || ref.length === 0 || ref.length > 256) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: must be a non-empty ref up to 256 characters.`);
  }
  if (ref.startsWith("-")) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: leading '-' is not allowed.`);
  }
  if (hasControlChar(ref) || /\s/.test(ref)) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: whitespace and control characters are not allowed.`);
  }
  if (
    ref === "."
    || ref.startsWith("/")
    || ref.endsWith(".")
    || ref.endsWith(".lock")
    || ref.endsWith("/")
    || ref.includes("..")
    || ref.includes("//")
    || ref.includes("@{")
    || /[:\\*?[\]{}]/.test(ref)
    || !SAFE_GIT_REF_CHARS.test(ref)
  ) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: unsafe Git revision syntax rejected.`);
  }
  return ref;
}

export async function validateGitReadPath(
  rootPath: string,
  rawPath: string,
  ignoreEngine: IgnoreEngine = DEFAULT_IGNORE_ENGINE,
  options: { checkWorktreeSymlink?: boolean; allowDot?: boolean } = {}
): Promise<string> {
  if (typeof rawPath !== "string" || rawPath.length === 0) {
    throw new RepoReaderError("GIT_OPERATION_UNSAFE_PATHSPEC", "Empty git pathspec rejected.");
  }
  if (hasControlChar(rawPath)) {
    throw new RepoReaderError("GIT_OPERATION_UNSAFE_PATHSPEC", "Unsafe git pathspec rejected: control characters are not allowed.");
  }
  if (rawPath.startsWith("\\\\") || rawPath.startsWith("//")) {
    throw new RepoReaderError("ABSOLUTE_PATH_REJECTED", "Absolute or UNC paths are not allowed.");
  }
  if (rawPath.startsWith("-") || rawPath.startsWith(":")) {
    throw new RepoReaderError("GIT_OPERATION_UNSAFE_PATHSPEC", "Unsafe git pathspec rejected: leading '-' or ':' is not allowed.");
  }

  const normalized = validateRepoPath(rawPath);
  if (normalized.startsWith("-") || normalized.startsWith(":")) {
    throw new RepoReaderError("GIT_OPERATION_UNSAFE_PATHSPEC", "Unsafe git pathspec rejected: leading '-' or ':' is not allowed.");
  }
  if (normalized === "." && !options.allowDot) {
    throw new RepoReaderError("GIT_OPERATION_UNSAFE_PATHSPEC", "Unsafe git pathspec rejected: '.' is not allowed here.");
  }

  if (containsDotGitSegment(normalized)) {
    throw new RepoReaderError("GIT_OPERATION_UNSAFE_PATHSPEC", "Git internals cannot be inspected.");
  }

  if (isDelegationControlArtifact(normalized)) {
    throw new RepoReaderError("INTERNAL_ARTIFACT_BLOCKED", "Internal delegation control artifact blocked.");
  }
  if (ignoreEngine.isSensitiveCandidate(normalized)) {
    throw new RepoReaderError("SECRET_CANDIDATE_BLOCKED", `Secret candidate blocked: ${normalized}`);
  }

  if ((options.checkWorktreeSymlink ?? true) && normalized !== ".") {
    const absolutePath = join(rootPath, normalized);
    let exists = false;
    try {
      await lstat(absolutePath);
      exists = true;
    } catch (error) {
      if (!isNotFoundError(error)) {
        throw error;
      }
    }

    if (exists) {
      const rootReal = await realpath(rootPath);
      const sandbox = new PathSandbox(rootReal);
      const resolved = await sandbox.resolve(normalized);
      const realRepoPath = normalizeRepoPath(relative(rootReal, resolved.absolutePath));
      if (containsDotGitSegment(realRepoPath)) {
        throw new RepoReaderError("GIT_OPERATION_UNSAFE_PATHSPEC", "Git internals cannot be inspected.");
      }
      if (isDelegationControlArtifact(realRepoPath)) {
        throw new RepoReaderError("INTERNAL_ARTIFACT_BLOCKED", "Internal delegation control artifact blocked.");
      }
      if (ignoreEngine.isSensitiveCandidate(realRepoPath)) {
        throw new RepoReaderError("SECRET_CANDIDATE_BLOCKED", "Secret candidate blocked.");
      }
    } else {
      await assertExistingParentWithinRoot(rootPath, normalized);
    }
  }

  return normalized;
}

export function validateGitPattern(pattern: string, fieldName = "pattern"): string {
  if (typeof pattern !== "string" || pattern.length === 0 || pattern.length > 128) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: must be a non-empty pattern up to 128 characters.`);
  }
  if (pattern.startsWith("-")) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: leading '-' is not allowed.`);
  }
  if (
    hasControlChar(pattern)
    || /\s/.test(pattern)
    || pattern.includes(":")
    || pattern.includes("\\")
    || pattern.includes("..")
    || !SAFE_GIT_PATTERN_CHARS.test(pattern)
  ) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: unsafe pattern syntax rejected.`);
  }
  return pattern;
}

export function validateGitFilterText(value: string, fieldName = "filter"): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 200) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: must be a non-empty string up to 200 characters.`);
  }
  if (value.startsWith("-")) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: leading '-' is not allowed.`);
  }
  if (hasControlChar(value)) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: control characters are not allowed.`);
  }
  return value;
}

export function validateGitDateSpec(value: string, fieldName = "date"): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 64) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: must be a non-empty date up to 64 characters.`);
  }
  if (value.startsWith("-") || hasControlChar(value)) {
    throw new RepoReaderError("VALIDATION_ERROR", `Invalid ${fieldName}: unsafe date value rejected.`);
  }
  const trimmed = value.trim();
  if (
    trimmed !== value
    || (!ISO_DATE_SPEC_REGEX.test(trimmed) && !UNIX_TIMESTAMP_REGEX.test(trimmed) && !RELATIVE_DATE_SPEC_REGEX.test(trimmed))
  ) {
    throw new RepoReaderError(
      "VALIDATION_ERROR",
      `Invalid ${fieldName}: expected ISO-8601 date, Unix timestamp, or relative time (e.g. '7 days ago').`
    );
  }
  return value;
}

export function isHiddenGitReadPath(
  repoPath: string,
  ignoreEngine: IgnoreEngine = DEFAULT_IGNORE_ENGINE
): HiddenGitReadPathResult {
  const normalized = normalizeRepoPath(repoPath).replace(/^\.\//, "");
  if (!normalized) {
    return { hidden: false };
  }
  if (isDelegationControlArtifact(normalized)) {
    return { hidden: true, reason: "internal_artifact" };
  }
  if (ignoreEngine.isSensitiveCandidate(normalized)) {
    return { hidden: true, reason: "secret_candidate" };
  }
  const base = normalized.toLowerCase().split("/").at(-1) ?? "";
  if (!isPublicEnvTemplatePath(normalized) && /^\.env[^a-z0-9_-]/i.test(base)) {
    return { hidden: true, reason: "secret_candidate" };
  }
  return { hidden: false };
}

export function redactGitText(text: string): { text: string; redacted: boolean } {
  const redacted = SECRET_SCANNER.redact(text);
  return { text: redacted, redacted: redacted !== text };
}

export function hasEnvTemplateSecret(repoPath: string, text: string): boolean {
  const normalized = normalizeRepoPath(repoPath).replace(/^\.\//, "");
  return isPublicEnvTemplatePath(normalized) && SECRET_SCANNER.hasSecretValue(text);
}

export function isBinaryBuffer(buf: Buffer): boolean {
  return buf.subarray(0, Math.min(buf.length, 8192)).includes(0);
}

export function truncateUtf8Bytes(text: string, maxBytes: number): { text: string; truncated: boolean } {
  if (maxBytes <= 0) {
    return { text: "", truncated: text.length > 0 };
  }
  const buffer = Buffer.from(text, "utf8");
  if (buffer.byteLength <= maxBytes) {
    return { text, truncated: false };
  }
  return {
    text: decodeUtf8Safe(buffer.subarray(0, maxBytes), true),
    truncated: true
  };
}

export function buildSafeDiffArgs(options: SafeDiffArgsOptions): string[] {
  const base = options.base !== undefined ? validateGitRef(options.base, "base") : undefined;
  const compare = options.compare !== undefined ? validateGitRef(options.compare, "compare") : undefined;
  const rangeMode = options.range_mode ?? "three_dot";
  const contextLines = clampContextLines(options.context_lines);

  if (compare && !base) {
    throw new RepoReaderError("VALIDATION_ERROR", "compare cannot be specified without base.");
  }

  const args = ["diff", "--find-renames", "--no-ext-diff", "--no-textconv", "--no-color"];
  if (options.names_only) {
    args.push("--name-only", "-z");
  } else if (options.stat_only) {
    args.push("--numstat", "-z");
  } else {
    args.push(`--unified=${contextLines}`);
  }

  if (base && compare) {
    const separator = rangeMode === "two_dot" ? ".." : "...";
    args.push(`${base}${separator}${compare}`);
  } else if (base) {
    if (options.staged === true && options.unstaged !== true) {
      args.push("--cached");
    }
    args.push(base);
  } else if (options.staged === true && options.unstaged === true) {
    args.push("HEAD");
  } else if (options.staged === true) {
    args.push("--cached");
  }

  if (options.paths && options.paths.length > 0) {
    args.push("--", ...options.paths);
  }
  return args;
}

export function filterAndRedactUnifiedDiff(
  rawDiff: string,
  ignoreEngine: IgnoreEngine = DEFAULT_IGNORE_ENGINE
): FilteredUnifiedDiffResult {
  const parsed = parseUnifiedDiff(rawDiff);
  const files: ParsedDiffFile[] = [];
  let omittedSecretFiles = 0;
  let omittedInternalFiles = 0;
  let redactedSecrets = false;

  for (const file of parsed) {
    if (!file.path || containsDotGitSegment(file.path) || (file.original_path && containsDotGitSegment(file.original_path))) {
      omittedSecretFiles += 1;
      continue;
    }

    const pathCheck = isHiddenGitReadPath(file.path, ignoreEngine);
    const originalCheck = file.original_path
      ? isHiddenGitReadPath(file.original_path, ignoreEngine)
      : { hidden: false as const };

    if (pathCheck.reason === "internal_artifact" || originalCheck.reason === "internal_artifact") {
      omittedInternalFiles += 1;
      continue;
    }
    if (pathCheck.reason === "secret_candidate" || originalCheck.reason === "secret_candidate") {
      omittedSecretFiles += 1;
      continue;
    }

    const joinedHunks = file.hunks.join("\n");
    if (
      hasEnvTemplateSecret(file.path, joinedHunks)
      || (file.original_path && hasEnvTemplateSecret(file.original_path, joinedHunks))
    ) {
      omittedSecretFiles += 1;
      continue;
    }

    if (file.is_binary) {
      files.push({
        path: file.path,
        ...(file.original_path ? { original_path: file.original_path } : {}),
        ...(file.status ? { status: file.status } : {}),
        is_binary: true,
        hunks: []
      });
      continue;
    }

    const redactedHunks = file.hunks.map((hunk) => {
      const result = redactGitText(hunk);
      if (result.redacted) redactedSecrets = true;
      return result.text;
    });

    files.push({
      path: file.path,
      ...(file.original_path ? { original_path: file.original_path } : {}),
      ...(file.status ? { status: file.status } : {}),
      hunks: redactedHunks
    });
  }

  return {
    files,
    omitted_secret_files: omittedSecretFiles,
    omitted_internal_files: omittedInternalFiles,
    redacted_secrets: redactedSecrets
  };
}

type RawParsedDiffFile = {
  path?: string;
  original_path?: string;
  status?: string;
  is_binary?: boolean;
  hunks: string[];
};

function parseUnifiedDiff(diff: string): RawParsedDiffFile[] {
  const files: RawParsedDiffFile[] = [];
  let current: RawParsedDiffFile | undefined;
  let currentHunk: string[] = [];

  for (const line of diff.split("\n")) {
    if (line.startsWith("diff --git ")) {
      if (current) {
        if (currentHunk.length > 0 && !current.is_binary) current.hunks.push(currentHunk.join("\n"));
        files.push(current);
      }
      const header = parseDiffGitHeader(line);
      current = {
        ...(header.path ? { path: header.path } : {}),
        ...(header.originalPath && header.originalPath !== header.path ? { original_path: header.originalPath } : {}),
        hunks: []
      };
      currentHunk = [];
      continue;
    }
    if (!current) continue;
    if (line.startsWith("rename from ")) {
      const parsedPath = unquoteGitPath(line.slice(12));
      if (parsedPath) current.original_path = parsedPath;
      current.status = "renamed";
      continue;
    }
    if (line.startsWith("rename to ")) {
      const parsedPath = unquoteGitPath(line.slice(10));
      if (parsedPath) current.path = parsedPath;
      current.status = "renamed";
      continue;
    }
    if (line.startsWith("copy from ")) {
      const parsedPath = unquoteGitPath(line.slice(10));
      if (parsedPath) current.original_path = parsedPath;
      current.status = "copied";
      continue;
    }
    if (line.startsWith("copy to ")) {
      const parsedPath = unquoteGitPath(line.slice(8));
      if (parsedPath) current.path = parsedPath;
      current.status = "copied";
      continue;
    }
    if (line.startsWith("--- ")) {
      const parsedPath = parseDiffMarkerPath(line.slice(4), "a/");
      if (parsedPath && !current.original_path && current.path && parsedPath !== current.path) {
        current.original_path = parsedPath;
      } else if (parsedPath && !current.path) {
        current.path = parsedPath;
      }
      continue;
    }
    if (line.startsWith("+++ ")) {
      const parsedPath = parseDiffMarkerPath(line.slice(4), "b/");
      if (parsedPath) {
        current.path = parsedPath;
      }
      continue;
    }
    if (line.startsWith("new file mode ")) {
      current.status = "added";
      continue;
    }
    if (line.startsWith("deleted file mode ")) {
      current.status = "deleted";
      continue;
    }
    if ((line.startsWith("Binary files ") && line.endsWith(" differ")) || line === "GIT binary patch") {
      current.is_binary = true;
      current.status ??= "modified";
      currentHunk = [];
      current.hunks = [];
      continue;
    }
    if (current.is_binary) continue;
    if (line.startsWith("@@")) {
      current.status ??= "modified";
      if (currentHunk.length > 0) current.hunks.push(currentHunk.join("\n"));
      currentHunk = [line];
      continue;
    }
    if (currentHunk.length > 0) currentHunk.push(line);
  }
  if (current) {
    if (currentHunk.length > 0 && !current.is_binary) current.hunks.push(currentHunk.join("\n"));
    files.push(current);
  }
  return files;
}

function parseDiffGitHeader(line: string): { originalPath?: string; path?: string } {
  const rest = line.slice("diff --git ".length);
  if (rest.startsWith('"')) {
    const first = readQuotedToken(rest, 0);
    if (!first || rest[first.nextIndex] !== " ") {
      return {};
    }
    const secondStart = first.nextIndex + 1;
    const secondRaw = rest.slice(secondStart);
    const secondValue = secondRaw.startsWith('"')
      ? readQuotedToken(secondRaw, 0)?.value
      : secondRaw;
    if (!secondValue) {
      return {};
    }
    return {
      originalPath: stripGitPrefix(first.value, "a/"),
      path: stripGitPrefix(secondValue, "b/")
    };
  }

  const quotedSecondIndex = rest.indexOf(' "b/');
  if (quotedSecondIndex > 0) {
    const firstRaw = rest.slice(0, quotedSecondIndex);
    const secondToken = readQuotedToken(rest, quotedSecondIndex + 1);
    if (secondToken && secondToken.nextIndex === rest.length) {
      return {
        originalPath: stripGitPrefix(firstRaw, "a/"),
        path: stripGitPrefix(secondToken.value, "b/")
      };
    }
  }

  if (rest.startsWith("a/")) {
    const body = rest.slice(2);
    const midpoint = Math.floor((body.length - 3) / 2);
    if (
      body.length >= 5
      && (body.length - 3) % 2 === 0
      && body.slice(midpoint, midpoint + 3) === " b/"
      && body.slice(0, midpoint) === body.slice(midpoint + 3)
    ) {
      const samePath = body.slice(0, midpoint);
      return { originalPath: samePath, path: samePath };
    }
    const match = rest.match(/^a\/(.+?) b\/(.+)$/);
    if (match?.[1] && match[2]) {
      return { originalPath: match[1], path: match[2] };
    }
  }
  return {};
}

function parseDiffMarkerPath(raw: string, expectedPrefix: "a/" | "b/"): string | undefined {
  const trimmed = raw.trimEnd();
  if (trimmed === "/dev/null") {
    return undefined;
  }
  const unquoted = unquoteGitPath(trimmed);
  if (!unquoted) {
    return undefined;
  }
  return stripGitPrefix(unquoted, expectedPrefix);
}

function stripGitPrefix(value: string, prefix: "a/" | "b/"): string | undefined {
  if (!value.startsWith(prefix) || value.length <= prefix.length) {
    return undefined;
  }
  return value.slice(prefix.length);
}

function unquoteGitPath(raw: string): string | undefined {
  if (!raw.startsWith('"')) {
    return raw;
  }
  const parsed = readQuotedToken(raw, 0);
  if (!parsed || parsed.nextIndex !== raw.length) {
    return undefined;
  }
  return parsed.value;
}

function readQuotedToken(input: string, startIndex: number): { value: string; nextIndex: number } | undefined {
  if (input[startIndex] !== '"') {
    return undefined;
  }
  const bytes: number[] = [];
  let i = startIndex + 1;
  while (i < input.length) {
    const ch = input[i]!;
    if (ch === '"') {
      return { value: Buffer.from(bytes).toString("utf8"), nextIndex: i + 1 };
    }
    if (ch === "\\") {
      if (i + 1 >= input.length) {
        return undefined;
      }
      const next = input[i + 1]!;
      if (next >= "0" && next <= "7" && i + 3 < input.length) {
        const oct = input.slice(i + 1, i + 4);
        if (/^[0-7]{3}$/.test(oct)) {
          bytes.push(Number.parseInt(oct, 8));
          i += 4;
          continue;
        }
      }
      const escapeMap: Record<string, number> = {
        "\\": 0x5c,
        '"': 0x22,
        a: 0x07,
        b: 0x08,
        f: 0x0c,
        n: 0x0a,
        r: 0x0d,
        t: 0x09,
        v: 0x0b
      };
      if (Object.hasOwn(escapeMap, next)) {
        bytes.push(escapeMap[next]!);
        i += 2;
        continue;
      }
      for (const byte of Buffer.from(next, "utf8")) bytes.push(byte);
      i += 2;
      continue;
    }
    const codePoint = input.codePointAt(i)!;
    const step = codePoint > 0xffff ? 2 : 1;
    for (const byte of Buffer.from(input.slice(i, i + step), "utf8")) bytes.push(byte);
    i += step;
  }
  return undefined;
}

function clampContextLines(contextLines: number | undefined): number {
  if (contextLines === undefined || !Number.isFinite(contextLines)) {
    return 3;
  }
  return Math.max(0, Math.min(20, Math.floor(contextLines)));
}

function normalizePathForCompare(pathValue: string): string {
  const resolved = resolve(pathValue);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}
