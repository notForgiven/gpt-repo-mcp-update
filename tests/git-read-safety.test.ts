import { execFile } from "node:child_process";
import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, test } from "vitest";
import { DEFAULT_LIMITS } from "../src/policies/limits.js";
import { RepoReaderError } from "../src/runtime/errors.js";
import { decodeUtf8Safe, runGitBounded, runGitReadOnly } from "../src/services/git-exec.js";
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
} from "../src/services/git-read-safety.js";
import { IgnoreEngine } from "../src/services/ignore-engine.js";

const execFileAsync = promisify(execFile);

describe("git-read-safety", () => {
  test("exports bounded read-only git limits", () => {
    expect(DEFAULT_LIMITS.git_read_timeout_ms).toBe(10_000);
    expect(DEFAULT_LIMITS.max_git_read_timeout_ms).toBe(15_000);
    expect(DEFAULT_LIMITS.max_git_log_commits).toBe(100);
    expect(DEFAULT_LIMITS.max_git_tree_entries).toBe(2_000);
    expect(DEFAULT_LIMITS.max_git_tree_depth).toBe(8);
    expect(DEFAULT_LIMITS.max_git_refs).toBe(500);
    expect(DEFAULT_LIMITS.max_git_blame_lines).toBe(500);
    expect(DEFAULT_LIMITS.max_git_show_bytes).toBe(256_000);
    expect(DEFAULT_LIMITS.max_git_status_entries).toBe(2_000);
    expect(DEFAULT_LIMITS.max_git_rev_parse_refs).toBe(50);
  });

  test("validateGitRef allows safe refs and rejects option/syntax injection", () => {
    for (const valid of [
      "HEAD",
      "main",
      "origin/main",
      "feature/safe_branch-1.2",
      "v1.2.3+build.1",
      "HEAD~3",
      "HEAD^2",
      "abc1234def5678",
      "refs/tags/v1.0.0"
    ]) {
      expect(validateGitRef(valid)).toBe(valid);
    }

    for (const invalid of [
      "",
      "-all",
      "--output=evil.txt",
      "--no-index",
      "--ext-diff",
      "HEAD:.env",
      ":0:.env",
      "main..dev",
      "main...dev",
      "HEAD@{0}",
      "a//b",
      "foo*bar",
      "foo?bar",
      "foo[0]",
      "foo\\bar",
      "foo bar",
      "foo\nbar",
      "foo\0bar",
      "branch.lock",
      "branch.",
      "branch/",
      "a".repeat(257)
    ]) {
      expect(() => validateGitRef(invalid)).toThrowError(RepoReaderError);
    }
  });

  test("validateGitReadPath rejects injection, traversal, .git, secrets, and internal artifacts", async () => {
    const root = await createGitFixture();
    const ignoreEngine = new IgnoreEngine();

    expect(await validateGitReadPath(root, "src/app.ts", ignoreEngine)).toBe("src/app.ts");
    expect(await validateGitReadPath(root, ".", ignoreEngine, { allowDot: true })).toBe(".");

    await expect(validateGitReadPath(root, "--cached", ignoreEngine)).rejects.toMatchObject({
      code: "GIT_OPERATION_UNSAFE_PATHSPEC"
    });
    await expect(validateGitReadPath(root, "./-leading-dash", ignoreEngine)).rejects.toMatchObject({
      code: "GIT_OPERATION_UNSAFE_PATHSPEC"
    });
    await expect(validateGitReadPath(root, ":(icase).env", ignoreEngine)).rejects.toMatchObject({
      code: "GIT_OPERATION_UNSAFE_PATHSPEC"
    });
    await expect(validateGitReadPath(root, ".git/config", ignoreEngine)).rejects.toMatchObject({
      code: "GIT_OPERATION_UNSAFE_PATHSPEC"
    });
    await expect(validateGitReadPath(root, ".GIT/HEAD", ignoreEngine)).rejects.toMatchObject({
      code: "GIT_OPERATION_UNSAFE_PATHSPEC"
    });
    await expect(validateGitReadPath(root, "vendor/nested/.git/config", ignoreEngine)).rejects.toMatchObject({
      code: "GIT_OPERATION_UNSAFE_PATHSPEC"
    });
    await expect(validateGitReadPath(root, "vendor/nested/.GIT/HEAD", ignoreEngine)).rejects.toMatchObject({
      code: "GIT_OPERATION_UNSAFE_PATHSPEC"
    });

    let dotGitSymlinkCreated = true;
    try {
      await symlink(join(root, ".git", "config"), join(root, "git-config-alias.txt"));
    } catch {
      dotGitSymlinkCreated = false;
    }
    if (dotGitSymlinkCreated) {
      await expect(validateGitReadPath(root, "git-config-alias.txt", ignoreEngine)).rejects.toMatchObject({
        code: "GIT_OPERATION_UNSAFE_PATHSPEC"
      });
    }
    await expect(validateGitReadPath(root, "../outside.ts", ignoreEngine)).rejects.toMatchObject({
      code: "PATH_TRAVERSAL_REJECTED"
    });
    await expect(validateGitReadPath(root, "/etc/passwd", ignoreEngine)).rejects.toMatchObject({
      code: "ABSOLUTE_PATH_REJECTED"
    });
    await expect(validateGitReadPath(root, "C:\\Windows\\win.ini", ignoreEngine)).rejects.toMatchObject({
      code: "ABSOLUTE_PATH_REJECTED"
    });
    await expect(validateGitReadPath(root, "\\\\server\\share\\file.txt", ignoreEngine)).rejects.toMatchObject({
      code: "ABSOLUTE_PATH_REJECTED"
    });
    await expect(validateGitReadPath(root, ".env.production", ignoreEngine)).rejects.toMatchObject({
      code: "SECRET_CANDIDATE_BLOCKED"
    });
    await expect(validateGitReadPath(root, "secrets/key.pem", ignoreEngine)).rejects.toMatchObject({
      code: "SECRET_CANDIDATE_BLOCKED"
    });

    const internalPath = ".chatgpt/codex-runs/2026-07-13T170000Z-run/runner.session.json";
    try {
      await validateGitReadPath(root, internalPath, ignoreEngine);
      expect.unreachable("Expected INTERNAL_ARTIFACT_BLOCKED");
    } catch (error) {
      expect(error).toMatchObject({ code: "INTERNAL_ARTIFACT_BLOCKED" });
      expect((error as Error).message).not.toContain(internalPath);
    }
  });

  test("validates patterns, filter text, and date specs safely", () => {
    expect(validateGitPattern("release/*")).toBe("release/*");
    expect(() => validateGitPattern("-D")).toThrowError(RepoReaderError);
    expect(() => validateGitPattern("a:b")).toThrowError(RepoReaderError);
    expect(() => validateGitPattern("a".repeat(129))).toThrowError(RepoReaderError);

    expect(validateGitFilterText("fix login")).toBe("fix login");
    expect(() => validateGitFilterText("--exec=id")).toThrowError(RepoReaderError);
    expect(() => validateGitFilterText("bad\nline")).toThrowError(RepoReaderError);
    expect(() => validateGitFilterText("a".repeat(201))).toThrowError(RepoReaderError);

    expect(validateGitDateSpec("2026-01-15")).toBe("2026-01-15");
    expect(validateGitDateSpec("2026-01-15T10:30:00Z")).toBe("2026-01-15T10:30:00Z");
    expect(validateGitDateSpec("7 days ago")).toBe("7 days ago");
    expect(validateGitDateSpec("yesterday")).toBe("yesterday");
    expect(() => validateGitDateSpec("--since=today")).toThrowError(RepoReaderError);
    expect(() => validateGitDateSpec("yesterday; rm -rf /")).toThrowError(RepoReaderError);
  });

  test("assertGitRepoConfined permits top-level root and rejects nested or non-git dirs without leaking paths", async () => {
    const root = await createGitFixture();
    const confined = await assertGitRepoConfined(root);
    expect(confined.length).toBeGreaterThan(0);

    const nested = join(root, "src");
    try {
      await assertGitRepoConfined(nested);
      expect.unreachable("Expected nested dir to fail confinement");
    } catch (error) {
      expect(error).toMatchObject({ code: "GIT_ERROR" });
      expect((error as Error).message).not.toContain(root);
    }

    const nonGit = await mkdtemp(join(tmpdir(), "repo-reader-nongit-"));
    try {
      await assertGitRepoConfined(nonGit);
      expect.unreachable("Expected non-git dir to fail confinement");
    } catch (error) {
      expect(error).toMatchObject({ code: "GIT_ERROR" });
      expect((error as Error).message).not.toContain(nonGit);
    }
  });

  test("buildSafeDiffArgs enforces no-ext-diff/no-textconv and validates refs", () => {
    expect(buildSafeDiffArgs({ base: "main", compare: "HEAD", range_mode: "two_dot", context_lines: 5 })).toEqual([
      "diff",
      "--find-renames",
      "--no-ext-diff",
      "--no-textconv",
      "--no-color",
      "--unified=5",
      "main..HEAD"
    ]);
    expect(buildSafeDiffArgs({ staged: true, unstaged: true })).toContain("HEAD");
    expect(buildSafeDiffArgs({ staged: true })).toContain("--cached");
    expect(buildSafeDiffArgs({ unstaged: true })).not.toContain("--cached");
    expect(() => buildSafeDiffArgs({ compare: "HEAD" })).toThrowError(RepoReaderError);
    expect(() => buildSafeDiffArgs({ base: "--output=evil.txt" })).toThrowError(RepoReaderError);
  });

  test("filterAndRedactUnifiedDiff omits secrets, internal artifacts, handles binary, and redacts tokens", () => {
    const sampleDiff = [
      "diff --git a/.env b/.env",
      "@@ -1 +1 @@",
      "-API_KEY=old",
      "+API_KEY=sk-secretEnv123456789",
      "diff --git a/.chatgpt/codex-runs/run-1/runner.session.json b/.chatgpt/codex-runs/run-1/runner.session.json",
      "@@ -1 +1 @@",
      "+{\"secret\":\"internal\"}",
      "diff --git a/assets/logo.png b/assets/logo.png",
      "Binary files a/assets/logo.png and b/assets/logo.png differ",
      "diff --git a/src/app.ts b/src/app.ts",
      "@@ -1 +1 @@",
      "+const key = \"sk-realTokenValue123456\";"
    ].join("\n");

    const filtered = filterAndRedactUnifiedDiff(sampleDiff);
    expect(filtered.omitted_secret_files).toBe(1);
    expect(filtered.omitted_internal_files).toBe(1);
    expect(filtered.redacted_secrets).toBe(true);
    expect(filtered.files).toEqual([
      { path: "assets/logo.png", status: "modified", is_binary: true, hunks: [] },
      { path: "src/app.ts", status: "modified", hunks: ["@@ -1 +1 @@\n+const key = \"[REDACTED_SECRET]\";"] }
    ]);
  });

  test("filterAndRedactUnifiedDiff unquotes quoted diff headers and fails closed on unparseable headers", () => {
    const quotedAndMalformedDiff = [
      'diff --git "a/.env\\"x" "b/.env\\"x"',
      "@@ -1 +1 @@",
      "+SECRET=leaked-from-quoted-env",
      'diff --git "a/secrets/\\"prod.txt" "b/secrets/\\"prod.txt"',
      "@@ -1 +1 @@",
      "+SECRET=leaked-from-quoted-secrets-dir",
      'diff --git "a/vendor/nested/.git/config" "b/vendor/nested/.git/config"',
      "@@ -1 +1 @@",
      "+[core] bare = false",
      'diff --git "unterminated-header',
      "@@ -1 +1 @@",
      "+SECRET=must-fail-closed",
      'diff --git "a/src/quote\\"name.ts" "b/src/quote\\"name.ts"',
      '--- "a/src/quote\\"name.ts"',
      '+++ "b/src/quote\\"name.ts"',
      "@@ -1 +1 @@",
      '+export const ok = "safe";'
    ].join("\n");

    const filtered = filterAndRedactUnifiedDiff(quotedAndMalformedDiff);
    const serialized = JSON.stringify(filtered);

    expect(filtered.omitted_secret_files).toBe(4);
    expect(filtered.files).toEqual([
      { path: 'src/quote"name.ts', status: "modified", hunks: ['@@ -1 +1 @@\n+export const ok = "safe";'] }
    ]);
    expect(serialized).not.toContain("leaked-from-quoted-env");
    expect(serialized).not.toContain("leaked-from-quoted-secrets-dir");
    expect(serialized).not.toContain("must-fail-closed");
    expect(serialized).not.toContain("unknown");
  });

  test("runGitReadOnly returns exit_code 0 when truncated with allow_stdout_truncation", async () => {
    const root = await createGitFixture();
    await writeFile(join(root, "src", "big.txt"), "x".repeat(200_000));
    await git(root, ["add", "--", "src/big.txt"]);
    await git(root, ["commit", "-m", "add big file"]);

    const result = await runGitReadOnly({
      root,
      args: ["show", "HEAD:src/big.txt"],
      max_stdout_bytes: 64,
      allow_stdout_truncation: true
    });

    expect(result.stdout_truncated).toBe(true);
    expect(result.exit_code).toBe(0);
    expect(Buffer.byteLength(result.stdout, "utf8")).toBeLessThanOrEqual(64);
  });

  test("helpers classify hidden paths, env templates, binary buffers, and UTF-8 safe truncation", () => {
    expect(isHiddenGitReadPath(".env")).toEqual({ hidden: true, reason: "secret_candidate" });
    expect(isHiddenGitReadPath(".chatgpt/codex-runs/r1/review.json")).toEqual({ hidden: true, reason: "internal_artifact" });
    expect(isHiddenGitReadPath("src/index.ts")).toEqual({ hidden: false });

    expect(hasEnvTemplateSecret(".env.example", "API_KEY=sk-liveSecret12345")).toBe(true);
    expect(hasEnvTemplateSecret(".env.example", "API_KEY=replace-me")).toBe(false);
    expect(redactGitText("token=sk-abc123456")).toEqual({ text: "token=[REDACTED_SECRET]", redacted: true });

    expect(isBinaryBuffer(Buffer.from([0x61, 0x00, 0x62]))).toBe(true);
    expect(isBinaryBuffer(Buffer.from("plain utf8 text", "utf8"))).toBe(false);

    const emoji = "a🚀b";
    const truncated = truncateUtf8Bytes(emoji, 3);
    expect(truncated.truncated).toBe(true);
    expect(truncated.text).toBe("a");
    expect(truncated.text).not.toContain("\uFFFD");
    expect(decodeUtf8Safe(Buffer.from(emoji, "utf8").subarray(0, 3), true)).toBe("a");
  });

  test("runGitBounded enforces timeout and terminates hung git processes cleanly", async () => {
    const root = await createGitFixture();
    const started = Date.now();

    await expect(runGitBounded({
      root,
      args: ["-c", 'alias.hang=!node -e "setTimeout(() => {}, 10000)"', "hang"],
      max_stdout_bytes: 1024,
      timeout_ms: 150
    })).rejects.toMatchObject({
      code: "GIT_ERROR",
      retryable: true
    } satisfies Partial<RepoReaderError>);

    expect(Date.now() - started).toBeLessThan(5_000);
  });

  test("runGitReadOnly executes cleanly on current platform with locked read-only env", async () => {
    const root = await createGitFixture();
    const res = await runGitReadOnly({
      root,
      args: ["rev-parse", "--short", "HEAD"],
      max_stdout_bytes: 1024
    });
    expect(res.exit_code).toBe(0);
    expect(res.stdout.trim()).toMatch(/^[0-9a-f]{7,}$/);
  });
});

async function createGitFixture() {
  const root = await mkdtemp(join(tmpdir(), "repo-reader-safety-"));
  await mkdir(join(root, "src"), { recursive: true });
  await git(root, ["init"]);
  await git(root, ["config", "user.email", "test@example.com"]);
  await git(root, ["config", "user.name", "Test User"]);
  await writeFile(join(root, "src", "app.ts"), "export const app = 1;\n");
  await git(root, ["add", "."]);
  await git(root, ["commit", "-m", "initial"]);
  return root;
}

async function git(cwd: string, args: string[]) {
  await execFileAsync("git", args, { cwd, env: { PATH: process.env.PATH ?? "" } });
}
