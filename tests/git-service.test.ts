import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, rename, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, test } from "vitest";
import { RepoReaderError } from "../src/runtime/errors.js";
import { GitService } from "../src/services/git-service.js";

const execFileAsync = promisify(execFile);

describe("GitService", () => {
  test("parses porcelain status including rename paths and spaces/UTF-8 names", async () => {
    const root = await createGitFixture();
    await rename(join(root, "src", "app.ts"), join(root, "src", "main.ts"));
    await git(root, ["add", "-A"]);
    await writeFile(join(root, "src", "main.ts"), "export const app = 2;\n");
    await writeFile(join(root, "notes.md"), "# Notes\n");
    await writeFile(join(root, "src", "my café file.ts"), "export const x = 1;\n");

    const result = await new GitService(root).status();

    expect(result.clean).toBe(false);
    expect(result.files).toEqual(
      expect.arrayContaining([
        { index: "R", worktree: "M", path: "src/main.ts", original_path: "src/app.ts" },
        { index: "?", worktree: "?", path: "notes.md" },
        { index: "?", worktree: "?", path: "src/my café file.ts" }
      ])
    );
    expect(result.counts.RM).toBe(1);
    expect(result.counts["??"]).toBe(2);
  });

  test("parses diff file status, hunks, and rename metadata", async () => {
    const root = await createGitFixture();
    await rename(join(root, "src", "app.ts"), join(root, "src", "main.ts"));
    await writeFile(join(root, "src", "other.ts"), "export const other = 2;\n");
    await git(root, ["add", "-A"]);

    const result = await new GitService(root).diff({ staged: true });

    expect(result.files).toEqual(expect.arrayContaining([
      expect.objectContaining({
        path: "src/main.ts",
        original_path: "src/app.ts",
        status: "renamed"
      }),
      expect.objectContaining({
        path: "src/other.ts",
        status: "modified",
        hunks: [expect.stringContaining("@@")]
      })
    ]));
  });

  test("handles staged, unstaged, combined, and neither diff scopes accurately", async () => {
    const root = await createGitFixture();
    await writeFile(join(root, "src", "app.ts"), "export const app = 2;\n");
    await git(root, ["add", "--", "src/app.ts"]);
    await writeFile(join(root, "src", "other.ts"), "export const other = 2;\n");

    const service = new GitService(root);
    const stagedOnly = await service.diff({ staged: true });
    const unstagedOnly = await service.diff({ unstaged: true });
    const both = await service.diff({ staged: true, unstaged: true });
    const neither = await service.diff({ staged: false, unstaged: false });

    expect(stagedOnly.files.map((file) => file.path)).toEqual(["src/app.ts"]);
    expect(unstagedOnly.files.map((file) => file.path)).toEqual(["src/other.ts"]);
    expect(both.files.map((file) => file.path).sort()).toEqual(["src/app.ts", "src/other.ts"]);
    expect(neither.files).toEqual([]);
  });

  test("validates path filters through repo-relative and git-read safety policy", async () => {
    const root = await createGitFixture();
    const service = new GitService(root);

    await expect(service.diff({ paths: ["../outside.ts"] })).rejects.toMatchObject({
      code: "PATH_TRAVERSAL_REJECTED"
    } satisfies Partial<RepoReaderError>);

    await expect(service.diff({ paths: [":(icase).env"] })).rejects.toMatchObject({
      code: "GIT_OPERATION_UNSAFE_PATHSPEC"
    } satisfies Partial<RepoReaderError>);

    await expect(service.diff({ paths: ["--cached"] })).rejects.toMatchObject({
      code: "GIT_OPERATION_UNSAFE_PATHSPEC"
    } satisfies Partial<RepoReaderError>);

    await expect(service.diff({ paths: [".env"] })).rejects.toMatchObject({
      code: "SECRET_CANDIDATE_BLOCKED"
    } satisfies Partial<RepoReaderError>);
  });

  test("rejects option and ref injection in diff base and compare without writing files", async () => {
    const root = await createGitFixture();
    await writeFile(join(root, "src", "app.ts"), "export const app = 2;\n");
    const service = new GitService(root);
    const evilFile = join(root, "evil.txt");

    for (const payload of [
      { base: "--output=evil.txt" },
      { base: "--no-index" },
      { base: "--ext-diff" },
      { base: "--textconv" },
      { base: "-O/etc/passwd" },
      { base: "HEAD:.env" },
      { base: "HEAD", compare: "--output=evil.txt" }
    ]) {
      await expect(service.diff(payload)).rejects.toMatchObject({
        code: "VALIDATION_ERROR"
      } satisfies Partial<RepoReaderError>);
    }

    await expect(access(evilFile)).rejects.toThrow();
  });

  test("omits secret candidate files and redacts secret tokens in diff output", async () => {
    const root = await createGitFixture();
    const envSecret = "sk-secretEnvToken1234567890";
    const templateSecret = "sk-templateLiveToken1234567890";
    const codeSecret = "sk-sourceToken1234567890";

    await writeFile(join(root, ".env"), "API_KEY=old\n");
    await writeFile(join(root, ".env.example"), "API_KEY=replace-me\n");
    await git(root, ["add", "-f", ".env", ".env.example"]);
    await git(root, ["commit", "-m", "add env fixtures"]);

    await writeFile(join(root, ".env"), `API_KEY=${envSecret}\n`);
    await writeFile(join(root, ".env.example"), `API_KEY=${templateSecret}\n`);
    await writeFile(join(root, "src", "app.ts"), `export const token = "${codeSecret}";\n`);

    const result = await new GitService(root).diff({});
    const serialized = JSON.stringify(result);

    expect(result.files.map((file) => file.path)).toEqual(["src/app.ts"]);
    expect(serialized).not.toContain(envSecret);
    expect(serialized).not.toContain(templateSecret);
    expect(serialized).not.toContain(codeSecret);
    expect(serialized).toContain("[REDACTED_SECRET]");
    expect(result.warnings.some((warning) => warning.includes("secret candidate"))).toBe(true);
    expect(result.warnings.some((warning) => warning.includes("Redacted secret-like"))).toBe(true);
  });

  test("neutralizes malicious .git/config commands during status and diff", async () => {
    const root = await createGitFixture();
    const marker = join(root, "rce-marker.txt");
    const markerJs = marker.replaceAll("\\", "\\\\");
    const cmd = `node -e "require('fs').writeFileSync('${markerJs}','pwned')"`;

    await git(root, ["config", "diff.external", cmd]);
    await git(root, ["config", "core.fsmonitor", cmd]);
    await git(root, ["config", "core.pager", cmd]);
    await git(root, ["config", "diff.evil.textconv", cmd]);
    await git(root, ["config", "alias.status", `!${cmd}`]);
    await writeFile(join(root, ".gitattributes"), "*.ts diff=evil\n");
    await writeFile(join(root, "src", "app.ts"), "export const app = 99;\n");

    const service = new GitService(root);
    const status = await service.status();
    const diff = await service.diff({});

    expect(status.files.some((file) => file.path === "src/app.ts")).toBe(true);
    expect(diff.files.some((file) => file.path === "src/app.ts")).toBe(true);
    await expect(access(marker)).rejects.toThrow();
    await expect(access(join(root, ".git", "index.lock"))).rejects.toThrow();
  });

  test("rejects nested subdirectory inside parent git repository", async () => {
    const root = await createGitFixture();
    const nested = join(root, "src");

    await expect(new GitService(nested).status()).rejects.toMatchObject({
      code: "GIT_ERROR"
    } satisfies Partial<RepoReaderError>);

    await expect(new GitService(nested).diff({})).rejects.toMatchObject({
      code: "GIT_ERROR"
    } satisfies Partial<RepoReaderError>);
  });

  test("truncates large diffs with warning", async () => {
    const root = await createGitFixture();
    await writeFile(join(root, "src", "app.ts"), Array.from({ length: 40 }, (_, index) => `line ${index}`).join("\n"));

    const result = await new GitService(root).diff({ max_bytes: 120 });

    expect(result.truncated).toBe(true);
    expect(result.warnings).toEqual([
      "Diff content truncated by max_bytes (120); Git completed successfully."
    ]);
  });

  test("hides mixed-case internal runner artifacts from status and diff", async () => {
    const root = await createGitFixture();
    const path = ".ChAtGpT/CoDeX-RuNs/2026-07-13T170000Z-private/RuNnEr.SeSsIoN.JsOn";
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), '{"thread_id":"baseline"}\n');
    await git(root, ["add", "-f", path]);
    await git(root, ["commit", "-m", "private runner baseline"]);
    await writeFile(join(root, path), '{"thread_id":"private-canary"}\n');

    const service = new GitService(root);
    const status = await service.status();
    const diff = await service.diff({});

    expect(status.files.map((file) => file.path)).not.toContain(path);
    expect(diff.files.map((file) => file.path)).not.toContain(path);
    expect(JSON.stringify({ status, diff })).not.toContain("private-canary");
    await expect(service.diff({ paths: [path] })).rejects.toMatchObject({
      code: "INTERNAL_ARTIFACT_BLOCKED"
    } satisfies Partial<RepoReaderError>);
  });

  test("blocks symlink aliases pointing to secrets or outside root in diff paths", async () => {
    const root = await createGitFixture();
    const outsideDir = await mkdtemp(join(tmpdir(), "repo-reader-outside-"));
    const outsideFile = join(outsideDir, "secret.txt");
    await writeFile(outsideFile, "outside\n");
    await writeFile(join(root, ".env"), "SECRET=1\n");

    let symlinkCreated = true;
    try {
      await symlink(join(root, ".env"), join(root, "env-alias.txt"));
      await symlink(outsideFile, join(root, "outside-alias.txt"));
    } catch {
      symlinkCreated = false;
    }

    if (symlinkCreated) {
      const service = new GitService(root);
      await expect(service.diff({ paths: ["env-alias.txt"] })).rejects.toMatchObject({
        code: "SECRET_CANDIDATE_BLOCKED"
      } satisfies Partial<RepoReaderError>);
      await expect(service.diff({ paths: ["outside-alias.txt"] })).rejects.toMatchObject({
        code: "SYMLINK_ESCAPE_REJECTED"
      } satisfies Partial<RepoReaderError>);
    }
  });
});

async function createGitFixture() {
  const root = await mkdtemp(join(tmpdir(), "repo-reader-git-"));
  await mkdir(join(root, "src"), { recursive: true });
  await git(root, ["init"]);
  await git(root, ["config", "user.email", "test@example.com"]);
  await git(root, ["config", "user.name", "Test User"]);
  await writeFile(join(root, "src", "app.ts"), "export const app = 1;\n");
  await writeFile(join(root, "src", "other.ts"), "export const other = 1;\n");
  await git(root, ["add", "."]);
  await git(root, ["commit", "-m", "initial"]);
  return root;
}

async function git(cwd: string, args: string[]) {
  await execFileAsync("git", args, { cwd, env: { PATH: process.env.PATH ?? "" } });
}
