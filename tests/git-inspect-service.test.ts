import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, test } from "vitest";
import { GitInspectInputSchema, GitInspectResultSchema } from "../src/contracts/git-inspect.contract.js";
import { GitInspectService } from "../src/services/git-inspect-service.js";

const execFileAsync = promisify(execFile);
const tempDirs: string[] = [];

const FAKE_SECRET_TOKEN = ["sk", "proj", "abcdefghijklmnopqrstuvwxyz123456"].join("-");

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
});

describe("GitInspectService", () => {
  test("validates input contracts and rejects invalid command combinations", () => {
    expect(GitInspectInputSchema.safeParse({ repo_id: "r", command: "blame" }).success).toBe(false);
    expect(GitInspectInputSchema.safeParse({ repo_id: "r", command: "merge_base", ref: "main" }).success).toBe(false);
    expect(GitInspectInputSchema.safeParse({ repo_id: "r", command: "rev_parse" }).success).toBe(false);
    expect(GitInspectInputSchema.safeParse({ repo_id: "r", command: "blame", file_path: "src/a.ts", start_line: 10, end_line: 5 }).success).toBe(false);
    expect(GitInspectInputSchema.safeParse({ repo_id: "r", command: "blame", file_path: "src/a.ts", start_line: 1, end_line: 600 }).success).toBe(false);
    expect(GitInspectInputSchema.safeParse({ repo_id: "r", command: "show", file_path: "src/a.ts", include_patch: true }).success).toBe(false);
    expect(GitInspectInputSchema.safeParse({ repo_id: "r", command: "diff", staged: true, ref: "HEAD", compare_ref: "main" }).success).toBe(false);
    expect(GitInspectInputSchema.safeParse({ repo_id: "r", command: "commit_tree", all_refs: true, ref: "main" }).success).toBe(false);
    expect(GitInspectInputSchema.safeParse({ repo_id: "r", command: "log", unknown_flag: true }).success).toBe(false);
  });

  test("supports status with branch tracking, ahead/behind, renames, path filter, and state detection", async () => {
    const { root } = await createRichGitFixture();
    const service = new GitInspectService(root);

    // Push main to bare remote, then make 1 local commit ahead
    await git(root, ["push", "-u", "origin", "main"]);
    await writeFile(join(root, "src", "ahead.ts"), "export const ahead = 1;\n");
    await git(root, ["add", "src/ahead.ts"]);
    await git(root, ["commit", "-m", "commit ahead of origin"]);

    // Create staged rename, unstaged edit, and untracked file
    await rename(join(root, "src", "util.ts"), join(root, "src", "helpers.ts"));
    await git(root, ["add", "-A"]);
    await writeFile(join(root, "src", "app.ts"), "export const app = 99;\n");
    await writeFile(join(root, "docs", "new-note.md"), "# Note\n");

    const res = await service.inspect({ repo_id: "fixture", command: "status" });
    expect(GitInspectResultSchema.parse(res)).toBeTruthy();
    expect(res.status).toMatchObject({
      branch: "main",
      detached: false,
      upstream: "origin/main",
      ahead: 1,
      behind: 0,
      state: "dirty",
      clean: false
    });
    expect(res.status?.files).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: "src/helpers.ts", original_path: "src/util.ts", status: "renamed", staged: true }),
      expect.objectContaining({ path: "src/app.ts", status: "modified", unstaged: true }),
      expect.objectContaining({ path: "docs/new-note.md", status: "untracked", unstaged: true })
    ]));

    // Scoped path filter
    const scoped = await service.inspect({ repo_id: "fixture", command: "status", paths: ["src/app.ts"] });
    expect(scoped.status?.files).toHaveLength(1);
    expect(scoped.status?.files[0]?.path).toBe("src/app.ts");

    // Merging state detection via .git/MERGE_HEAD marker without host path leaks
    await writeFile(join(root, ".git", "MERGE_HEAD"), `${res.status!.head_sha}\n`);
    const merging = await service.inspect({ repo_id: "fixture", command: "status" });
    expect(merging.status?.state).toBe("merging");
    expect(JSON.stringify(merging)).not.toContain(root);
  });

  test("supports branch listing across local/remote/all scopes, pattern, merged/contains, and limit", async () => {
    const { root } = await createRichGitFixture();
    await git(root, ["push", "-u", "origin", "main"]);
    await git(root, ["push", "origin", "feature/alpha"]);
    const service = new GitInspectService(root);

    const local = await service.inspect({ repo_id: "fixture", command: "branch", scope: "local" });
    expect(GitInspectResultSchema.parse(local)).toBeTruthy();
    expect(local.branches?.current_branch).toBe("main");
    expect(local.branches?.items.map((b) => b.name)).toEqual(expect.arrayContaining(["main", "feature/alpha", "feature/beta"]));

    const filtered = await service.inspect({ repo_id: "fixture", command: "branch", scope: "local", pattern: "feature/*" });
    expect(filtered.branches?.items.map((b) => b.name).sort()).toEqual(["feature/alpha", "feature/beta"]);

    const remote = await service.inspect({ repo_id: "fixture", command: "branch", scope: "remote" });
    expect(remote.branches?.items.every((b) => b.scope === "remote")).toBe(true);
    expect(remote.branches?.items.map((b) => b.name)).toEqual(expect.arrayContaining(["origin/main", "origin/feature/alpha"]));

    const limited = await service.inspect({ repo_id: "fixture", command: "branch", scope: "all", limit: 2 });
    expect(limited.truncated).toBe(true);
    expect(limited.truncation_reason).toBe("limit");
    expect(limited.branches?.items).toHaveLength(2);
    expect(limited.branches?.total_count).toBeGreaterThan(2);

    const mergedIntoMain = await service.inspect({ repo_id: "fixture", command: "branch", merged: "main" });
    expect(mergedIntoMain.branches?.items.map((b) => b.name)).toContain("feature/alpha");
    expect(mergedIntoMain.branches?.items.map((b) => b.name)).not.toContain("feature/beta");

    // Pathological wildcard pattern finishes in linear time without regex backtracking
    const redosSafe = await service.inspect({
      repo_id: "fixture",
      command: "branch",
      pattern: "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b"
    });
    expect(redosSafe.branches?.items).toEqual([]);
  });

  test("supports tag listing for lightweight and annotated tags with pattern and sort", async () => {
    const { root } = await createRichGitFixture();
    const service = new GitInspectService(root);

    const tags = await service.inspect({ repo_id: "fixture", command: "tag", sort: "refname" });
    expect(GitInspectResultSchema.parse(tags)).toBeTruthy();
    expect(tags.tags?.items.map((t) => t.name)).toEqual(["v0.1.0", "v1.0.0"]);

    const lightweight = tags.tags?.items.find((t) => t.name === "v0.1.0");
    const annotated = tags.tags?.items.find((t) => t.name === "v1.0.0");
    expect(lightweight?.is_annotated).toBe(false);
    expect(annotated?.is_annotated).toBe(true);
    expect(annotated?.target_sha).toMatch(/^[0-9a-f]{40}$/);
    expect(annotated?.subject).toContain("Release 1.0.0");

    const filtered = await service.inspect({ repo_id: "fixture", command: "tag", pattern: "v1.*" });
    expect(filtered.tags?.items.map((t) => t.name)).toEqual(["v1.0.0"]);
  });

  test("supports log with pagination, range, grep, author, merges, first_parent, and include_stat", async () => {
    const { root } = await createRichGitFixture();
    const service = new GitInspectService(root);

    const page1 = await service.inspect({ repo_id: "fixture", command: "log", limit: 2, include_stat: true });
    expect(GitInspectResultSchema.parse(page1)).toBeTruthy();
    expect(page1.truncated).toBe(true);
    expect(page1.commits?.items).toHaveLength(2);
    expect(page1.commits?.items[0]?.files).toBeDefined();

    const page2 = await service.inspect({ repo_id: "fixture", command: "log", limit: 2, skip: 2 });
    expect(page2.commits?.skip).toBe(2);
    expect(page2.commits?.items[0]?.sha).not.toBe(page1.commits?.items[0]?.sha);

    const mergesOnly = await service.inspect({ repo_id: "fixture", command: "log", merges: "only" });
    expect(mergesOnly.commits?.items.length).toBeGreaterThanOrEqual(1);
    expect(mergesOnly.commits?.items.every((c) => c.parents.length >= 2)).toBe(true);

    const noMerges = await service.inspect({ repo_id: "fixture", command: "log", merges: "exclude" });
    expect(noMerges.commits?.items.every((c) => c.parents.length <= 1)).toBe(true);

    const range = await service.inspect({
      repo_id: "fixture",
      command: "log",
      ref: "main",
      compare_ref: "feature/beta",
      range_mode: "two_dot"
    });
    expect(range.commits?.items.map((c) => c.subject)).toContain("Add beta module");

    const grepped = await service.inspect({ repo_id: "fixture", command: "log", grep: "alpha" });
    expect(grepped.commits?.items.length).toBeGreaterThanOrEqual(1);

    const byAuthor = await service.inspect({ repo_id: "fixture", command: "log", author: "Bob" });
    expect(byAuthor.commits?.items.length).toBeGreaterThanOrEqual(1);
    expect(byAuthor.commits?.items.every((c) => c.author_name.includes("Bob"))).toBe(true);
  });

  test("supports diff across staged, unstaged, ref ranges, two_dot/three_dot, stat_only, and truncation", async () => {
    const { root } = await createRichGitFixture();
    const service = new GitInspectService(root);

    // Ref comparison stat_only
    const statDiff = await service.inspect({
      repo_id: "fixture",
      command: "diff",
      ref: "main",
      compare_ref: "feature/beta",
      range_mode: "two_dot",
      stat_only: true
    });
    expect(GitInspectResultSchema.parse(statDiff)).toBeTruthy();
    expect(statDiff.diff?.stat_only).toBe(true);
    expect(statDiff.diff?.files).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: "src/beta.ts", insertions: 1, deletions: 0, hunks: [] })
    ]));

    // Staged vs unstaged separation
    await writeFile(join(root, "src", "app.ts"), "export const app = 10;\n");
    await git(root, ["add", "src/app.ts"]);
    await writeFile(join(root, "src", "util.ts"), "export const util = 20;\n");

    const stagedOnly = await service.inspect({ repo_id: "fixture", command: "diff", staged: true });
    expect(stagedOnly.diff?.files.map((f) => f.path)).toEqual(["src/app.ts"]);
    expect(stagedOnly.diff?.files[0]?.hunks.length).toBeGreaterThan(0);

    const unstagedOnly = await service.inspect({ repo_id: "fixture", command: "diff", unstaged: true });
    expect(unstagedOnly.diff?.files.map((f) => f.path)).toEqual(["src/util.ts"]);

    const both = await service.inspect({ repo_id: "fixture", command: "diff", staged: true, unstaged: true });
    expect(both.diff?.files.map((f) => f.path).sort()).toEqual(["src/app.ts", "src/util.ts"]);

    const neither = await service.inspect({ repo_id: "fixture", command: "diff", staged: false, unstaged: false });
    expect(neither.diff?.files).toEqual([]);
    expect(neither.diff?.total_file_count).toBe(0);
  });

  test("supports commit_tree (DAG + ASCII graph) and file_tree (ref ls-tree with depth & path scoping)", async () => {
    const { root } = await createRichGitFixture();
    const service = new GitInspectService(root);

    const commitTree = await service.inspect({ repo_id: "fixture", command: "commit_tree", all_refs: true, limit: 20 });
    expect(GitInspectResultSchema.parse(commitTree)).toBeTruthy();
    expect(commitTree.commit_tree?.all_refs).toBe(true);
    expect(commitTree.commit_tree?.nodes.some((n) => n.parents.length === 2)).toBe(true);
    expect(commitTree.commit_tree?.graph_lines.length).toBeGreaterThan(0);
    expect(commitTree.commit_tree?.graph_lines.some((line) => line.includes("*"))).toBe(true);

    // file_tree on feature/beta (not currently checked out!)
    const betaTree = await service.inspect({
      repo_id: "fixture",
      command: "file_tree",
      ref: "feature/beta",
      recursive: true
    });
    expect(GitInspectResultSchema.parse(betaTree)).toBeTruthy();
    expect(betaTree.file_tree?.entries.map((e) => e.path)).toContain("src/beta.ts");

    // Non-recursive root tree vs path scoped (dir and single file in subdir)
    const rootTree = await service.inspect({ repo_id: "fixture", command: "file_tree", ref: "main", recursive: false });
    expect(rootTree.file_tree?.entries.some((e) => e.path === "src" && e.type === "tree")).toBe(true);
    expect(rootTree.file_tree?.entries.some((e) => e.path === "src/app.ts")).toBe(false);

    const srcTree = await service.inspect({ repo_id: "fixture", command: "file_tree", ref: "main", path: "src", recursive: true });
    expect(srcTree.file_tree?.entries.every((e) => e.path.startsWith("src/"))).toBe(true);
    expect(srcTree.file_tree?.entries.map((e) => e.path)).toContain("src/app.ts");

    const singleFileTree = await service.inspect({ repo_id: "fixture", command: "file_tree", ref: "HEAD", path: "src/app.ts" });
    expect(singleFileTree.file_tree?.entries).toHaveLength(1);
    expect(singleFileTree.file_tree?.entries[0]).toMatchObject({ path: "src/app.ts", name: "app.ts", type: "blob" });
  });

  test("supports show (commit + annotated tag + blob slicing), blame, rev_parse, merge_base, and shortlog", async () => {
    const { root } = await createRichGitFixture();
    const service = new GitInspectService(root);

    // show commit
    const showCommit = await service.inspect({ repo_id: "fixture", command: "show", ref: "feature/beta", include_patch: true });
    expect(GitInspectResultSchema.parse(showCommit)).toBeTruthy();
    expect(showCommit.show?.kind).toBe("commit");
    expect(showCommit.show?.commit?.subject).toBe("Add beta module");
    expect(showCommit.show?.commit?.files[0]?.hunks.length).toBeGreaterThan(0);

    // show annotated tag dereferences cleanly to its target commit
    const showAnnotatedTag = await service.inspect({ repo_id: "fixture", command: "show", ref: "v1.0.0", include_patch: true });
    expect(GitInspectResultSchema.parse(showAnnotatedTag)).toBeTruthy();
    expect(showAnnotatedTag.show?.kind).toBe("commit");
    expect(showAnnotatedTag.show?.commit?.sha).toMatch(/^[0-9a-f]{40}$/);
    expect(showAnnotatedTag.show?.commit?.subject).toBe("Merge feature/alpha");

    // show blob with exact line count (no trailing newline extra empty line) and later line range with small max_bytes
    const showBlob = await service.inspect({
      repo_id: "fixture",
      command: "show",
      ref: "main",
      file_path: "src/app.ts",
      start_line: 2,
      end_line: 2,
      max_bytes: 32
    });
    expect(GitInspectResultSchema.parse(showBlob)).toBeTruthy();
    expect(showBlob.show?.kind).toBe("blob");
    expect(showBlob.show?.blob?.total_lines).toBe(2);
    expect(showBlob.show?.blob?.start_line).toBe(2);
    expect(showBlob.show?.blob?.end_line).toBe(2);
    expect(showBlob.show?.blob?.text).toBe("export const mode = 'main';");

    // blame
    const blame = await service.inspect({ repo_id: "fixture", command: "blame", ref: "main", file_path: "src/app.ts" });
    expect(GitInspectResultSchema.parse(blame)).toBeTruthy();
    expect(blame.blame?.lines.length).toBeGreaterThanOrEqual(2);
    expect(blame.blame?.lines[0]?.sha).toMatch(/^[0-9a-f]{40}$/);

    // rev_parse
    const revParse = await service.inspect({
      repo_id: "fixture",
      command: "rev_parse",
      refs: ["HEAD", "v1.0.0", "nonexistent-branch"]
    });
    expect(GitInspectResultSchema.parse(revParse)).toBeTruthy();
    expect(revParse.resolved_refs?.items).toEqual([
      expect.objectContaining({ ref: "HEAD", resolved: true, object_type: "commit" }),
      expect.objectContaining({ ref: "v1.0.0", resolved: true, object_type: "tag" }),
      expect.objectContaining({ ref: "nonexistent-branch", resolved: false, error: "REF_NOT_FOUND" })
    ]);

    // merge_base
    const mergeBase = await service.inspect({
      repo_id: "fixture",
      command: "merge_base",
      ref: "main",
      compare_ref: "feature/beta"
    });
    expect(GitInspectResultSchema.parse(mergeBase)).toBeTruthy();
    expect(mergeBase.merge_base?.sha).toMatch(/^[0-9a-f]{40}$/);

    // shortlog
    const shortlog = await service.inspect({ repo_id: "fixture", command: "shortlog", ref: "main" });
    expect(GitInspectResultSchema.parse(shortlog)).toBeTruthy();
    expect(shortlog.shortlog?.total_commits).toBeGreaterThanOrEqual(3);
    expect(shortlog.shortlog?.contributors.map((c) => c.author_name)).toEqual(expect.arrayContaining(["Alice", "Bob"]));
  });

  test("security: rejects option/flag injection and pathspec attacks without mutating repo", async () => {
    const { root } = await createRichGitFixture();
    const service = new GitInspectService(root);

    await expect(service.inspect({ repo_id: "fixture", command: "diff", ref: "--output=evil.txt" })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(service.inspect({ repo_id: "fixture", command: "diff", ref: "--no-index" })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(service.inspect({ repo_id: "fixture", command: "diff", ref: "--ext-diff" })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(service.inspect({ repo_id: "fixture", command: "log", ref: "-all" })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(service.inspect({ repo_id: "fixture", command: "show", ref: "HEAD:.env" })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(service.inspect({ repo_id: "fixture", command: "branch", pattern: "-D" })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(service.inspect({ repo_id: "fixture", command: "log", grep: "--exec=calc" })).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(service.inspect({ repo_id: "fixture", command: "status", paths: ["--cached"] })).rejects.toMatchObject({ code: "GIT_OPERATION_UNSAFE_PATHSPEC" });
    await expect(service.inspect({ repo_id: "fixture", command: "diff", paths: [":(icase).env"] })).rejects.toMatchObject({ code: "GIT_OPERATION_UNSAFE_PATHSPEC" });
    await expect(service.inspect({ repo_id: "fixture", command: "file_tree", path: "../outside" })).rejects.toMatchObject({ code: "PATH_TRAVERSAL_REJECTED" });
    await expect(service.inspect({ repo_id: "fixture", command: "show", file_path: ".git/config" })).rejects.toMatchObject({ code: "GIT_OPERATION_UNSAFE_PATHSPEC" });

    await expect(access(join(root, "evil.txt"))).rejects.toThrow();
  });

  test("security: neutralizes malicious .git/config hooks, diff.external, textconv, fsmonitor, pager, and aliases", async () => {
    const { root } = await createRichGitFixture();
    const marker = join(root, "rce-canary.txt");
    const touchCmd = `node -e "require('fs').writeFileSync(${JSON.stringify(marker)}, 'pwned')"`;

    await git(root, ["config", "diff.external", touchCmd]);
    await git(root, ["config", "core.pager", touchCmd]);
    await git(root, ["config", "core.fsmonitor", touchCmd]);
    await git(root, ["config", "diff.evil.textconv", touchCmd]);
    await git(root, ["config", "alias.status", `!${touchCmd}`]);
    await writeFile(join(root, ".gitattributes"), "*.ts diff=evil\n");
    await writeFile(join(root, "src", "app.ts"), "export const app = 123;\n");

    const service = new GitInspectService(root);
    await service.inspect({ repo_id: "fixture", command: "status" });
    await service.inspect({ repo_id: "fixture", command: "diff" });
    await service.inspect({ repo_id: "fixture", command: "log", include_stat: true });
    await service.inspect({ repo_id: "fixture", command: "show", ref: "HEAD", include_patch: true });
    await service.inspect({ repo_id: "fixture", command: "commit_tree" });

    await expect(access(marker)).rejects.toThrow();
    await expect(access(join(root, ".git", "index.lock"))).rejects.toThrow();
  });

  test("security: isolates secrets, .env.example with real secret, delegation artifacts, and redacts secret tokens", async () => {
    const { root } = await createRichGitFixture();
    const internalPath = ".ChAtGpT/CoDeX-RuNs/2026-07-13T170000Z-run/RuNnEr.SeSsIoN.JsOn";
    await mkdir(dirname(join(root, internalPath)), { recursive: true });
    await mkdir(join(root, "secrets"), { recursive: true });
    await writeFile(join(root, ".env"), `API_KEY=${FAKE_SECRET_TOKEN}\n`);
    await writeFile(join(root, "secrets", "api.key"), "PRIVATE KEY DATA\n");
    await writeFile(join(root, ".env.example"), `OPENAI_API_KEY=${FAKE_SECRET_TOKEN}\n`);
    await writeFile(join(root, internalPath), '{"thread_id":"internal-canary"}\n');
    await writeFile(join(root, "src", "leaky.ts"), `export const token = "${FAKE_SECRET_TOKEN}";\n`);
    await git(root, ["add", "-f", ".env", "secrets/api.key", ".env.example", internalPath, "src/leaky.ts"]);
    await git(root, ["commit", "-m", `Add config with ${FAKE_SECRET_TOKEN}`]);

    // Also modify tracked secrets and add untracked id_rsa
    await writeFile(join(root, ".env"), `API_KEY=${FAKE_SECRET_TOKEN}-v2\n`);
    await writeFile(join(root, ".env.example"), `OPENAI_API_KEY=${FAKE_SECRET_TOKEN}\nEXTRA=1\n`);
    await writeFile(join(root, "id_rsa"), "SSH KEY\n");
    await writeFile(join(root, internalPath), '{"thread_id":"internal-canary-2"}\n');
    await writeFile(join(root, "src", "leaky.ts"), `export const token = "${FAKE_SECRET_TOKEN}";\nexport const x = 2;\n`);

    const service = new GitInspectService(root);

    // 1. status: hides .env, id_rsa, internal artifact
    const status = await service.inspect({ repo_id: "fixture", command: "status" });
    const statusJson = JSON.stringify(status);
    expect(statusJson).not.toContain(".env\"");
    expect(statusJson).not.toContain("id_rsa");
    expect(statusJson).not.toContain("internal-canary");
    expect(statusJson).not.toContain("RuNnEr.SeSsIoN");
    expect(status.warnings.some((w) => w.includes("secret-candidate"))).toBe(true);

    // 2. diff: omits .env & .env.example (real secret), hides internal artifact, redacts token in src/leaky.ts
    const diff = await service.inspect({ repo_id: "fixture", command: "diff" });
    const diffJson = JSON.stringify(diff);
    expect(diffJson).not.toContain(FAKE_SECRET_TOKEN);
    expect(diffJson).not.toContain("internal-canary");
    expect(diff.diff?.files.map((f) => f.path)).toEqual(["src/leaky.ts"]);
    expect(diff.diff?.omitted_secret_files).toBeGreaterThanOrEqual(2);
    expect(diffJson).toContain("[REDACTED_SECRET]");

    // 3. log: redacts commit subject, omits secret & internal paths from stats
    const log = await service.inspect({ repo_id: "fixture", command: "log", limit: 1, include_stat: true });
    const logJson = JSON.stringify(log);
    expect(logJson).not.toContain(FAKE_SECRET_TOKEN);
    expect(logJson).not.toContain("RuNnEr.SeSsIoN");
    expect(log.commits?.items[0]?.files?.map((f) => f.path)).not.toContain(".env");
    expect(log.commits?.items[0]?.files?.map((f) => f.path)).not.toContain("secrets/api.key");
    expect(log.commits?.items[0]?.subject).toContain("[REDACTED_SECRET]");

    // 4. file_tree: omits secrets & internal artifacts, records secret_candidates count
    const fileTree = await service.inspect({ repo_id: "fixture", command: "file_tree", ref: "HEAD", recursive: true });
    const treePaths = fileTree.file_tree?.entries.map((e) => e.path) ?? [];
    expect(treePaths).not.toContain(".env");
    expect(treePaths).not.toContain("secrets/api.key");
    expect(treePaths.some((p) => p.toLowerCase().includes("runner.session.json"))).toBe(false);
    expect(fileTree.file_tree?.excluded_summary.secret_candidates).toBeGreaterThanOrEqual(2);

    // 5. show commit: redacts subject & patch, omits secret paths
    const showCommit = await service.inspect({ repo_id: "fixture", command: "show", ref: "HEAD", include_patch: true });
    const showCommitJson = JSON.stringify(showCommit);
    expect(showCommitJson).not.toContain(FAKE_SECRET_TOKEN);
    expect(showCommitJson).not.toContain("internal-canary");
    expect(showCommit.show?.commit?.files.map((f) => f.path)).toEqual(["src/leaky.ts"]);

    // 6. show blob & blame: block secret paths, internal artifacts, .env.example with secret; redact src/leaky.ts
    await expect(service.inspect({ repo_id: "fixture", command: "show", file_path: ".env" })).rejects.toMatchObject({ code: "SECRET_CANDIDATE_BLOCKED" });
    await expect(service.inspect({ repo_id: "fixture", command: "show", file_path: internalPath })).rejects.toMatchObject({ code: "INTERNAL_ARTIFACT_BLOCKED" });
    await expect(service.inspect({ repo_id: "fixture", command: "show", file_path: ".env.example" })).rejects.toMatchObject({ code: "SECRET_CANDIDATE_BLOCKED" });
    await expect(service.inspect({ repo_id: "fixture", command: "blame", file_path: ".env" })).rejects.toMatchObject({ code: "SECRET_CANDIDATE_BLOCKED" });
    await expect(service.inspect({ repo_id: "fixture", command: "blame", file_path: ".env.example" })).rejects.toMatchObject({ code: "SECRET_CANDIDATE_BLOCKED" });

    const showLeaky = await service.inspect({ repo_id: "fixture", command: "show", file_path: "src/leaky.ts" });
    expect(showLeaky.show?.blob?.text).not.toContain(FAKE_SECRET_TOKEN);
    expect(showLeaky.show?.blob?.text).toContain("[REDACTED_SECRET]");

    const blameLeaky = await service.inspect({ repo_id: "fixture", command: "blame", file_path: "src/leaky.ts" });
    expect(JSON.stringify(blameLeaky)).not.toContain(FAKE_SECRET_TOKEN);
    expect(blameLeaky.blame?.lines[0]?.content).toContain("[REDACTED_SECRET]");
  });

  test("security: handles binary files safely and enforces repo-root confinement & symlink blocking", async () => {
    const { root } = await createRichGitFixture();
    await writeFile(join(root, "assets.bin"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02, 0x03]));
    await git(root, ["add", "assets.bin"]);
    await git(root, ["commit", "-m", "Add binary asset"]);

    const service = new GitInspectService(root);
    await expect(service.inspect({ repo_id: "fixture", command: "show", file_path: "assets.bin" })).rejects.toMatchObject({
      code: "BINARY_FILE_REJECTED"
    });
    await expect(service.inspect({ repo_id: "fixture", command: "blame", file_path: "assets.bin" })).rejects.toMatchObject({
      code: "BINARY_FILE_REJECTED"
    });

    const showBinCommit = await service.inspect({ repo_id: "fixture", command: "show", ref: "HEAD", include_patch: true });
    expect(showBinCommit.show?.commit?.files).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: "assets.bin", is_binary: true, hunks: [] })
    ]));

    // Subdirectory inside a git repo must be rejected by repo-root confinement
    const subService = new GitInspectService(join(root, "src"));
    await expect(subService.inspect({ repo_id: "nested", command: "log" })).rejects.toMatchObject({
      code: "GIT_ERROR"
    });

    // Symlink alias to secret file (best-effort on platforms allowing symlinks)
    await writeFile(join(root, ".env"), "SECRET=1\n");
    let symlinkCreated = false;
    try {
      await symlink(join(root, ".env"), join(root, "src", "alias.txt"));
      symlinkCreated = true;
    } catch {
      // Windows without Developer Mode may disallow symlink creation.
    }
    if (symlinkCreated) {
      await expect(service.inspect({ repo_id: "fixture", command: "show", file_path: "src/alias.txt" })).rejects.toMatchObject({
        code: "SECRET_CANDIDATE_BLOCKED"
      });
    }
  });
});

async function createRichGitFixture(): Promise<{ root: string; remoteRoot: string }> {
  const root = await mkdtemp(join(tmpdir(), "gpt-repo-git-inspect-"));
  const remoteRoot = await mkdtemp(join(tmpdir(), "gpt-repo-git-remote-"));
  tempDirs.push(root, remoteRoot);

  await git(remoteRoot, ["init", "--bare"]);
  await mkdir(join(root, "src"), { recursive: true });
  await mkdir(join(root, "docs"), { recursive: true });

  await git(root, ["init", "-b", "main"]);
  await git(root, ["config", "core.autocrlf", "false"]);
  await git(root, ["config", "user.email", "alice@example.com"]);
  await git(root, ["config", "user.name", "Alice"]);
  await git(root, ["remote", "add", "origin", remoteRoot]);

  await writeFile(join(root, "README.md"), "# Fixture\n");
  await writeFile(join(root, "src", "app.ts"), "export const app = 1;\nexport const mode = 'init';\n");
  await writeFile(join(root, "src", "util.ts"), "export const util = 1;\n");
  await git(root, ["add", "."]);
  await git(root, ["commit", "-m", "Initial commit"]);
  await git(root, ["tag", "v0.1.0"]);

  // feature/alpha branch merged into main
  await git(root, ["checkout", "-b", "feature/alpha"]);
  await writeFile(join(root, "src", "alpha.ts"), "export const alpha = true;\n");
  await git(root, ["add", "src/alpha.ts"]);
  await git(root, ["commit", "-m", "Add alpha feature"], {
    GIT_AUTHOR_NAME: "Bob",
    GIT_AUTHOR_EMAIL: "bob@example.com",
    GIT_COMMITTER_NAME: "Bob",
    GIT_COMMITTER_EMAIL: "bob@example.com"
  });

  await git(root, ["checkout", "main"]);
  await writeFile(join(root, "src", "app.ts"), "export const app = 2;\nexport const mode = 'main';\n");
  await git(root, ["add", "src/app.ts"]);
  await git(root, ["commit", "-m", "Update app on main"]);
  await git(root, ["merge", "--no-ff", "feature/alpha", "-m", "Merge feature/alpha"]);
  await git(root, ["tag", "-a", "v1.0.0", "-m", "Release 1.0.0"]);

  // feature/beta branch unmerged from main
  await git(root, ["checkout", "-b", "feature/beta"]);
  await writeFile(join(root, "src", "beta.ts"), "export const beta = true;\n");
  await git(root, ["add", "src/beta.ts"]);
  await git(root, ["commit", "-m", "Add beta module"]);

  await git(root, ["checkout", "main"]);
  return { root, remoteRoot };
}

async function git(cwd: string, args: string[], extraEnv: Record<string, string> = {}): Promise<void> {
  await execFileAsync("git", args, {
    cwd,
    env: {
      PATH: process.env.PATH ?? "",
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      ...(process.env.WINDIR ? { WINDIR: process.env.WINDIR } : {}),
      ...extraEnv
    }
  });
}
