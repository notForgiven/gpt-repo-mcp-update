import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";
import { ReadManyInputSchema, ReadManyResultSchema } from "../src/contracts/file.contract.js";
import { HARD_LIMIT_CAPS } from "../src/policies/limits.js";
import { RepoTreeService } from "../src/services/repo-tree-service.js";
import { RootRegistry } from "../src/services/root-registry.js";
import type { ReadManyResult } from "../src/services/read-many-service.js";
import { readManyHandler } from "../src/tools/handlers.js";
import { createRepoFixture } from "./fixtures/repo-fixture.js";

async function createTestFixture(): Promise<{ root: string; outside: string }> {
  try {
    return await createRepoFixture();
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== "EPERM") {
      throw error;
    }
    const root = await mkdtemp(join(tmpdir(), "repo-reader-fixture-"));
    const outside = await mkdtemp(join(tmpdir(), "repo-reader-outside-"));
    await mkdir(join(root, "src"), { recursive: true });
    await mkdir(join(root, "docs"), { recursive: true });
    await mkdir(join(root, "node_modules", "pkg"), { recursive: true });
    await mkdir(join(root, "dist"), { recursive: true });
    await mkdir(join(root, "vendor", "nested", ".git"), { recursive: true });
    await mkdir(join(root, "vendor", "submodule"), { recursive: true });
    await writeFile(join(root, "src", "app.ts"), [
      "export function rawFetch() {",
      "  return fetch('/api/users');",
      "}",
      ""
    ].join("\n"));
    await writeFile(join(root, "src", "controllers.ts"), [
      "export const controller = 'users';",
      "export const token = 'public-token';",
      ""
    ].join("\n"));
    await writeFile(join(root, "src", "admin.controller.ts"), "export const admin = true;\n");
    await writeFile(join(root, "src", "users.controller.ts"), "export const users = true;\n");
    await writeFile(join(root, "docs", "guide.md"), "# Guide\nSearchable docs\n");
    await writeFile(join(root, ".env"), "API_TOKEN=super-secret\n");
    await writeFile(join(root, "config.key"), "private-key\n");
    await writeFile(join(root, "node_modules", "pkg", "index.js"), "module.exports = 'ignored';\n");
    await writeFile(join(root, "dist", "bundle.js"), "console.log('generated');\n");
    await writeFile(join(root, "binary.bin"), Buffer.from([0, 1, 2, 3]));
    await writeFile(join(root, "vendor", "nested", "index.ts"), "export const nested = true;\n");
    await writeFile(join(root, "vendor", "submodule", ".git"), "gitdir: ../.git/modules/vendor/submodule\n");
    await writeFile(join(root, "vendor", "submodule", "README.md"), "# submodule\n");
    await writeFile(join(outside, "secret.txt"), "outside secret\n");
    return { root, outside };
  }
}

async function createContext(limits?: {
  max_files?: number;
  max_bytes_per_file?: number;
  max_file_bytes?: number;
  max_total_bytes?: number;
  max_read_many_tree_pages?: number;
}) {
  const fixture = await createTestFixture();
  const registry = await RootRegistry.fromConfig({
    repos: [{ repo_id: "fixture", display_name: "Fixture", root: fixture.root }],
    limits: limits ?? { max_files: 3, max_bytes_per_file: 128_000, max_total_bytes: 750_000 }
  });
  return { fixture, context: { registry } };
}

describe("repo_read_many", () => {
  test("rejects calls without paths or include globs", async () => {
    const { context } = await createContext();

    const result = await readManyHandler({ repo_id: "fixture" }, context);

    expect(result.isError).toBe(true);
    expect(result.structuredContent).toEqual({
      ok: false,
      error: {
        code: "VALIDATION_ERROR",
        message: "repo_read_many requires paths or include_globs.",
        retryable: false
      }
    });
  });

  test("reads explicit files and reports policy-blocked files as skipped", async () => {
    const { context } = await createContext();

    const result = await callReadMany({
      repo_id: "fixture",
      paths: ["src/app.ts", ".env", "binary.bin"]
    }, context);

    expect(result.files.map((file) => file.path)).toEqual(["src/app.ts"]);
    expect(result.skipped).toEqual([
      { path: ".env", reason: "SECRET_CANDIDATE_BLOCKED" },
      { path: "binary.bin", reason: "BINARY_FILE_REJECTED" }
    ]);
    expect(result.matched_count).toBe(3);
    expect(result.returned_count).toBe(1);
    expect(result.total_bytes_returned).toBe(result.files[0]!.bytes_returned);
    expect(result.remaining_count).toBe(0);
    expect(() => ReadManyResultSchema.parse(result)).not.toThrow();
  });

  test("supports include and exclude globs", async () => {
    const { context } = await createContext();

    const result = await callReadMany({
      repo_id: "fixture",
      include_globs: ["src/**/*.controller.ts"],
      exclude_globs: ["src/admin.*"]
    }, context);

    expect(result.files.map((file) => file.path)).toEqual(["src/users.controller.ts"]);
    expect(result.skipped).toEqual([]);
  });

  test("enforces max_files with a resumable cursor", async () => {
    const { context } = await createContext();

    const first = await callReadMany({
      repo_id: "fixture",
      paths: ["src/app.ts", "src/controllers.ts", "src/admin.controller.ts"],
      max_files: 2
    }, context);

    expect(first.files.map((file) => file.path)).toEqual(["src/app.ts", "src/controllers.ts"]);
    expect(first.truncated).toBe(true);
    expect(first.next_cursor).toBe("2");
    expect(first.remaining_count).toBe(1);
    expect(first.total_bytes_returned).toBe(
      first.files.reduce((sum, file) => sum + file.bytes_returned, 0)
    );

    const second = await callReadMany({
      repo_id: "fixture",
      paths: ["src/app.ts", "src/controllers.ts", "src/admin.controller.ts"],
      max_files: 2,
      cursor: first.next_cursor
    }, context);

    expect(second.files.map((file) => file.path)).toEqual(["src/admin.controller.ts"]);
    expect(second.truncated).toBe(false);
    expect(second.next_cursor).toBeUndefined();
    expect(second.remaining_count).toBe(0);
  });

  test("enforces max_total_bytes and keeps stable skipped reason codes", async () => {
    const { context } = await createContext();

    const result = await callReadMany({
      repo_id: "fixture",
      paths: ["src/app.ts", "src/controllers.ts"],
      max_total_bytes: 70
    }, context);

    expect(result.files.map((file) => file.path)).toEqual(["src/app.ts"]);
    expect(result.skipped).toEqual([
      { path: "src/controllers.ts", reason: "MAX_TOTAL_BYTES_EXCEEDED" }
    ]);
    expect(result.truncated).toBe(true);
    expect(result.next_cursor).toBe("1");
    expect(result.remaining_count).toBe(1);
    expect(result.total_bytes_returned).toBe(result.files[0]!.bytes_returned);
  });

  test("resumes budget-skipped files via next_cursor without dropping or duplicating files", async () => {
    const { context } = await createContext();

    const first = await callReadMany({
      repo_id: "fixture",
      paths: ["src/app.ts", "src/controllers.ts", "src/admin.controller.ts"],
      max_total_bytes: 70
    }, context);

    expect(first.files.map((file) => file.path)).toEqual(["src/app.ts"]);
    expect(first.skipped).toEqual([
      { path: "src/controllers.ts", reason: "MAX_TOTAL_BYTES_EXCEEDED" }
    ]);
    expect(first.truncated).toBe(true);
    expect(first.next_cursor).toBe("1");
    expect(first.remaining_count).toBe(2);

    const second = await callReadMany({
      repo_id: "fixture",
      paths: ["src/app.ts", "src/controllers.ts", "src/admin.controller.ts"],
      max_total_bytes: 200,
      cursor: first.next_cursor
    }, context);

    expect(second.files.map((file) => file.path)).toEqual(["src/controllers.ts", "src/admin.controller.ts"]);
    expect(second.skipped).toEqual([]);
    expect(second.truncated).toBe(false);
    expect(second.next_cursor).toBeUndefined();
    expect(second.remaining_count).toBe(0);
  });

  test("avoids infinite cursor loops when the first file alone exceeds max_total_bytes", async () => {
    const { context } = await createContext();

    const result = await callReadMany({
      repo_id: "fixture",
      paths: ["src/controllers.ts", "src/admin.controller.ts"],
      max_total_bytes: 40
    }, context);

    expect(result.files.map((file) => file.path)).toEqual(["src/admin.controller.ts"]);
    expect(result.skipped).toEqual([
      { path: "src/controllers.ts", reason: "MAX_TOTAL_BYTES_EXCEEDED" }
    ]);
    expect(result.truncated).toBe(false);
    expect(result.next_cursor).toBeUndefined();
    expect(result.remaining_count).toBe(0);
  });

  test("clamps caller max_total_bytes against configured server limits and enforces hard caps in schema", async () => {
    const { context } = await createContext({
      max_files: 10,
      max_bytes_per_file: 128_000,
      max_total_bytes: 70
    });

    const result = await callReadMany({
      repo_id: "fixture",
      paths: ["src/app.ts", "src/controllers.ts"],
      max_total_bytes: 500_000
    }, context);

    expect(result.files.map((file) => file.path)).toEqual(["src/app.ts"]);
    expect(result.skipped).toEqual([
      { path: "src/controllers.ts", reason: "MAX_TOTAL_BYTES_EXCEEDED" }
    ]);

    expect(ReadManyInputSchema.safeParse({
      repo_id: "fixture",
      paths: ["src/app.ts"],
      max_total_bytes: HARD_LIMIT_CAPS.max_total_bytes + 1
    }).success).toBe(false);
    expect(ReadManyInputSchema.safeParse({
      repo_id: "fixture",
      paths: ["src/app.ts"],
      max_files: HARD_LIMIT_CAPS.max_files + 1
    }).success).toBe(false);
    expect(ReadManyInputSchema.safeParse({
      repo_id: "fixture",
      paths: ["src/app.ts"],
      max_bytes_per_file: HARD_LIMIT_CAPS.max_bytes_per_file + 1
    }).success).toBe(false);
  });

  test("reads batches larger than 50 files under default and raised config limits", async () => {
    const fixture = await createTestFixture();
    const batchDir = join(fixture.root, "src", "batch");
    await mkdir(batchDir, { recursive: true });
    const allPaths: string[] = [];
    for (let index = 0; index < 120; index += 1) {
      const name = `file-${String(index).padStart(3, "0")}.ts`;
      await writeFile(join(batchDir, name), `export const n = ${index};\n`);
      allPaths.push(`src/batch/${name}`);
    }

    const defaultRegistry = await RootRegistry.fromConfig({
      repos: [{ repo_id: "fixture", display_name: "Fixture", root: fixture.root }]
    });
    const defaultPage = await callReadMany({
      repo_id: "fixture",
      paths: allPaths
    }, { registry: defaultRegistry });
    expect(defaultPage.returned_count).toBe(100);
    expect(defaultPage.remaining_count).toBe(20);
    expect(defaultPage.truncated).toBe(true);
    expect(defaultPage.next_cursor).toBe("100");

    const raisedRegistry = await RootRegistry.fromConfig({
      repos: [{ repo_id: "fixture", display_name: "Fixture", root: fixture.root }],
      limits: { max_files: 150 }
    });
    const raisedPage = await callReadMany({
      repo_id: "fixture",
      paths: allPaths,
      max_files: 120
    }, { registry: raisedRegistry });
    expect(raisedPage.returned_count).toBe(120);
    expect(raisedPage.remaining_count).toBe(0);
    expect(raisedPage.truncated).toBe(false);
    expect(raisedPage.next_cursor).toBeUndefined();
  });

  test("truncates large files per max_bytes_per_file without starving other files in the batch", async () => {
    const { fixture, context } = await createContext({
      max_files: 10,
      max_bytes_per_file: 2_048,
      max_total_bytes: 4_096
    });
    const bigLines = Array.from({ length: 400 }, (_, index) => `export const row_${index} = "${"z".repeat(40)}";`);
    await writeFile(join(fixture.root, "src", "huge.ts"), `${bigLines.join("\n")}\n`);

    const result = await callReadMany({
      repo_id: "fixture",
      paths: ["src/huge.ts", "src/app.ts"],
      max_bytes_per_file: 1_024,
      max_total_bytes: 2_048
    }, context);

    expect(result.skipped).toEqual([]);
    expect(result.files.map((file) => file.path)).toEqual(["src/huge.ts", "src/app.ts"]);
    expect(result.files[0]!.truncated).toBe(true);
    expect(result.files[0]!.has_more).toBe(true);
    expect(result.files[0]!.next_start_line).toBeGreaterThan(1);
    expect(result.files[0]!.bytes_returned).toBeLessThanOrEqual(1_024);
    expect(result.files[1]!.truncated).toBe(false);
    expect(result.total_bytes_returned).toBe(
      result.files[0]!.bytes_returned + result.files[1]!.bytes_returned
    );
  });

  test("paginates RepoTreeService across multiple pages for include_globs discovery", async () => {
    const { context } = await createContext({
      max_files: 20,
      max_bytes_per_file: 128_000,
      max_total_bytes: 750_000,
      max_read_many_tree_pages: 10
    });

    const originalTree = RepoTreeService.prototype.tree;
    const treeSpy = vi.spyOn(RepoTreeService.prototype, "tree").mockImplementation(function (this: RepoTreeService, options) {
      return originalTree.call(this, { ...options, page_size: 2 });
    });

    try {
      const result = await callReadMany({
        repo_id: "fixture",
        include_globs: ["src/**/*.ts"]
      }, context);

      expect(treeSpy.mock.calls.length).toBeGreaterThan(2);
      expect(result.files.map((file) => file.path)).toEqual([
        "src/admin.controller.ts",
        "src/app.ts",
        "src/controllers.ts",
        "src/users.controller.ts"
      ]);
      expect(result.remaining_count).toBe(0);
    } finally {
      treeSpy.mockRestore();
    }
  });
});

async function callReadMany(
  input: Parameters<typeof readManyHandler>[0],
  context: Awaited<ReturnType<typeof createContext>>["context"]
): Promise<ReadManyResult> {
  const result = await readManyHandler(input, context);
  return result.structuredContent as ReadManyResult;
}
