import { execFile } from "node:child_process";
import { mkdir, mkdtemp, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { describe, expect, test } from "vitest";
import {
  loadConfig,
  readConfigDocument,
  resolveConfigPath,
  resolveServerConfigPath
} from "../src/config/store.js";
import { validateConfigDocument } from "../src/config/validation.js";
import {
  clampEffectiveLimits,
  clampReadLimits,
  DEFAULT_LIMITS,
  EFFECTIVE_LIMIT_CAPS,
  HARD_LIMIT_CAPS
} from "../src/policies/limits.js";
import { RootRegistry } from "../src/services/root-registry.js";
import {
  gitDiffHandler,
  projectBriefHandler,
  searchHandler,
  taskInventoryHandler,
  treeHandler
} from "../src/tools/handlers.js";

const execFileAsync = promisify(execFile);

describe("config store", () => {
  test.each([
    {
      name: "top-level config",
      path: [],
      document: { repos: [], limits: {}, limitz: {} }
    },
    {
      name: "repository",
      path: ["repos", 0],
      document: {
        repos: [{ repo_id: "repo", display_name: "Repo", root: ".", display_nam: "Typo" }],
        limits: {}
      }
    },
    {
      name: "write policy",
      path: ["repos", 0, "writes"],
      document: {
        repos: [{
          repo_id: "repo",
          display_name: "Repo",
          root: ".",
          writes: { enabledd: true }
        }],
        limits: {}
      }
    },
    {
      name: "operations policy",
      path: ["repos", 0, "operations"],
      document: {
        repos: [{
          repo_id: "repo",
          display_name: "Repo",
          root: ".",
          operations: { git_stage_enabledd: true }
        }],
        limits: {}
      }
    },
    {
      name: "limits",
      path: ["limits"],
      document: { repos: [], limits: { max_filse: 10 } }
    }
  ])("rejects unknown fields in $name", async ({ document, path }) => {
    const sandbox = await mkdtemp(join(tmpdir(), "config-store-"));
    const configPath = join(sandbox, "config.local.json");
    await writeFile(configPath, JSON.stringify(document));

    await expect(loadConfig(configPath)).rejects.toMatchObject({
      issues: expect.arrayContaining([
        expect.objectContaining({
          code: "unrecognized_keys",
          path
        })
      ])
    });
  });

  test("migrates legacy ship-like operations to validation-enabled runtime policy", async () => {
    const sandbox = await mkdtemp(join(tmpdir(), "config-store-"));
    const configPath = join(sandbox, "config.local.json");
    const repoRoot = join(sandbox, "repo");
    await mkdir(join(repoRoot, ".git"), { recursive: true });
    await writeFile(configPath, JSON.stringify({
      repos: [
        {
          repo_id: "ship-like",
          display_name: "Ship Like",
          root: repoRoot,
          operations: {
            enabled: true,
            git_stage_enabled: true,
            git_commit_enabled: true,
            validation_test_path_globs: [],
            cleanup_enabled: true
          }
        }
      ],
      limits: {}
    }, null, 2));

    const config = await loadConfig(configPath);

    expect(config.repos[0]?.operations).toMatchObject({
      enabled: true,
      git_stage_enabled: true,
      git_commit_enabled: true,
      validation_enabled: true,
      validation_test_path_globs: ["tests/**", "**/*.test.ts", "**/*.spec.ts"],
      cleanup_enabled: true
    });
  });

  test("preserves an explicit ship-like validation opt-out", async () => {
    const sandbox = await mkdtemp(join(tmpdir(), "config-store-"));
    const configPath = join(sandbox, "config.local.json");
    const repoRoot = join(sandbox, "repo");
    await mkdir(join(repoRoot, ".git"), { recursive: true });
    await writeFile(configPath, JSON.stringify({
      repos: [{
        repo_id: "explicit-opt-out",
        display_name: "Explicit Opt Out",
        root: repoRoot,
        operations: {
          enabled: true,
          git_stage_enabled: true,
          git_commit_enabled: true,
          validation_enabled: false,
          validation_test_path_globs: [],
          cleanup_enabled: true
        }
      }],
      limits: {}
    }, null, 2));

    const config = await loadConfig(configPath);

    expect(config.repos[0]?.operations).toMatchObject({
      validation_enabled: false,
      validation_test_path_globs: []
    });
  });

  test("clamps read limits to [1, HARD_LIMIT_CAPS] with sensible defaults", () => {
    expect(clampReadLimits()).toEqual({
      max_files: DEFAULT_LIMITS.max_files,
      max_bytes_per_file: DEFAULT_LIMITS.max_bytes_per_file,
      max_file_bytes: DEFAULT_LIMITS.max_file_bytes,
      max_total_bytes: DEFAULT_LIMITS.max_total_bytes,
      max_read_many_tree_pages: DEFAULT_LIMITS.max_read_many_tree_pages
    });

    expect(clampReadLimits({
      max_files: 999,
      max_bytes_per_file: 10_000_000,
      max_file_bytes: 999_999_999,
      max_total_bytes: 99_999_999,
      max_read_many_tree_pages: 500
    })).toEqual({
      max_files: HARD_LIMIT_CAPS.max_files,
      max_bytes_per_file: HARD_LIMIT_CAPS.max_bytes_per_file,
      max_file_bytes: HARD_LIMIT_CAPS.max_file_bytes,
      max_total_bytes: HARD_LIMIT_CAPS.max_total_bytes,
      max_read_many_tree_pages: HARD_LIMIT_CAPS.max_read_many_tree_pages
    });

    expect(clampReadLimits({
      max_files: 0,
      max_bytes_per_file: -10,
      max_file_bytes: Number.NaN,
      max_total_bytes: Number.POSITIVE_INFINITY,
      max_read_many_tree_pages: Number.NEGATIVE_INFINITY
    })).toEqual({
      max_files: 1,
      max_bytes_per_file: 1,
      max_file_bytes: DEFAULT_LIMITS.max_file_bytes,
      max_total_bytes: HARD_LIMIT_CAPS.max_total_bytes,
      max_read_many_tree_pages: 1
    });
  });

  test("clamps all effective limits to [1, EFFECTIVE_LIMIT_CAPS] with safe defaults", () => {
    expect(clampEffectiveLimits()).toEqual({
      max_files: DEFAULT_LIMITS.max_files,
      max_bytes_per_file: DEFAULT_LIMITS.max_bytes_per_file,
      max_file_bytes: DEFAULT_LIMITS.max_file_bytes,
      max_total_bytes: DEFAULT_LIMITS.max_total_bytes,
      max_read_many_tree_pages: DEFAULT_LIMITS.max_read_many_tree_pages,
      max_search_results: DEFAULT_LIMITS.max_search_results,
      max_tree_entries: DEFAULT_LIMITS.max_tree_entries,
      max_task_inventory_files: DEFAULT_LIMITS.max_task_inventory_files,
      max_task_inventory_tree_pages: DEFAULT_LIMITS.max_task_inventory_tree_pages,
      max_task_inventory_file_bytes: DEFAULT_LIMITS.max_task_inventory_file_bytes,
      max_project_brief_doc_bytes: DEFAULT_LIMITS.max_project_brief_doc_bytes,
      max_depth: DEFAULT_LIMITS.max_depth,
      max_diff_bytes: DEFAULT_LIMITS.max_diff_bytes
    });

    expect(clampEffectiveLimits({
      max_search_results: 999_999,
      max_tree_entries: 999_999,
      max_task_inventory_files: 999_999,
      max_task_inventory_tree_pages: 999_999,
      max_task_inventory_file_bytes: 99_999_999,
      max_project_brief_doc_bytes: 99_999_999,
      max_depth: 999,
      max_diff_bytes: 99_999_999
    })).toMatchObject({
      max_search_results: EFFECTIVE_LIMIT_CAPS.max_search_results,
      max_tree_entries: EFFECTIVE_LIMIT_CAPS.max_tree_entries,
      max_task_inventory_files: EFFECTIVE_LIMIT_CAPS.max_task_inventory_files,
      max_task_inventory_tree_pages: EFFECTIVE_LIMIT_CAPS.max_task_inventory_tree_pages,
      max_task_inventory_file_bytes: EFFECTIVE_LIMIT_CAPS.max_task_inventory_file_bytes,
      max_project_brief_doc_bytes: EFFECTIVE_LIMIT_CAPS.max_project_brief_doc_bytes,
      max_depth: EFFECTIVE_LIMIT_CAPS.max_depth,
      max_diff_bytes: EFFECTIVE_LIMIT_CAPS.max_diff_bytes
    });

    expect(clampEffectiveLimits({
      max_search_results: 0,
      max_tree_entries: -5,
      max_task_inventory_files: Number.NaN,
      max_task_inventory_tree_pages: Number.POSITIVE_INFINITY,
      max_task_inventory_file_bytes: Number.NEGATIVE_INFINITY,
      max_project_brief_doc_bytes: Number.NaN,
      max_depth: Number.POSITIVE_INFINITY,
      max_diff_bytes: 0
    })).toMatchObject({
      max_search_results: 1,
      max_tree_entries: 1,
      max_task_inventory_files: DEFAULT_LIMITS.max_task_inventory_files,
      max_task_inventory_tree_pages: EFFECTIVE_LIMIT_CAPS.max_task_inventory_tree_pages,
      max_task_inventory_file_bytes: 1,
      max_project_brief_doc_bytes: DEFAULT_LIMITS.max_project_brief_doc_bytes,
      max_depth: EFFECTIVE_LIMIT_CAPS.max_depth,
      max_diff_bytes: 1
    });
  });

  test("accepts valid read limits up to hard caps in config store and RootRegistry", async () => {
    const sandbox = await mkdtemp(join(tmpdir(), "config-store-limits-"));
    const configPath = join(sandbox, "config.local.json");
    const repoRoot = join(sandbox, "repo");
    await mkdir(repoRoot, { recursive: true });
    await writeFile(configPath, JSON.stringify({
      repos: [{ repo_id: "repo", display_name: "Repo", root: repoRoot }],
      limits: {
        max_files: HARD_LIMIT_CAPS.max_files,
        max_bytes_per_file: HARD_LIMIT_CAPS.max_bytes_per_file,
        max_file_bytes: HARD_LIMIT_CAPS.max_file_bytes,
        max_total_bytes: HARD_LIMIT_CAPS.max_total_bytes,
        max_read_many_tree_pages: HARD_LIMIT_CAPS.max_read_many_tree_pages
      }
    }));

    const config = await loadConfig(configPath);
    const registry = await RootRegistry.fromFile(configPath);

    expect(config.limits).toMatchObject({
      max_files: HARD_LIMIT_CAPS.max_files,
      max_bytes_per_file: HARD_LIMIT_CAPS.max_bytes_per_file,
      max_file_bytes: HARD_LIMIT_CAPS.max_file_bytes,
      max_total_bytes: HARD_LIMIT_CAPS.max_total_bytes,
      max_read_many_tree_pages: HARD_LIMIT_CAPS.max_read_many_tree_pages
    });
    expect(registry.limits).toEqual({
      max_files: HARD_LIMIT_CAPS.max_files,
      max_bytes_per_file: HARD_LIMIT_CAPS.max_bytes_per_file,
      max_file_bytes: HARD_LIMIT_CAPS.max_file_bytes,
      max_total_bytes: HARD_LIMIT_CAPS.max_total_bytes,
      max_read_many_tree_pages: HARD_LIMIT_CAPS.max_read_many_tree_pages
    });
  });

  test.each([
    ["max_files", HARD_LIMIT_CAPS.max_files + 1],
    ["max_bytes_per_file", HARD_LIMIT_CAPS.max_bytes_per_file + 1],
    ["max_file_bytes", HARD_LIMIT_CAPS.max_file_bytes + 1],
    ["max_total_bytes", HARD_LIMIT_CAPS.max_total_bytes + 1],
    ["max_read_many_tree_pages", HARD_LIMIT_CAPS.max_read_many_tree_pages + 1]
  ])("rejects %s exceeding hard cap in both loadConfig and RootRegistry", async (field, value) => {
    const sandbox = await mkdtemp(join(tmpdir(), "config-store-cap-"));
    const configPath = join(sandbox, "config.local.json");
    const document = { repos: [], limits: { [field]: value } };
    await writeFile(configPath, JSON.stringify(document));

    await expect(loadConfig(configPath)).rejects.toMatchObject({
      issues: expect.arrayContaining([
        expect.objectContaining({
          code: "too_big",
          path: ["limits", field]
        })
      ])
    });

    await expect(RootRegistry.fromConfig(document)).rejects.toMatchObject({
      issues: expect.arrayContaining([
        expect.objectContaining({
          code: "too_big",
          path: ["limits", field]
        })
      ])
    });
  });

  test("loads config.example.json cleanly through both loadConfig and RootRegistry", async () => {
    const config = await loadConfig("config.example.json");
    const registry = await RootRegistry.fromFile("config.example.json");

    expect(config.limits).toEqual({
      max_files: 100,
      max_bytes_per_file: 256_000,
      max_file_bytes: 10_485_760,
      max_total_bytes: 1_500_000
    });
    expect(registry.limits).toEqual({
      max_files: 100,
      max_bytes_per_file: 256_000,
      max_file_bytes: 10_485_760,
      max_total_bytes: 1_500_000,
      max_read_many_tree_pages: 10
    });
  });

  test("resolveConfigPath and resolveServerConfigPath ignore blank env vars and default to ./config.local.json", () => {
    const cwd = join(tmpdir(), "cfg-cwd");

    expect(resolveConfigPath({ env: { GPT_REPO_CONFIG: "   ", REPO_READER_CONFIG: "" }, cwd }))
      .toBe(resolve(cwd, "./config.local.json"));

    expect(resolveConfigPath({ env: { GPT_REPO_CONFIG: "  ", REPO_READER_CONFIG: "./legacy.json" }, cwd }))
      .toBe(resolve(cwd, "./legacy.json"));

    expect(resolveServerConfigPath({ env: { GPT_REPO_CONFIG: "   " }, cwd })).toEqual({
      configPath: resolve(cwd, "./config.local.json"),
      explicit: false
    });

    expect(resolveServerConfigPath({ env: { GPT_REPO_CONFIG: " ./custom.json " }, cwd })).toEqual({
      configPath: resolve(cwd, "./custom.json"),
      explicit: true
    });
  });

  test("strips UTF-8 BOM when reading config files via store and RootRegistry", async () => {
    const sandbox = await mkdtemp(join(tmpdir(), "config-store-bom-"));
    const repoRoot = join(sandbox, "repo");
    await mkdir(join(repoRoot, ".git"), { recursive: true });
    const configPath = join(sandbox, "config.local.json");
    const json = JSON.stringify({
      repos: [{ repo_id: "bom-repo", display_name: "BOM Repo", root: repoRoot }],
      limits: { max_search_results: 42 }
    });
    await writeFile(configPath, `\uFEFF${json}`, "utf8");

    const doc = await readConfigDocument(configPath);
    expect(doc).toMatchObject({ limits: { max_search_results: 42 } });

    const loaded = await loadConfig(configPath);
    expect(loaded.repos[0]?.repo_id).toBe("bom-repo");

    const registry = await RootRegistry.fromFile(configPath);
    expect(registry.get("bom-repo").root).toBe(await realpath(repoRoot));
    expect(registry.effectiveLimits.max_search_results).toBe(42);
  });

  test("resolves relative repo.root paths against the config file directory rather than process.cwd()", async () => {
    const sandbox = await mkdtemp(join(tmpdir(), "config-store-relroot-"));
    const configDir = join(sandbox, "nested", "cfg");
    const repoRoot = join(sandbox, "nested", "my-repo");
    await mkdir(configDir, { recursive: true });
    await mkdir(join(repoRoot, ".git"), { recursive: true });
    const configPath = join(configDir, "config.local.json");
    await writeFile(configPath, JSON.stringify({
      repos: [{ repo_id: "rel", display_name: "Relative Repo", root: "../my-repo" }],
      limits: {}
    }), "utf8");

    const registry = await RootRegistry.fromFile(configPath);
    expect(registry.get("rel").root).toBe(await realpath(repoRoot));

    const validation = await validateConfigDocument(await readConfigDocument(configPath), {
      baseDir: dirname(configPath)
    });
    expect(validation.issues).toEqual([]);
    expect(validation.config?.repos[0]?.repo_id).toBe("rel");
  });

  test("preserves all configured LimitsConfigSchema fields and propagates them through tool handlers", async () => {
    const sandbox = await mkdtemp(join(tmpdir(), "config-store-propagate-"));
    const repoRoot = join(sandbox, "repo");
    await mkdir(join(repoRoot, "a", "b", "c"), { recursive: true });
    await writeFile(join(repoRoot, "README.md"), `# Title\n${"hello world ".repeat(100)}\n`);
    await writeFile(join(repoRoot, "a", "one.ts"), "// TODO: first\n// TODO: second\nexport const hit = 'needle';\nexport const hit2 = 'needle';\n");
    await writeFile(join(repoRoot, "a", "b", "two.ts"), "// TODO: third\nexport const hit3 = 'needle';\n");
    await writeFile(join(repoRoot, "a", "b", "c", "deep.ts"), "export const deep = 'needle';\n");

    await execFileAsync("git", ["init"], { cwd: repoRoot });
    await execFileAsync("git", ["config", "user.name", "Test"], { cwd: repoRoot });
    await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: repoRoot });
    await execFileAsync("git", ["add", "."], { cwd: repoRoot });
    await execFileAsync("git", ["commit", "-m", "init"], { cwd: repoRoot });
    await writeFile(join(repoRoot, "a", "one.ts"), `${"// TODO: updated\n".repeat(40)}export const hit = 'needle';\nexport const hit2 = 'needle';\n`);

    const registry = await RootRegistry.fromConfig({
      repos: [{ repo_id: "prop", display_name: "Prop", root: repoRoot }],
      limits: {
        max_depth: 1,
        max_tree_entries: 2,
        max_search_results: 1,
        max_task_inventory_files: 1,
        max_task_inventory_tree_pages: 2,
        max_task_inventory_file_bytes: 512,
        max_project_brief_doc_bytes: 32,
        max_diff_bytes: 120
      }
    });

    expect(registry.effectiveLimits).toMatchObject({
      max_depth: 1,
      max_tree_entries: 2,
      max_search_results: 1,
      max_task_inventory_files: 1,
      max_task_inventory_tree_pages: 2,
      max_task_inventory_file_bytes: 512,
      max_project_brief_doc_bytes: 32,
      max_diff_bytes: 120
    });

    const treeRes = await treeHandler({ repo_id: "prop" }, { registry });
    const treeData = treeRes.structuredContent as { entries: Array<{ path: string }>; truncated: boolean };
    expect(treeData.entries.length).toBeLessThanOrEqual(2);
    expect(treeData.truncated).toBe(true);
    expect(treeData.entries.some((entry) => entry.path.includes("a/b/c"))).toBe(false);

    const searchRegistry = await RootRegistry.fromConfig({
      repos: [{ repo_id: "prop", display_name: "Prop", root: repoRoot }],
      limits: { max_search_results: 1 }
    });
    const searchRes = await searchHandler({ repo_id: "prop", query: "needle" }, { registry: searchRegistry });
    const searchData = searchRes.structuredContent as { returned_count: number; matched_count: number; truncated: boolean };
    expect(searchData.returned_count).toBe(1);
    expect(searchData.matched_count).toBeGreaterThan(1);
    expect(searchData.truncated).toBe(true);

    const taskRegistry = await RootRegistry.fromConfig({
      repos: [{ repo_id: "prop", display_name: "Prop", root: repoRoot }],
      limits: { max_task_inventory_files: 1, max_search_results: 1 }
    });
    const taskRes = await taskInventoryHandler({ repo_id: "prop" }, { registry: taskRegistry });
    const taskData = taskRes.structuredContent as { scanned_file_count: number; returned_count: number; warnings: string[] };
    expect(taskData.scanned_file_count).toBe(1);
    expect(taskData.returned_count).toBeLessThanOrEqual(1);
    expect(taskData.warnings).toContain("SCAN_FILE_LIMIT_REACHED");

    const briefRegistry = await RootRegistry.fromConfig({
      repos: [{ repo_id: "prop", display_name: "Prop", root: repoRoot }],
      limits: { max_project_brief_doc_bytes: 32 }
    });
    const briefRes = await projectBriefHandler({ repo_id: "prop" }, { registry: briefRegistry });
    const briefData = briefRes.structuredContent as { warnings: string[] };
    expect(briefData.warnings).toContain("FILE_TRUNCATED:README.md");

    const diffRegistry = await RootRegistry.fromConfig({
      repos: [{ repo_id: "prop", display_name: "Prop", root: repoRoot }],
      limits: { max_diff_bytes: 120 }
    });
    const diffRes = await gitDiffHandler({ repo_id: "prop" }, { registry: diffRegistry });
    const diffData = diffRes.structuredContent as { truncated: boolean; truncation_reason?: string };
    expect(diffData.truncated).toBe(true);
    expect(diffData.truncation_reason).toContain("max_bytes");
  });
});
