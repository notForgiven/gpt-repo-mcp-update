import { readFile, realpath } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { z } from "zod";
import {
  clampEffectiveLimits,
  clampReadLimits,
  type EffectiveLimits,
  type ReadLimits
} from "../policies/limits.js";
import { RepoReaderError } from "../runtime/errors.js";
import { RepoConfigSchema, RepoReaderConfigSchema } from "../config/schema.js";
import { parseConfigJson } from "../config/store.js";

type ParsedRepoConfig = z.infer<typeof RepoConfigSchema>;
export type RepoConfig = Omit<ParsedRepoConfig, "writes" | "operations"> & {
  writes?: ParsedRepoConfig["writes"];
  operations?: ParsedRepoConfig["operations"];
};
export type RepoReaderConfig = z.infer<typeof RepoReaderConfigSchema>;
type RepoReaderConfigInput = z.input<typeof RepoReaderConfigSchema>;

export class RootRegistry {
  private constructor(
    private readonly repos: RepoConfig[],
    readonly limits: ReadLimits,
    readonly effectiveLimits: EffectiveLimits,
    readonly codeIntelligence: RepoReaderConfig["code_intelligence"]
  ) {}

  static async fromConfig(
    config: RepoReaderConfigInput,
    options: { baseDir?: string } = {}
  ): Promise<RootRegistry> {
    const parsed = RepoReaderConfigSchema.parse(config);
    const baseDir = options.baseDir ?? process.cwd();
    const repos: RepoConfig[] = [];
    for (const repo of parsed.repos) {
      repos.push({ ...repo, root: await realpath(resolve(baseDir, repo.root)) });
    }
    return new RootRegistry(
      repos,
      clampReadLimits(parsed.limits),
      clampEffectiveLimits(parsed.limits),
      parsed.code_intelligence
    );
  }

  static async fromFile(configPath: string): Promise<RootRegistry> {
    const resolvedPath = resolve(configPath);
    const raw = await readFile(resolvedPath, "utf8");
    return RootRegistry.fromConfig(parseConfigJson(raw) as RepoReaderConfigInput, {
      baseDir: dirname(resolvedPath)
    });
  }

  list(): Array<Pick<RepoConfig, "repo_id" | "display_name" | "root">> {
    return this.repos.map((repo) => ({
      repo_id: repo.repo_id,
      display_name: repo.display_name,
      root: repo.root
    }));
  }

  get(repoId: string): RepoConfig {
    const repo = this.repos.find((candidate) => candidate.repo_id === repoId);
    if (!repo) {
      throw new RepoReaderError("UNKNOWN_REPO", `Unknown repo_id: ${repoId}`);
    }
    return repo;
  }
}
