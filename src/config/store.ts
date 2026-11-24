import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { atomicWriteJson, isNotFoundError } from "../runtime/fs-helpers.js";
import { RepoReaderConfigSchema, type RepoReaderConfig } from "./schema.js";

export const DEFAULT_CONFIG_FILENAME = "./config.local.json";

export function resolveConfigPath(options: {
  cliConfigPath?: string;
  env: NodeJS.ProcessEnv;
  cwd: string;
}): string {
  const selected = firstNonEmpty(
    options.cliConfigPath,
    options.env.GPT_REPO_CONFIG,
    options.env.REPO_READER_CONFIG
  ) ?? DEFAULT_CONFIG_FILENAME;
  return resolve(options.cwd, selected);
}

export function resolveServerConfigPath(options: {
  env: NodeJS.ProcessEnv;
  cwd: string;
}): { configPath: string; explicit: boolean } {
  const explicitValue = firstNonEmpty(
    options.env.GPT_REPO_CONFIG,
    options.env.REPO_READER_CONFIG
  );
  if (explicitValue !== undefined) {
    return {
      configPath: resolve(options.cwd, explicitValue),
      explicit: true
    };
  }
  return {
    configPath: resolve(options.cwd, DEFAULT_CONFIG_FILENAME),
    explicit: false
  };
}

export function parseConfigJson(raw: string): unknown {
  const withoutBom = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  return JSON.parse(withoutBom);
}

export async function loadConfig(configPath: string): Promise<RepoReaderConfig> {
  try {
    const raw = await readFile(configPath, "utf8");
    return RepoReaderConfigSchema.parse(parseConfigJson(raw));
  } catch (error) {
    if (isNotFoundError(error)) {
      return RepoReaderConfigSchema.parse({});
    }
    throw error;
  }
}

export async function readConfigDocument(configPath: string): Promise<unknown> {
  const raw = await readFile(configPath, "utf8");
  return parseConfigJson(raw);
}

export async function writeConfigAtomic(configPath: string, config: RepoReaderConfig): Promise<void> {
  await atomicWriteJson(configPath, config);
}

function firstNonEmpty(...values: Array<string | undefined>): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  return undefined;
}
