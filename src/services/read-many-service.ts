import { clampEffectiveLimits, clampReadLimits, type EffectiveLimits, type ReadLimits } from "../policies/limits.js";
import { PathSandbox } from "./path-sandbox.js";
import { FileReader } from "./file-reader.js";
import { RepoTreeService } from "./repo-tree-service.js";
import { isExcludedByGlob, matchesGlob } from "./glob-service.js";
import { RepoReaderError, toRepoReaderError } from "../runtime/errors.js";

export type ReadManyOptions = {
  paths?: string[];
  include_globs?: string[];
  exclude_globs?: string[];
  max_files?: number;
  max_bytes_per_file?: number;
  max_total_bytes?: number;
  cursor?: string;
};

export type ReadManyResult = {
  files: Array<Awaited<ReturnType<FileReader["read"]>>>;
  skipped: Array<{ path: string; reason: string }>;
  matched_count: number;
  returned_count: number;
  total_bytes_returned: number;
  remaining_count: number;
  truncated: boolean;
  next_cursor?: string;
};

export class ReadManyService {
  private readonly limits: ReadLimits;
  private readonly treeLimits: Partial<Pick<EffectiveLimits, "max_depth" | "max_tree_entries">>;

  constructor(
    private readonly sandbox: PathSandbox,
    limits?: Partial<EffectiveLimits>
  ) {
    this.limits = clampReadLimits(limits);
    const effective = clampEffectiveLimits(limits);
    this.treeLimits = {
      max_depth: effective.max_depth,
      max_tree_entries: effective.max_tree_entries
    };
  }

  async readMany(options: ReadManyOptions): Promise<ReadManyResult> {
    if ((options.paths?.length ?? 0) === 0 && (options.include_globs?.length ?? 0) === 0) {
      throw new RepoReaderError("VALIDATION_ERROR", "repo_read_many requires paths or include_globs.");
    }

    const reader = new FileReader(this.sandbox, this.limits);
    const paths = await this.expandPaths(options);
    const start = parseCursor(options.cursor);
    const maxFiles = Math.min(options.max_files ?? this.limits.max_files, this.limits.max_files);
    const effectivePerFileBytes = Math.min(
      options.max_bytes_per_file ?? this.limits.max_bytes_per_file,
      this.limits.max_bytes_per_file
    );
    const maxTotalBytes = Math.min(
      options.max_total_bytes ?? this.limits.max_total_bytes,
      this.limits.max_total_bytes
    );
    const window = paths.slice(start, start + maxFiles);
    const files: ReadManyResult["files"] = [];
    const skipped: ReadManyResult["skipped"] = [];
    let totalBytes = 0;
    let firstBudgetSkippedIndex: number | undefined;

    for (let index = 0; index < window.length; index += 1) {
      const path = window[index]!;
      try {
        const file = await reader.read({ path, max_bytes: effectivePerFileBytes });
        if (totalBytes + file.bytes_returned > maxTotalBytes) {
          skipped.push({ path, reason: "MAX_TOTAL_BYTES_EXCEEDED" });
          if (files.length > 0) {
            firstBudgetSkippedIndex = start + index;
            break;
          }
          continue;
        }
        totalBytes += file.bytes_returned;
        files.push(file);
      } catch (error) {
        const normalized = toRepoReaderError(error);
        if (normalized.code !== "INTERNAL_ARTIFACT_BLOCKED") {
          skipped.push({ path, reason: normalized.code });
        }
      }
    }

    const nextIndex = firstBudgetSkippedIndex ?? (start + window.length);
    const remainingCount = Math.max(0, paths.length - nextIndex);
    const truncated = remainingCount > 0;
    return {
      files,
      skipped,
      matched_count: paths.length,
      returned_count: files.length,
      total_bytes_returned: totalBytes,
      remaining_count: remainingCount,
      truncated,
      next_cursor: truncated ? String(nextIndex) : undefined
    };
  }

  private async expandPaths(options: ReadManyOptions): Promise<string[]> {
    const explicitPaths = options.paths ?? [];
    const treeEntries: Array<{ path: string; type: string }> = [];
    if (options.include_globs?.length) {
      const treeService = new RepoTreeService(this.sandbox, this.treeLimits);
      let treeCursor: string | undefined;
      for (let page = 0; page < this.limits.max_read_many_tree_pages; page += 1) {
        const pageResult = await treeService.tree({
          include_files: true,
          respect_default_excludes: true,
          cursor: treeCursor
        });
        treeEntries.push(...pageResult.entries);
        if (!pageResult.truncated || !pageResult.next_cursor) {
          break;
        }
        treeCursor = pageResult.next_cursor;
      }
    }
    const globPaths = (options.include_globs ?? []).flatMap((glob) =>
      treeEntries
        .filter((entry) => entry.type === "file" && matchesGlob(entry.path, glob))
        .map((entry) => entry.path)
    );
    return [...new Set([...explicitPaths, ...globPaths])]
      .filter((path) => !isExcludedByGlob(path, options.exclude_globs))
      .sort((a, b) => explicitPaths.includes(a) && explicitPaths.includes(b) ? 0 : a.localeCompare(b));
  }
}

function parseCursor(cursor?: string): number {
  if (!cursor) {
    return 0;
  }
  const parsed = Number.parseInt(cursor, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}
