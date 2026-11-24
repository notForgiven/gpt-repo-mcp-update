export const HARD_LIMIT_CAPS = {
  max_files: 250,
  max_bytes_per_file: 2_097_152,
  max_file_bytes: 52_428_800,
  max_total_bytes: 4_194_304,
  max_read_many_tree_pages: 25
} as const;

export const DEFAULT_LIMITS = {
  max_files: 100,
  max_bytes_per_file: 256_000,
  max_file_bytes: 10_485_760,
  max_total_bytes: 1_500_000,
  max_read_many_tree_pages: 10,
  max_search_results: 100,
  max_tree_entries: 2_000,
  max_task_inventory_files: 5_000,
  max_task_inventory_tree_pages: 20,
  max_task_inventory_file_bytes: 128_000,
  max_project_brief_doc_bytes: 32_000,
  max_decision_log_source_bytes: 32_000,
  max_decision_log_sources: 20,
  max_change_plan_files: 30,
  max_change_plan_tree_pages: 5,
  max_depth: 8,
  max_diff_bytes: 256_000,
  git_read_timeout_ms: 10_000,
  max_git_read_timeout_ms: 15_000,
  max_git_log_commits: 100,
  max_git_tree_entries: 2_000,
  max_git_tree_depth: 8,
  max_git_refs: 500,
  max_git_blame_lines: 500,
  max_git_show_bytes: 256_000,
  max_git_status_entries: 2_000,
  max_git_rev_parse_refs: 50
} as const;

export type ReadLimits = {
  max_files: number;
  max_bytes_per_file: number;
  max_file_bytes: number;
  max_total_bytes: number;
  max_read_many_tree_pages: number;
};

export type EffectiveLimits = ReadLimits & {
  max_search_results: number;
  max_tree_entries: number;
  max_task_inventory_files: number;
  max_task_inventory_tree_pages: number;
  max_task_inventory_file_bytes: number;
  max_project_brief_doc_bytes: number;
  max_depth: number;
  max_diff_bytes: number;
};

export function clampReadLimits(partial?: Partial<ReadLimits>): ReadLimits {
  return {
    max_files: clampLimit(partial?.max_files, DEFAULT_LIMITS.max_files, HARD_LIMIT_CAPS.max_files),
    max_bytes_per_file: clampLimit(
      partial?.max_bytes_per_file,
      DEFAULT_LIMITS.max_bytes_per_file,
      HARD_LIMIT_CAPS.max_bytes_per_file
    ),
    max_file_bytes: clampLimit(
      partial?.max_file_bytes,
      DEFAULT_LIMITS.max_file_bytes,
      HARD_LIMIT_CAPS.max_file_bytes
    ),
    max_total_bytes: clampLimit(
      partial?.max_total_bytes,
      DEFAULT_LIMITS.max_total_bytes,
      HARD_LIMIT_CAPS.max_total_bytes
    ),
    max_read_many_tree_pages: clampLimit(
      partial?.max_read_many_tree_pages,
      DEFAULT_LIMITS.max_read_many_tree_pages,
      HARD_LIMIT_CAPS.max_read_many_tree_pages
    )
  };
}

export const EFFECTIVE_LIMIT_CAPS = {
  ...HARD_LIMIT_CAPS,
  max_search_results: 1_000,
  max_tree_entries: 10_000,
  max_task_inventory_files: 20_000,
  max_task_inventory_tree_pages: 100,
  max_task_inventory_file_bytes: 1_048_576,
  max_project_brief_doc_bytes: 256_000,
  max_depth: 32,
  max_diff_bytes: 2_097_152
} as const;

export function clampEffectiveLimits(partial?: Partial<EffectiveLimits>): EffectiveLimits {
  return {
    ...clampReadLimits(partial),
    max_search_results: clampLimit(
      partial?.max_search_results,
      DEFAULT_LIMITS.max_search_results,
      EFFECTIVE_LIMIT_CAPS.max_search_results
    ),
    max_tree_entries: clampLimit(
      partial?.max_tree_entries,
      DEFAULT_LIMITS.max_tree_entries,
      EFFECTIVE_LIMIT_CAPS.max_tree_entries
    ),
    max_task_inventory_files: clampLimit(
      partial?.max_task_inventory_files,
      DEFAULT_LIMITS.max_task_inventory_files,
      EFFECTIVE_LIMIT_CAPS.max_task_inventory_files
    ),
    max_task_inventory_tree_pages: clampLimit(
      partial?.max_task_inventory_tree_pages,
      DEFAULT_LIMITS.max_task_inventory_tree_pages,
      EFFECTIVE_LIMIT_CAPS.max_task_inventory_tree_pages
    ),
    max_task_inventory_file_bytes: clampLimit(
      partial?.max_task_inventory_file_bytes,
      DEFAULT_LIMITS.max_task_inventory_file_bytes,
      EFFECTIVE_LIMIT_CAPS.max_task_inventory_file_bytes
    ),
    max_project_brief_doc_bytes: clampLimit(
      partial?.max_project_brief_doc_bytes,
      DEFAULT_LIMITS.max_project_brief_doc_bytes,
      EFFECTIVE_LIMIT_CAPS.max_project_brief_doc_bytes
    ),
    max_depth: clampLimit(
      partial?.max_depth,
      DEFAULT_LIMITS.max_depth,
      EFFECTIVE_LIMIT_CAPS.max_depth
    ),
    max_diff_bytes: clampLimit(
      partial?.max_diff_bytes,
      DEFAULT_LIMITS.max_diff_bytes,
      EFFECTIVE_LIMIT_CAPS.max_diff_bytes
    )
  };
}

function clampLimit(value: number | undefined, fallback: number, cap: number): number {
  if (value === undefined || Number.isNaN(value)) {
    return fallback;
  }
  if (!Number.isFinite(value)) {
    return value > 0 ? cap : 1;
  }
  return Math.min(Math.max(1, Math.floor(value)), cap);
}
