import { z } from "zod";
import { HARD_LIMIT_CAPS } from "../policies/limits.js";
import { RepoInputSchema } from "./repo.contract.js";

export const PathInputSchema = z.object({
  path: z.string().min(1)
});

export const GlobScopeSchema = z.object({
  include_globs: z.array(z.string()).optional(),
  exclude_globs: z.array(z.string()).optional()
});

export const FetchFileInputSchema = RepoInputSchema.extend({
  path: z.string().min(1).describe("Repo-relative POSIX file path to read."),
  start_line: z.number().int().positive().optional().describe("1-based inclusive starting line number to read."),
  end_line: z.number().int().positive().optional().describe("1-based inclusive ending line number to read."),
  max_bytes: z.number().int().positive().max(HARD_LIMIT_CAPS.max_bytes_per_file).optional().describe("Maximum UTF-8 bytes returned for this read; larger content is truncated cleanly with continuation metadata."),
  override_default_excludes: z.boolean().optional().describe("Allow reading default-excluded generated or dependency files with an audit warning.")
}).superRefine((value, context) => {
  if (value.start_line !== undefined && value.end_line !== undefined && value.end_line < value.start_line) {
    context.addIssue({
      code: "custom",
      path: ["end_line"],
      message: "end_line must be greater than or equal to start_line."
    });
  }
});

export const ReadManyInputSchema = RepoInputSchema.extend({
  paths: z.array(z.string()).optional().describe("Explicit repo-relative file paths to read in this batch."),
  include_globs: z.array(z.string()).optional().describe("Glob patterns matched against repository files to include in this batch."),
  exclude_globs: z.array(z.string()).optional().describe("Glob patterns excluding matched paths from this batch."),
  max_files: z.number().int().positive().max(HARD_LIMIT_CAPS.max_files).optional().describe("Maximum number of files to inspect per page, clamped by server limits."),
  max_bytes_per_file: z.number().int().positive().max(HARD_LIMIT_CAPS.max_bytes_per_file).optional().describe("Maximum UTF-8 bytes returned per file before truncating with continuation metadata."),
  max_total_bytes: z.number().int().positive().max(HARD_LIMIT_CAPS.max_total_bytes).optional().describe("Maximum total returned UTF-8 bytes across all files in this page, clamped by server limits."),
  cursor: z.string().optional().describe("Opaque pagination cursor returned by a previous repo_read_many call.")
}).refine((input) => (input.paths?.length ?? 0) > 0 || (input.include_globs?.length ?? 0) > 0, {
  message: "repo_read_many requires paths or include_globs.",
  path: ["paths"]
});

export const FileClassificationSchema = z.object({
  path: z.string(),
  language: z.string().optional(),
  is_binary: z.boolean(),
  is_secret_candidate: z.boolean(),
  is_generated: z.boolean()
});

export const FileSummarySchema = z.object({
  path: z.string(),
  type: z.enum(["file", "directory", "nested_repo", "submodule"]),
  size_bytes: z.number().int().nonnegative().optional()
});

export const FileContentSchema = z.object({
  path: z.string().describe("Repo-relative POSIX path of the file."),
  language: z.string().optional().describe("Detected source language inferred from the file extension when known."),
  size_bytes: z.number().int().nonnegative().describe("Full on-disk file size in bytes."),
  sha256: z.string().describe("Hex SHA-256 digest of the full on-disk file contents."),
  total_lines: z.number().int().nonnegative().describe("Total number of lines in the full file."),
  start_line: z.number().int().positive().describe("1-based starting line number requested for this read."),
  end_line: z.number().int().nonnegative().describe("1-based ending line number included in text, or 0 when no lines were returned."),
  truncated: z.boolean().describe("True when returned text was capped by max_bytes before reaching the requested end line."),
  has_more: z.boolean().describe("True when additional lines remain in the file after this returned slice."),
  next_start_line: z.number().int().positive().optional().describe("Suggested 1-based start_line for reading the next chunk when has_more is true."),
  bytes_returned: z.number().int().nonnegative().describe("UTF-8 byte length of the returned text slice."),
  text: z.string().describe("Returned UTF-8 file text slice after secret redaction."),
  warnings: z.array(z.string()).default([]).describe("Policy, truncation, or redaction warnings associated with this file read.")
});

export const ReadManyResultSchema = z.object({
  files: z.array(FileContentSchema).describe("Successfully read files included in this page."),
  skipped: z.array(z.object({
    path: z.string().describe("Repo-relative path of the skipped file."),
    reason: z.string().describe("Machine-readable reason code explaining why the file was skipped.")
  })).describe("Files skipped due to policy checks, errors, or the total byte budget."),
  matched_count: z.number().int().nonnegative().describe("Total deduplicated candidate files matched across explicit paths and globs."),
  returned_count: z.number().int().nonnegative().describe("Number of files returned in this page."),
  total_bytes_returned: z.number().int().nonnegative().describe("Total UTF-8 bytes of returned file text across files in this page."),
  remaining_count: z.number().int().nonnegative().describe("Number of matched files remaining after this page when truncated is true."),
  truncated: z.boolean().describe("True when additional matched files remain beyond this page."),
  next_cursor: z.string().optional().describe("Pagination cursor to pass to the next repo_read_many call when truncated is true.")
});
