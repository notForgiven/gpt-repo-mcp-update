import { z } from "zod";
import { RepoInputSchema } from "./repo.contract.js";

export const GitInspectCommandSchema = z.enum([
  "status",
  "branch",
  "tag",
  "log",
  "diff",
  "commit_tree",
  "file_tree",
  "show",
  "blame",
  "rev_parse",
  "merge_base",
  "shortlog"
]);

export const GitInspectRangeModeSchema = z.enum(["two_dot", "three_dot"]);
export const GitInspectBranchScopeSchema = z.enum(["local", "remote", "all"]);
export const GitInspectMergeFilterSchema = z.enum(["include", "only", "exclude"]);
export const GitInspectSortSchema = z.enum([
  "refname",
  "-refname",
  "committerdate",
  "-committerdate",
  "creatordate",
  "-creatordate",
  "version:refname",
  "-version:refname"
]);

export const GitInspectInputSchema = RepoInputSchema.extend({
  command: GitInspectCommandSchema.describe("Allowlisted read-only Git inspection command to execute without mutation."),
  ref: z.string().min(1).max(256).optional().describe("Validated Git ref, branch, tag, or commit SHA used as the primary target or diff/log base."),
  compare_ref: z.string().min(1).max(256).optional().describe("Validated secondary Git ref or commit SHA used for range comparisons, diff targets, or merge_base."),
  range_mode: GitInspectRangeModeSchema.optional().describe("Range operator constructed server-side between ref and compare_ref: two_dot (ref..compare_ref) or three_dot (ref...compare_ref)."),
  refs: z.array(z.string().min(1).max(256)).min(1).max(50).optional().describe("List of up to 50 validated Git refs to resolve when command is rev_parse."),
  paths: z.array(z.string().min(1)).min(1).max(200).optional().describe("Optional repo-relative POSIX paths to scope status, log, diff, commit_tree, show, or shortlog."),
  file_path: z.string().min(1).optional().describe("Single repo-relative non-secret file path for command=blame or blob inspection in command=show."),
  path: z.string().min(1).optional().describe("Optional repo-relative directory or file prefix when inspecting a ref tree with command=file_tree."),
  pattern: z.string().min(1).max(128).optional().describe("Optional wildcard pattern to filter branch or tag names without flag syntax."),
  scope: GitInspectBranchScopeSchema.optional().describe("Branch listing scope for command=branch: local, remote, or all."),
  contains: z.string().min(1).max(256).optional().describe("Optional validated commit or ref filter matching branches or tags that contain it."),
  merged: z.string().min(1).max(256).optional().describe("Optional validated ref filter returning branches merged into the specified commit."),
  no_merged: z.string().min(1).max(256).optional().describe("Optional validated ref filter returning branches not merged into the specified commit."),
  sort: GitInspectSortSchema.optional().describe("Allowlisted sort order for branch or tag listings."),
  author: z.string().min(1).max(200).optional().describe("Optional fixed-string author filter for command=log."),
  since: z.string().min(1).max(64).optional().describe("Optional ISO date or bounded relative time lower bound for log or shortlog."),
  until: z.string().min(1).max(64).optional().describe("Optional ISO date or bounded relative time upper bound for log or shortlog."),
  grep: z.string().min(1).max(200).optional().describe("Optional fixed-string commit message filter for command=log."),
  first_parent: z.boolean().optional().describe("Follow only the first parent of merge commits in command=log or command=commit_tree."),
  merges: GitInspectMergeFilterSchema.optional().describe("Control whether merge commits are included, exclusive, or excluded in command=log."),
  all_refs: z.boolean().optional().describe("Include all local and remote refs in command=commit_tree instead of only HEAD or ref."),
  recursive: z.boolean().optional().describe("Recursively descend into subtrees when command=file_tree."),
  max_depth: z.number().int().min(1).max(8).optional().describe("Maximum directory depth (1..8) for command=file_tree."),
  staged: z.boolean().optional().describe("Inspect staged index changes in command=diff."),
  unstaged: z.boolean().optional().describe("Inspect unstaged worktree changes in command=diff."),
  stat_only: z.boolean().optional().describe("Return file-level diff stats without patch hunks for command=diff or commit command=show."),
  include_patch: z.boolean().optional().describe("Include bounded secret-filtered unified patch hunks when inspecting a commit with command=show."),
  include_stat: z.boolean().optional().describe("Include per-commit filtered file change stats for command=log."),
  context_lines: z.number().int().min(0).max(20).optional().describe("Unified diff context lines (0..20) for command=diff or commit command=show."),
  start_line: z.number().int().positive().optional().describe("1-based inclusive start line for command=blame or blob command=show."),
  end_line: z.number().int().positive().optional().describe("1-based inclusive end line for command=blame or blob command=show."),
  limit: z.number().int().positive().max(2_000).optional().describe("Bounded item cap clamped server-side per command (commits, refs, tree entries, or contributors)."),
  skip: z.number().int().min(0).max(10_000).optional().describe("Number of commits to skip for pagination in command=log."),
  max_files: z.number().int().positive().max(100).optional().describe("Maximum number of changed files loaded for command=diff or commit command=show."),
  max_bytes: z.number().int().positive().max(256_000).optional().describe("Maximum output bytes (capped at 256000) for diff, show, or graph output.")
}).strict().superRefine((value, context) => {
  if (value.start_line !== undefined && value.end_line !== undefined && value.end_line < value.start_line) {
    context.addIssue({
      code: "custom",
      path: ["end_line"],
      message: "end_line must be greater than or equal to start_line."
    });
  }

  if (value.command === "blame") {
    if (!value.file_path) {
      context.addIssue({
        code: "custom",
        path: ["file_path"],
        message: "command=blame requires file_path."
      });
    }
    if (value.start_line !== undefined && value.end_line !== undefined && value.end_line - value.start_line + 1 > 500) {
      context.addIssue({
        code: "custom",
        path: ["end_line"],
        message: "command=blame line span must not exceed 500 lines."
      });
    }
  }

  if (value.command === "merge_base") {
    if (!value.ref) {
      context.addIssue({
        code: "custom",
        path: ["ref"],
        message: "command=merge_base requires ref."
      });
    }
    if (!value.compare_ref) {
      context.addIssue({
        code: "custom",
        path: ["compare_ref"],
        message: "command=merge_base requires compare_ref."
      });
    }
  }

  if (value.command === "rev_parse") {
    if (!value.refs || value.refs.length === 0) {
      context.addIssue({
        code: "custom",
        path: ["refs"],
        message: "command=rev_parse requires a non-empty refs array."
      });
    }
  }

  if (value.command === "show" && value.file_path) {
    if (value.include_patch !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["include_patch"],
        message: "include_patch cannot be combined with file_path in command=show."
      });
    }
    if (value.stat_only !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["stat_only"],
        message: "stat_only cannot be combined with file_path in command=show."
      });
    }
  }

  if (value.compare_ref && !value.ref && value.command !== "merge_base") {
    context.addIssue({
      code: "custom",
      path: ["ref"],
      message: "compare_ref requires ref to be specified."
    });
  }

  if (value.command === "diff" && value.staged && value.compare_ref) {
    context.addIssue({
      code: "custom",
      path: ["compare_ref"],
      message: "staged diff cannot be combined with compare_ref."
    });
  }

  if (value.command === "commit_tree" && value.all_refs && value.ref) {
    context.addIssue({
      code: "custom",
      path: ["all_refs"],
      message: "Provide either all_refs=true or an explicit ref for command=commit_tree, not both."
    });
  }
});

const StatusFileSchema = z.object({
  path: z.string().describe("Repo-relative POSIX path of the changed entry."),
  original_path: z.string().optional().describe("Original repo-relative path when renamed or copied."),
  index: z.string().describe("Index status code from Git porcelain v2."),
  worktree: z.string().describe("Worktree status code from Git porcelain v2."),
  status: z.enum(["modified", "added", "deleted", "renamed", "copied", "untracked", "unmerged", "unknown"]).describe("Normalized change classification."),
  staged: z.boolean().describe("Whether the entry has staged index changes."),
  unstaged: z.boolean().describe("Whether the entry has unstaged worktree changes or is untracked.")
});

export const GitInspectStatusPayloadSchema = z.object({
  branch: z.string().describe("Current branch name, or HEAD when detached."),
  head_sha: z.string().describe("Current HEAD commit SHA, or unborn when no commits exist."),
  detached: z.boolean().describe("Whether HEAD is detached from a local branch."),
  upstream: z.string().optional().describe("Configured upstream tracking ref if present."),
  ahead: z.number().int().nonnegative().describe("Commits ahead of the configured upstream ref."),
  behind: z.number().int().nonnegative().describe("Commits behind the configured upstream ref."),
  state: z.enum(["clean", "dirty", "merging", "rebasing", "cherry_picking", "reverting", "bisecting"]).describe("Detected repository operation or cleanliness state."),
  clean: z.boolean().describe("Whether no visible working tree or index changes exist."),
  counts: z.record(z.string(), z.number().int().nonnegative()).describe("Counts of changed files keyed by normalized status."),
  total_file_count: z.number().int().nonnegative().describe("Total changed entries observed before any entry cap."),
  files: z.array(StatusFileSchema).describe("Bounded list of changed repository files excluding internal control artifacts.")
});

const BranchEntrySchema = z.object({
  name: z.string().describe("Short branch name."),
  full_ref: z.string().describe("Full Git ref name under refs/heads or refs/remotes."),
  scope: z.enum(["local", "remote"]).describe("Whether the branch is local or remote-tracking."),
  is_current: z.boolean().describe("Whether this branch is currently checked out."),
  head_sha: z.string().describe("Full 40-character tip commit SHA."),
  short_sha: z.string().describe("Abbreviated tip commit SHA."),
  upstream: z.string().optional().describe("Short upstream tracking branch name if configured."),
  track_short: z.string().optional().describe("Short upstream divergence indicator such as ahead/behind or gone."),
  subject: z.string().describe("Redacted tip commit subject line."),
  committer_date: z.string().describe("ISO-8601 committer timestamp of the branch tip.")
});

export const GitInspectBranchesPayloadSchema = z.object({
  scope: GitInspectBranchScopeSchema.describe("Applied branch listing scope."),
  current_branch: z.string().optional().describe("Currently checked-out local branch name if not detached."),
  total_count: z.number().int().nonnegative().describe("Total matching branches before applying limit."),
  items: z.array(BranchEntrySchema).describe("Bounded list of matching branches.")
});

const TagEntrySchema = z.object({
  name: z.string().describe("Tag name under refs/tags."),
  object_type: z.string().describe("Git object type of the tag ref (commit or tag)."),
  sha: z.string().describe("Full SHA of the tag object or directly tagged commit."),
  target_sha: z.string().optional().describe("Dereferenced target commit SHA for annotated tags."),
  date: z.string().describe("ISO-8601 creator or commit timestamp."),
  subject: z.string().describe("Redacted tag annotation or commit subject line."),
  is_annotated: z.boolean().describe("Whether the tag is an annotated Git tag object.")
});

export const GitInspectTagsPayloadSchema = z.object({
  total_count: z.number().int().nonnegative().describe("Total matching tags before applying limit."),
  items: z.array(TagEntrySchema).describe("Bounded list of matching tags.")
});

const DiffFileStatSchema = z.object({
  path: z.string().describe("Repo-relative POSIX file path."),
  original_path: z.string().optional().describe("Original repo-relative path when renamed or copied."),
  status: z.string().optional().describe("Change status such as modified, added, deleted, or renamed."),
  insertions: z.number().int().nonnegative().optional().describe("Number of added lines when available."),
  deletions: z.number().int().nonnegative().optional().describe("Number of deleted lines when available."),
  is_binary: z.boolean().optional().describe("Whether Git reported this file as binary.")
});

const CommitEntrySchema = z.object({
  sha: z.string().describe("Full 40-character commit SHA."),
  short_sha: z.string().describe("Abbreviated commit SHA."),
  parents: z.array(z.string()).describe("Parent commit SHAs in order."),
  refs: z.array(z.string()).describe("Branch, tag, or HEAD decorations pointing at this commit."),
  author_name: z.string().describe("Commit author display name."),
  author_date: z.string().describe("ISO-8601 author timestamp."),
  committer_date: z.string().describe("ISO-8601 committer timestamp."),
  subject: z.string().describe("Redacted commit subject line."),
  body: z.string().optional().describe("Optional redacted commit body text."),
  files: z.array(DiffFileStatSchema).optional().describe("Optional filtered per-file change stats when include_stat=true."),
  omitted_secret_files: z.number().int().nonnegative().optional().describe("Number of secret-candidate files omitted from commit stats.")
});

export const GitInspectCommitsPayloadSchema = z.object({
  ref: z.string().optional().describe("Primary ref queried for commit history."),
  compare_ref: z.string().optional().describe("Secondary ref queried when using a range."),
  range_mode: GitInspectRangeModeSchema.optional().describe("Range operator applied between ref and compare_ref."),
  skip: z.number().int().nonnegative().describe("Number of commits skipped for pagination."),
  total_returned: z.number().int().nonnegative().describe("Number of commits returned in this response."),
  items: z.array(CommitEntrySchema).describe("Bounded list of commits in Git log order.")
});

const DiffFileSchema = DiffFileStatSchema.extend({
  hunks: z.array(z.string()).describe("Redacted unified diff hunks for non-secret text files.")
});

export const GitInspectDiffPayloadSchema = z.object({
  ref: z.string().optional().describe("Base ref compared in this diff."),
  compare_ref: z.string().optional().describe("Target ref compared against ref."),
  range_mode: GitInspectRangeModeSchema.optional().describe("Range operator used between ref and compare_ref."),
  staged: z.boolean().optional().describe("Whether staged index changes were inspected."),
  unstaged: z.boolean().optional().describe("Whether unstaged worktree changes were inspected."),
  stat_only: z.boolean().describe("Whether only file stats were requested without patch hunks."),
  files: z.array(DiffFileSchema).describe("Filtered and redacted diff files."),
  total_file_count: z.number().int().nonnegative().describe("Total changed non-internal files before max_files truncation."),
  omitted_secret_files: z.number().int().nonnegative().describe("Number of secret-candidate files whose diff content was omitted.")
});

const CommitTreeNodeSchema = z.object({
  sha: z.string().describe("Full 40-character commit SHA."),
  short_sha: z.string().describe("Abbreviated commit SHA."),
  parents: z.array(z.string()).describe("Parent commit SHAs forming the commit DAG."),
  refs: z.array(z.string()).describe("Ref decorations pointing at this commit."),
  subject: z.string().describe("Redacted commit subject line."),
  author_name: z.string().describe("Commit author display name."),
  author_date: z.string().describe("ISO-8601 author timestamp.")
});

export const GitInspectCommitTreePayloadSchema = z.object({
  ref: z.string().optional().describe("Starting ref for commit graph traversal when all_refs is false."),
  all_refs: z.boolean().describe("Whether all refs were included in the commit graph."),
  nodes: z.array(CommitTreeNodeSchema).describe("Structured commit DAG nodes."),
  graph_lines: z.array(z.string()).describe("Bounded redacted ASCII commit-graph lines from git log --graph.")
});

const FileTreeEntrySchema = z.object({
  path: z.string().describe("Repo-relative POSIX path inside the Git tree object."),
  name: z.string().describe("Base entry name within its parent directory."),
  type: z.enum(["blob", "tree", "commit"]).describe("Git object type (blob=file, tree=directory, commit=submodule)."),
  mode: z.string().describe("Six-digit Git object mode string."),
  sha: z.string().describe("Git object SHA."),
  size_bytes: z.number().int().nonnegative().optional().describe("Blob size in bytes when entry type is blob.")
});

export const GitInspectFileTreePayloadSchema = z.object({
  ref: z.string().describe("Requested Git ref whose object tree was inspected."),
  resolved_sha: z.string().describe("Resolved commit or tree SHA for ref."),
  path: z.string().describe("Normalized repo-relative subtree path inspected."),
  recursive: z.boolean().describe("Whether subtrees were traversed recursively."),
  max_depth: z.number().int().positive().describe("Applied maximum traversal depth."),
  entries: z.array(FileTreeEntrySchema).describe("Bounded Git tree entries excluding secret and internal paths."),
  excluded_summary: z.record(z.string(), z.number().int().nonnegative()).describe("Counts of entries omitted by safety filters.")
});

export const GitInspectShowPayloadSchema = z.object({
  kind: z.enum(["commit", "blob"]).describe("Whether show inspected a commit or a single file blob at a ref."),
  ref: z.string().describe("Validated ref inspected by show."),
  commit: z.object({
    sha: z.string().describe("Full 40-character commit SHA."),
    short_sha: z.string().describe("Abbreviated commit SHA."),
    parents: z.array(z.string()).describe("Parent commit SHAs."),
    refs: z.array(z.string()).describe("Ref decorations pointing at this commit."),
    author_name: z.string().describe("Commit author display name."),
    author_date: z.string().describe("ISO-8601 author timestamp."),
    committer_date: z.string().describe("ISO-8601 committer timestamp."),
    subject: z.string().describe("Redacted commit subject line."),
    body: z.string().describe("Redacted commit body text."),
    files: z.array(DiffFileSchema).describe("Filtered file stats and optional redacted hunks for the commit."),
    total_file_count: z.number().int().nonnegative().describe("Total changed non-internal files in the commit."),
    omitted_secret_files: z.number().int().nonnegative().describe("Number of secret-candidate files omitted from commit details.")
  }).optional().describe("Commit details returned when kind=commit."),
  blob: z.object({
    path: z.string().describe("Validated repo-relative POSIX file path inspected."),
    sha: z.string().describe("Resolved Git blob SHA."),
    size_bytes: z.number().int().nonnegative().describe("Total UTF-8 byte size of the blob."),
    total_lines: z.number().int().nonnegative().describe("Total line count of the blob."),
    start_line: z.number().int().positive().describe("1-based inclusive starting line returned."),
    end_line: z.number().int().nonnegative().describe("1-based inclusive ending line returned."),
    text: z.string().describe("Bounded redacted UTF-8 text slice of the blob.")
  }).optional().describe("Blob content returned when kind=blob.")
});

const BlameLineSchema = z.object({
  line_number: z.number().int().positive().describe("1-based line number in the target file."),
  sha: z.string().describe("Full 40-character commit SHA that introduced this line."),
  short_sha: z.string().describe("Abbreviated commit SHA."),
  author_name: z.string().describe("Author name recorded by Git blame."),
  author_time: z.string().describe("ISO-8601 author timestamp for the blamed commit."),
  summary: z.string().describe("Redacted commit summary for the blamed commit."),
  content: z.string().describe("Redacted text content of the blamed line.")
});

export const GitInspectBlamePayloadSchema = z.object({
  ref: z.string().describe("Validated Git ref used for blame."),
  path: z.string().describe("Validated repo-relative file path blamed."),
  start_line: z.number().int().positive().describe("1-based inclusive starting line blamed."),
  end_line: z.number().int().nonnegative().describe("1-based inclusive ending line blamed."),
  total_lines: z.number().int().nonnegative().describe("Total number of lines returned."),
  lines: z.array(BlameLineSchema).describe("Bounded line-by-line blame attribution entries.")
});

const ResolvedRefItemSchema = z.object({
  ref: z.string().describe("Original validated ref expression requested."),
  resolved: z.boolean().describe("Whether the ref resolved to a Git object."),
  sha: z.string().optional().describe("Full resolved Git object SHA when found."),
  short_sha: z.string().optional().describe("Abbreviated resolved SHA when found."),
  object_type: z.string().optional().describe("Git object type (commit, tree, blob, tag) when found."),
  error: z.string().optional().describe("Safe resolution error reason when unresolved.")
});

export const GitInspectResolvedRefsPayloadSchema = z.object({
  items: z.array(ResolvedRefItemSchema).describe("Per-ref resolution results in request order.")
});

export const GitInspectMergeBasePayloadSchema = z.object({
  ref: z.string().describe("Primary validated ref passed to merge-base."),
  compare_ref: z.string().describe("Secondary validated ref passed to merge-base."),
  sha: z.string().describe("Full 40-character common ancestor commit SHA."),
  short_sha: z.string().describe("Abbreviated common ancestor commit SHA."),
  subject: z.string().describe("Redacted subject line of the common ancestor commit."),
  author_name: z.string().describe("Author display name of the common ancestor commit."),
  author_date: z.string().describe("ISO-8601 author timestamp of the common ancestor commit.")
});

const ShortlogContributorSchema = z.object({
  author_name: z.string().describe("Contributor display name."),
  commits: z.number().int().nonnegative().describe("Commit count attributed to this contributor.")
});

export const GitInspectShortlogPayloadSchema = z.object({
  ref: z.string().optional().describe("Primary ref queried for shortlog."),
  compare_ref: z.string().optional().describe("Secondary ref queried when using a range."),
  range_mode: GitInspectRangeModeSchema.optional().describe("Range operator applied between ref and compare_ref."),
  total_commits: z.number().int().nonnegative().describe("Sum of commits across returned contributors."),
  contributors: z.array(ShortlogContributorSchema).describe("Bounded contributor commit counts sorted descending.")
});

export const GitInspectResultSchema = z.object({
  ok: z.literal(true).describe("True when read-only Git inspection succeeded."),
  repo_id: z.string().describe("Approved repository identifier inspected."),
  command: GitInspectCommandSchema.describe("Executed read-only Git inspection command."),
  truncated: z.boolean().describe("Whether results were truncated by an entry, file, line, or byte cap."),
  truncation_reason: z.string().optional().describe("Reason describing which cap truncated the result, when truncated is true."),
  warnings: z.array(z.string()).default([]).describe("Non-fatal warnings such as secret redaction, omitted secret paths, or truncation."),
  status: GitInspectStatusPayloadSchema.optional().describe("Structured working tree, branch, upstream, and repo state payload for command=status."),
  branches: GitInspectBranchesPayloadSchema.optional().describe("Structured branch listing payload for command=branch."),
  tags: GitInspectTagsPayloadSchema.optional().describe("Structured tag listing payload for command=tag."),
  commits: GitInspectCommitsPayloadSchema.optional().describe("Structured commit history payload for command=log."),
  diff: GitInspectDiffPayloadSchema.optional().describe("Structured filtered diff payload for command=diff."),
  commit_tree: GitInspectCommitTreePayloadSchema.optional().describe("Structured commit DAG and ASCII graph payload for command=commit_tree."),
  file_tree: GitInspectFileTreePayloadSchema.optional().describe("Structured Git ref object tree payload for command=file_tree."),
  show: GitInspectShowPayloadSchema.optional().describe("Structured commit or blob inspection payload for command=show."),
  blame: GitInspectBlamePayloadSchema.optional().describe("Structured line-range blame payload for command=blame."),
  resolved_refs: GitInspectResolvedRefsPayloadSchema.optional().describe("Structured ref resolution payload for command=rev_parse."),
  merge_base: GitInspectMergeBasePayloadSchema.optional().describe("Structured common ancestor payload for command=merge_base."),
  shortlog: GitInspectShortlogPayloadSchema.optional().describe("Structured contributor commit summary payload for command=shortlog.")
});

export type GitInspectCommand = z.infer<typeof GitInspectCommandSchema>;
export type GitInspectInput = z.infer<typeof GitInspectInputSchema>;
export type GitInspectResult = z.infer<typeof GitInspectResultSchema>;
