import { extname } from "node:path";
import { clampReadLimits, type ReadLimits } from "../policies/limits.js";
import { RepoReaderError } from "../runtime/errors.js";
import { IgnoreEngine, isPublicEnvTemplatePath } from "./ignore-engine.js";
import { PathSandbox } from "./path-sandbox.js";
import { SecretScanner } from "./secret-scanner.js";
import { readFileLineWindow, readFilePrefix } from "./bounded-read.js";

const PUBLIC_ENV_TEMPLATE_MAX_BYTES = 256_000;

const LANGUAGE_BY_EXT: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "tsx",
  ".js": "javascript",
  ".jsx": "jsx",
  ".json": "json",
  ".md": "markdown",
  ".py": "python",
  ".go": "go",
  ".rs": "rust",
  ".java": "java",
  ".css": "css",
  ".html": "html",
  ".yml": "yaml",
  ".yaml": "yaml"
};

export type FetchFileOptions = {
  path: string;
  start_line?: number;
  end_line?: number;
  max_bytes?: number;
  override_default_excludes?: boolean;
};

export class FileReader {
  private readonly ignoreEngine = new IgnoreEngine();
  private readonly secretScanner = new SecretScanner();
  private readonly limits: ReadLimits;

  constructor(private readonly sandbox: PathSandbox, limits?: Partial<ReadLimits>) {
    this.limits = clampReadLimits(limits);
  }

  async read(options: FetchFileOptions) {
    if (
      options.start_line !== undefined &&
      options.end_line !== undefined &&
      options.end_line < options.start_line
    ) {
      throw new RepoReaderError("VALIDATION_ERROR", "end_line must be greater than or equal to start_line.");
    }

    const resolved = await this.sandbox.resolve(options.path);
    if (!resolved.stat.isFile()) {
      throw new RepoReaderError("UNSUPPORTED_FILE_TYPE", `Not a regular file: ${resolved.repoPath}`);
    }

    const warnings: string[] = [];
    if (this.ignoreEngine.isIgnored(resolved.repoPath) && !options.override_default_excludes) {
      throw new RepoReaderError("DEFAULT_EXCLUDE_BLOCKED", `Path is excluded by default: ${resolved.repoPath}`);
    }
    if (this.ignoreEngine.isIgnored(resolved.repoPath) && options.override_default_excludes) {
      warnings.push(`Read default-excluded path with override: ${resolved.repoPath}`);
    }
    if (this.ignoreEngine.isInternalArtifact(resolved.repoPath)) {
      throw new RepoReaderError("INTERNAL_ARTIFACT_BLOCKED", "Internal delegation control artifact blocked.");
    }
    if (this.ignoreEngine.isSensitiveCandidate(resolved.repoPath)) {
      throw new RepoReaderError("SECRET_CANDIDATE_BLOCKED", `Secret candidate blocked: ${resolved.repoPath}`);
    }
    if (resolved.stat.size > this.limits.max_file_bytes) {
      throw new RepoReaderError(
        "SIZE_LIMIT_EXCEEDED",
        `File exceeds max_file_bytes (${this.limits.max_file_bytes}): ${resolved.repoPath}`
      );
    }

    if (isPublicEnvTemplatePath(resolved.repoPath)) {
      const envScanCap = Math.min(PUBLIC_ENV_TEMPLATE_MAX_BYTES, this.limits.max_file_bytes);
      if (resolved.stat.size > envScanCap) {
        throw new RepoReaderError(
          "SIZE_LIMIT_EXCEEDED",
          `Public env template exceeds scan cap (${envScanCap} bytes): ${resolved.repoPath}`
        );
      }
      const { buffer: fullTemplate, truncated: envTruncated } = await readFilePrefix(resolved.absolutePath, envScanCap);
      if (envTruncated) {
        throw new RepoReaderError(
          "SIZE_LIMIT_EXCEEDED",
          `Public env template exceeds scan cap (${envScanCap} bytes): ${resolved.repoPath}`
        );
      }
      if (fullTemplate.includes(0)) {
        throw new RepoReaderError("BINARY_FILE_REJECTED", `Binary file blocked: ${resolved.repoPath}`);
      }
      if (this.secretScanner.hasSecretValue(fullTemplate.toString("utf8"))) {
        throw new RepoReaderError("SECRET_CANDIDATE_BLOCKED", `Secret candidate blocked: ${resolved.repoPath}`);
      }
    }

    const maxBytes = Math.min(
      options.max_bytes ?? this.limits.max_bytes_per_file,
      this.limits.max_bytes_per_file
    );

    let window;
    try {
      window = await readFileLineWindow({
        filePath: resolved.absolutePath,
        maxFileBytes: this.limits.max_file_bytes,
        maxBytes,
        startLine: options.start_line,
        endLine: options.end_line,
        redactLine: (line) => this.secretScanner.redact(line)
      });
    } catch (error) {
      if (error instanceof RepoReaderError) {
        if (error.code === "BINARY_FILE_REJECTED") {
          throw new RepoReaderError("BINARY_FILE_REJECTED", `Binary file blocked: ${resolved.repoPath}`);
        }
        if (error.code === "SIZE_LIMIT_EXCEEDED") {
          throw new RepoReaderError(
            "SIZE_LIMIT_EXCEEDED",
            `File exceeds max_file_bytes (${this.limits.max_file_bytes}): ${resolved.repoPath}`
          );
        }
        if (error.code === "UNSUPPORTED_FILE_TYPE") {
          throw new RepoReaderError("UNSUPPORTED_FILE_TYPE", `Not a regular file: ${resolved.repoPath}`);
        }
      }
      throw error;
    }

    if (window.line_truncated) {
      warnings.push(`Truncated line ${window.end_line} to fit max_bytes (${maxBytes}).`);
    } else if (window.truncated) {
      warnings.push(`Truncated file content at line ${window.end_line} to fit max_bytes (${maxBytes}).`);
    }
    if (window.pem_redacted || window.secret_redacted) {
      warnings.push(`Redacted secret-like values in ${resolved.repoPath}.`);
    }

    return {
      path: resolved.repoPath,
      language: LANGUAGE_BY_EXT[extname(resolved.repoPath).toLowerCase()],
      size_bytes: window.size_bytes,
      sha256: window.sha256,
      total_lines: window.total_lines,
      start_line: window.start_line,
      end_line: window.end_line,
      truncated: window.truncated,
      has_more: window.has_more,
      next_start_line: window.next_start_line,
      bytes_returned: window.bytes_returned,
      text: window.text,
      warnings
    };
  }
}
