import { spawn, type ChildProcess } from "node:child_process";
import { realpath } from "node:fs/promises";
import { dirname } from "node:path";
import { DEFAULT_LIMITS } from "../policies/limits.js";
import { RepoReaderError } from "../runtime/errors.js";

const DEFAULT_STDERR_LIMIT = 64 * 1024;
const TERMINATION_GRACE_MS = 250;
const FORCE_SETTLE_GRACE_MS = 250;

export const GIT_READ_ONLY_GLOBAL_ARGS = [
  "--no-pager",
  "--no-optional-locks",
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.untrackedCache=false",
  "-c",
  "core.pager=cat",
  "-c",
  "core.quotePath=false",
  "-c",
  "diff.external=",
  "-c",
  "diff.mnemonicPrefix=false",
  "-c",
  "color.ui=never",
  "-c",
  "credential.helper=",
  "-c",
  "protocol.ext.allow=never",
  "-c",
  "safe.bareRepository=explicit",
  "-c",
  "gc.auto=0",
  "-c",
  "maintenance.auto=false"
] as const;

export type BoundedProcessResult = {
  stdout: string;
  stderr: string;
  exit_code: number;
  stdout_truncated: boolean;
  stderr_truncated: boolean;
};

export type BoundedBufferProcessResult = {
  stdout: Buffer;
  stderr: string;
  exit_code: number;
  stdout_truncated: boolean;
  stderr_truncated: boolean;
};

export type RunGitBoundedInput = {
  root: string;
  args: string[];
  max_stdout_bytes: number;
  max_stderr_bytes?: number;
  allow_stdout_truncation?: boolean;
  allow_non_zero_exit?: boolean;
  timeout_ms?: number;
  env?: NodeJS.ProcessEnv;
};

export type RunGitReadOnlyInput = {
  root: string;
  args: string[];
  max_stdout_bytes: number;
  max_stderr_bytes?: number;
  allow_stdout_truncation?: boolean;
  allow_non_zero_exit?: boolean;
  timeout_ms?: number;
  root_real?: string;
};

export function gitReadOnlyEnv(rootReal: string): NodeJS.ProcessEnv {
  const parent = dirname(rootReal);
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? "",
    GIT_TERMINAL_PROMPT: "0",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_PAGER: "cat",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null"
  };
  if (process.platform === "win32") {
    if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
    if (process.env.WINDIR) env.WINDIR = process.env.WINDIR;
  }
  if (parent && parent !== rootReal) {
    env.GIT_CEILING_DIRECTORIES = parent;
  }
  return env;
}

export async function runGitBounded(input: RunGitBoundedInput): Promise<BoundedProcessResult> {
  const raw = await runGitRaw(input);
  return {
    stdout: decodeUtf8Safe(raw.stdout, raw.stdout_truncated),
    stderr: raw.stderr,
    exit_code: raw.exit_code,
    stdout_truncated: raw.stdout_truncated,
    stderr_truncated: raw.stderr_truncated
  };
}

export async function runGitReadOnly(input: RunGitReadOnlyInput): Promise<BoundedProcessResult> {
  const raw = await runGitReadOnlyBuffer(input);
  return {
    stdout: decodeUtf8Safe(raw.stdout, raw.stdout_truncated),
    stderr: raw.stderr,
    exit_code: raw.exit_code,
    stdout_truncated: raw.stdout_truncated,
    stderr_truncated: raw.stderr_truncated
  };
}

export async function runGitReadOnlyBuffer(input: RunGitReadOnlyInput): Promise<BoundedBufferProcessResult> {
  const rootReal = input.root_real ?? await realpath(input.root);
  const timeoutMs = clampReadOnlyTimeout(input.timeout_ms);
  return runGitRaw({
    root: rootReal,
    args: [...GIT_READ_ONLY_GLOBAL_ARGS, ...input.args],
    max_stdout_bytes: input.max_stdout_bytes,
    max_stderr_bytes: input.max_stderr_bytes ?? DEFAULT_STDERR_LIMIT,
    allow_stdout_truncation: input.allow_stdout_truncation,
    allow_non_zero_exit: input.allow_non_zero_exit,
    timeout_ms: timeoutMs,
    env: gitReadOnlyEnv(rootReal)
  });
}

export function decodeUtf8Safe(buffer: Buffer, truncated = false): string {
  if (!truncated || buffer.length === 0) {
    return buffer.toString("utf8");
  }
  const safeLength = findValidUtf8PrefixLength(buffer);
  return buffer.subarray(0, safeLength).toString("utf8");
}

function clampReadOnlyTimeout(timeoutMs: number | undefined): number {
  const requested = timeoutMs ?? DEFAULT_LIMITS.git_read_timeout_ms;
  if (!Number.isFinite(requested) || requested <= 0) {
    return DEFAULT_LIMITS.git_read_timeout_ms;
  }
  return Math.min(Math.floor(requested), DEFAULT_LIMITS.max_git_read_timeout_ms);
}

async function runGitRaw(input: RunGitBoundedInput): Promise<BoundedBufferProcessResult> {
  return new Promise((resolve, reject) => {
    const child = spawn("git", input.args, {
      cwd: input.root,
      env: input.env ?? { PATH: process.env.PATH ?? "" },
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32"
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let stdoutTruncated = false;
    let stderrTruncated = false;
    let timedOut = false;
    let terminatedForTruncation = false;
    let settled = false;
    const stderrLimit = input.max_stderr_bytes ?? DEFAULT_STDERR_LIMIT;
    let timeoutTimer: NodeJS.Timeout | undefined;
    let forceTimer: NodeJS.Timeout | undefined;
    let forceSettleTimer: NodeJS.Timeout | undefined;

    const clearTimers = (): void => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (forceTimer) clearTimeout(forceTimer);
      if (forceSettleTimer) clearTimeout(forceSettleTimer);
    };

    const settleResolve = (result: BoundedBufferProcessResult): void => {
      if (settled) return;
      settled = true;
      clearTimers();
      resolve(result);
    };

    const settleReject = (error: RepoReaderError): void => {
      if (settled) return;
      settled = true;
      clearTimers();
      reject(error);
    };

    const beginTermination = (onForceSettle: () => void): void => {
      terminateProcessTree(child, "SIGTERM");
      if (!forceTimer) {
        forceTimer = setTimeout(() => {
          terminateProcessTree(child, "SIGKILL");
          forceSettleTimer = setTimeout(() => {
            child.stdout.destroy();
            child.stderr.destroy();
            child.unref();
            onForceSettle();
          }, FORCE_SETTLE_GRACE_MS);
        }, TERMINATION_GRACE_MS);
      }
    };

    if (typeof input.timeout_ms === "number" && input.timeout_ms > 0) {
      timeoutTimer = setTimeout(() => {
        timedOut = true;
        beginTermination(() => {
          settleReject(new RepoReaderError("GIT_ERROR", "Git command timed out.", {
            retryable: true,
            diagnostics: { timed_out: true, timeout_ms: input.timeout_ms }
          }));
        });
      }, input.timeout_ms);
    }

    child.stdout.on("data", (chunk: Buffer) => {
      const remaining = input.max_stdout_bytes - stdoutBytes;
      if (remaining > 0) {
        const accepted = chunk.subarray(0, remaining);
        stdout.push(accepted);
        stdoutBytes += accepted.length;
      }
      if (chunk.length > Math.max(remaining, 0)) {
        stdoutTruncated = true;
        if (!terminatedForTruncation && !timedOut) {
          terminatedForTruncation = true;
          beginTermination(() => {
            if (input.allow_stdout_truncation) {
              settleResolve({
                stdout: Buffer.concat(stdout),
                stderr: decodeUtf8Safe(Buffer.concat(stderr), stderrTruncated),
                exit_code: 0,
                stdout_truncated: true,
                stderr_truncated: stderrTruncated
              });
            } else {
              settleReject(new RepoReaderError("SIZE_LIMIT_EXCEEDED", "Git output exceeded the bounded inspection limit.", {
                diagnostics: { max_stdout_bytes: input.max_stdout_bytes, source: "git_stdout" }
              }));
            }
          });
        }
      }
    });

    child.stderr.on("data", (chunk: Buffer) => {
      const remaining = stderrLimit - stderrBytes;
      if (remaining > 0) {
        const accepted = chunk.subarray(0, remaining);
        stderr.push(accepted);
        stderrBytes += accepted.length;
      }
      if (chunk.length > Math.max(remaining, 0)) stderrTruncated = true;
    });

    child.once("error", (error) => {
      settleReject(new RepoReaderError("GIT_ERROR", error.message));
    });

    child.once("close", (code, signal) => {
      if (timedOut) {
        settleReject(new RepoReaderError("GIT_ERROR", "Git command timed out.", {
          retryable: true,
          diagnostics: { timed_out: true, timeout_ms: input.timeout_ms }
        }));
        return;
      }
      const stderrText = decodeUtf8Safe(Buffer.concat(stderr), stderrTruncated);
      if (terminatedForTruncation && stdoutTruncated) {
        if (input.allow_stdout_truncation) {
          settleResolve({
            stdout: Buffer.concat(stdout),
            stderr: stderrText,
            exit_code: 0,
            stdout_truncated: true,
            stderr_truncated: stderrTruncated
          });
          return;
        }
        settleReject(new RepoReaderError("SIZE_LIMIT_EXCEEDED", "Git output exceeded the bounded inspection limit.", {
          diagnostics: { max_stdout_bytes: input.max_stdout_bytes, source: "git_stdout" }
        }));
        return;
      }

      const result: BoundedBufferProcessResult = {
        stdout: Buffer.concat(stdout),
        stderr: stderrText,
        exit_code: code ?? 1,
        stdout_truncated: stdoutTruncated,
        stderr_truncated: stderrTruncated
      };
      if (code !== 0 && !input.allow_non_zero_exit) {
        settleReject(new RepoReaderError("GIT_ERROR", result.stderr.trim() || `Git exited with ${code ?? signal ?? "unknown"}.`, {
          diagnostics: { exit_code: code, signal, stderr_truncated: stderrTruncated }
        }));
        return;
      }
      if (stdoutTruncated && !input.allow_stdout_truncation) {
        settleReject(new RepoReaderError("SIZE_LIMIT_EXCEEDED", "Git output exceeded the bounded inspection limit.", {
          diagnostics: { max_stdout_bytes: input.max_stdout_bytes, source: "git_stdout" }
        }));
        return;
      }
      settleResolve(result);
    });
  });
}

function terminateProcessTree(child: Pick<ChildProcess, "pid" | "kill">, signal: NodeJS.Signals): void {
  if (!child.pid) {
    return;
  }
  if (process.platform === "win32") {
    if (signal === "SIGKILL") {
      const taskkill = spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true
      });
      taskkill.once("error", () => {
        child.kill("SIGKILL");
      });
      taskkill.unref();
      return;
    }
    child.kill(signal);
    return;
  }

  try {
    process.kill(-child.pid, signal);
  } catch {
    child.kill(signal);
  }
}

function findValidUtf8PrefixLength(buffer: Buffer): number {
  const len = buffer.length;
  if (len === 0) return 0;

  let trailingContinuations = 0;
  for (let i = len - 1; i >= Math.max(0, len - 4); i -= 1) {
    const byte = buffer[i]!;
    if ((byte & 0xc0) === 0x80) {
      trailingContinuations += 1;
      continue;
    }
    let expectedLength = 1;
    if ((byte & 0x80) === 0x00) expectedLength = 1;
    else if ((byte & 0xe0) === 0xc0) expectedLength = 2;
    else if ((byte & 0xf0) === 0xe0) expectedLength = 3;
    else if ((byte & 0xf8) === 0xf0) expectedLength = 4;
    else return i;

    const actualLength = trailingContinuations + 1;
    if (actualLength < expectedLength) {
      return i;
    }
    return len;
  }
  return Math.max(0, len - trailingContinuations);
}
