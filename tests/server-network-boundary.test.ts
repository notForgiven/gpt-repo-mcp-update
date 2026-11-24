import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, test } from "vitest";

const require = createRequire(import.meta.url);
const TSX_IMPORT_URL = pathToFileURL(require.resolve("tsx")).href;

const children = new Set<ChildProcess>();

describe("server network boundary", () => {
  afterEach(async () => {
    await Promise.all([...children].map((child) => stopChild(child)));
  });

  test("defaults to an explicit loopback binding", async () => {
    const server = await startServer();
    await waitForHealth(server);

    expect(server.output()).toContain(`http://127.0.0.1:${server.port}/mcp`);
  });

  test("rejects an external bind unless it is explicitly authorized", async () => {
    const server = await startServer({ GPT_REPO_HOST: "0.0.0.0" });
    const exited = await waitForExit(server.child, 10_000);

    expect(exited).toBe(true);
    expect(server.child.exitCode).not.toBe(0);
    expect(server.output()).toContain("GPT_REPO_ALLOW_EXTERNAL_BIND=true");
  });

  test("rejects browser requests from a non-loopback origin and host", async () => {
    const server = await startServer();
    await waitForHealth(server);

    const response = await httpRequest(server.port, {
      Host: "attacker.example",
      Origin: "https://attacker.example"
    });

    expect(response).toMatchObject({ status: 403, body: "Forbidden origin" });
  });

  test("allows an explicitly authorized external bind", async () => {
    const server = await startServer({
      GPT_REPO_ALLOW_EXTERNAL_BIND: "true",
      GPT_REPO_HOST: "0.0.0.0"
    });

    await waitForHealth(server);
    expect(server.output()).toContain(`http://0.0.0.0:${server.port}/mcp`);
  });

  test("bounds MCP sessions and releases capacity on DELETE", async () => {
    const server = await startServer({ GPT_REPO_MAX_SESSIONS: "1" });
    await waitForHealth(server);

    const first = await initializeSession(server.port);
    expect(first.status).toBe(200);
    expect(first.sessionId).toEqual(expect.any(String));

    const rejected = await initializeSession(server.port);
    expect(rejected.status).toBe(503);
    await waitForOutput(server, '"error_category":"session_capacity"');

    const deleted = await fetch(`http://127.0.0.1:${server.port}/mcp`, {
      method: "DELETE",
      headers: {
        Accept: "application/json, text/event-stream",
        "mcp-session-id": first.sessionId ?? ""
      }
    });
    await deleted.text();
    expect(deleted.ok).toBe(true);

    const replacement = await initializeSession(server.port);
    expect(replacement.status).toBe(200);
    expect(replacement.sessionId).toEqual(expect.any(String));
  });

  test("audits an invalid session with safe category and request correlation", async () => {
    const server = await startServer();
    await waitForHealth(server);

    const response = await httpRequest(server.port, {
      "mcp-session-id": "do-not-log-this-session-id"
    });

    expect(response.status).toBe(400);
    await waitForOutput(server, '"error_category":"invalid_session"');
    expect(server.output()).toContain('"request_id":');
    expect(server.output()).not.toContain("do-not-log-this-session-id");
  });

  test("auto-loads ./config.local.json from cwd when GPT_REPO_CONFIG is unset", async () => {
    const workdir = await mkdtemp(join(tmpdir(), "gpt-repo-default-cfg-"));
    const repoRoot = join(workdir, "demo-repo");
    await mkdir(join(repoRoot, ".git"), { recursive: true });
    await writeFile(join(workdir, "config.local.json"), JSON.stringify({
      repos: [{ repo_id: "auto-demo", display_name: "Auto Demo", root: "./demo-repo" }],
      limits: {}
    }), "utf8");

    const server = await startServerWithOptions({ cwd: workdir, omitConfigEnv: true });
    await waitForHealth(server);
    await waitForOutput(server, "(1 repo(s))");

    const session = await initializeSession(server.port);
    expect(session.status).toBe(200);
    const listResponse = await fetch(`http://127.0.0.1:${server.port}/mcp`, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
        "mcp-session-id": session.sessionId ?? ""
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "repo_list_roots", arguments: {} }
      })
    });
    const listText = await listResponse.text();
    expect(listResponse.ok).toBe(true);
    expect(listText).toContain("auto-demo");
  });

  test("falls back to an empty registry when GPT_REPO_CONFIG is unset and ./config.local.json is absent", async () => {
    const emptyWorkdir = await mkdtemp(join(tmpdir(), "gpt-repo-empty-cfg-"));
    const server = await startServerWithOptions({ cwd: emptyWorkdir, omitConfigEnv: true });
    await waitForHealth(server);
    await waitForOutput(server, "starting with 0 approved repositories");
  });

  test("fails fast when GPT_REPO_CONFIG is explicitly set to a missing file", async () => {
    const missingPath = join(tmpdir(), `gpt-repo-missing-${Date.now()}.json`);
    const server = await startServer({ GPT_REPO_CONFIG: missingPath });
    const exited = await waitForExit(server.child, 10_000);

    expect(exited).toBe(true);
    expect(server.child.exitCode).not.toBe(0);
  });

  test("fails fast when implicit ./config.local.json exists but references a missing repo.root", async () => {
    const workdir = await mkdtemp(join(tmpdir(), "gpt-repo-missing-root-cfg-"));
    await writeFile(join(workdir, "config.local.json"), JSON.stringify({
      repos: [{ repo_id: "broken", display_name: "Broken", root: "./does-not-exist" }],
      limits: {}
    }), "utf8");

    const server = await startServerWithOptions({ cwd: workdir, omitConfigEnv: true });
    const exited = await waitForExit(server.child, 10_000);

    expect(exited).toBe(true);
    expect(server.child.exitCode).not.toBe(0);
    expect(server.output()).not.toContain("starting with 0 approved repositories");
  });
});

async function initializeSession(port: number): Promise<{ status: number; sessionId: string | null }> {
  const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "session-boundary-test", version: "1.0.0" }
      }
    })
  });
  await response.text();
  return {
    status: response.status,
    sessionId: response.headers.get("mcp-session-id")
  };
}

async function startServer(extraEnv: Record<string, string> = {}) {
  return startServerWithOptions({ extraEnv });
}

async function startServerWithOptions(options: {
  extraEnv?: Record<string, string>;
  cwd?: string;
  omitConfigEnv?: boolean;
} = {}) {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "gpt-repo-network-boundary-"));
  const configPath = join(fixtureRoot, "config.json");
  const port = await freePort();
  await writeFile(configPath, JSON.stringify({ repos: [], limits: {} }), "utf8");
  let output = "";
  const serverEntry = resolve(process.cwd(), "src/server.ts");
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PORT: String(port),
    ...options.extraEnv
  };
  if (options.omitConfigEnv) {
    delete env.GPT_REPO_CONFIG;
    delete env.REPO_READER_CONFIG;
  } else if (!options.extraEnv?.GPT_REPO_CONFIG && !options.extraEnv?.REPO_READER_CONFIG) {
    env.GPT_REPO_CONFIG = configPath;
  }
  const child = spawn(process.execPath, ["--import", TSX_IMPORT_URL, serverEntry], {
    cwd: options.cwd ?? process.cwd(),
    env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  children.add(child);
  child.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });
  child.once("exit", () => {
    children.delete(child);
    void rm(fixtureRoot, { recursive: true, force: true });
    if (options.cwd) {
      void rm(options.cwd, { recursive: true, force: true });
    }
  });
  return { child, output: () => output, port };
}

async function waitForHealth(server: Awaited<ReturnType<typeof startServer>>): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (server.child.exitCode !== null || server.child.signalCode !== null) {
      throw new Error(`Server exited before becoming healthy.\n${server.output()}`.trim());
    }
    try {
      const response = await fetch(`http://127.0.0.1:${server.port}/health`, {
        signal: AbortSignal.timeout(300)
      });
      if (response.ok) {
        return;
      }
    } catch {
      // The server may still be starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Server did not become healthy.\n${server.output()}`.trim());
}

async function waitForOutput(
  server: Awaited<ReturnType<typeof startServer>>,
  expected: string
): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    if (server.output().includes(expected)) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`Server output did not contain ${expected}.\n${server.output()}`);
}

function httpRequest(port: number, headers: Record<string, string>): Promise<{ status?: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1",
      port,
      path: "/mcp",
      method: "GET",
      headers
    }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        resolve({ status: res.statusCode, body });
      });
    });
    req.once("error", reject);
    req.end();
  });
}

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Could not reserve a local port.");
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
  return address.port;
}

async function waitForExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return true;
  }
  return Promise.race([
    once(child, "exit").then(() => true),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), timeoutMs))
  ]);
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  child.kill("SIGTERM");
  if (!await waitForExit(child, 1_000)) {
    child.kill("SIGKILL");
    await once(child, "exit");
  }
}
