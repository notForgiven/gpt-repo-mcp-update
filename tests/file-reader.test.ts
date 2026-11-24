import { createHash } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { FetchFileInputSchema, FileContentSchema } from "../src/contracts/file.contract.js";
import { FileReader } from "../src/services/file-reader.js";
import { PathSandbox } from "../src/services/path-sandbox.js";
import { RootRegistry } from "../src/services/root-registry.js";
import { fetchFileHandler } from "../src/tools/handlers.js";
import { createRepoFixture } from "./fixtures/repo-fixture.js";

async function createTestFixture(): Promise<{ root: string; outside: string }> {
  try {
    return await createRepoFixture();
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== "EPERM") {
      throw error;
    }
    const root = await mkdtemp(join(tmpdir(), "repo-reader-fixture-"));
    const outside = await mkdtemp(join(tmpdir(), "repo-reader-outside-"));
    await mkdir(join(root, "src"), { recursive: true });
    await mkdir(join(root, "docs"), { recursive: true });
    await mkdir(join(root, "node_modules", "pkg"), { recursive: true });
    await mkdir(join(root, "dist"), { recursive: true });
    await mkdir(join(root, "vendor", "nested", ".git"), { recursive: true });
    await mkdir(join(root, "vendor", "submodule"), { recursive: true });
    await writeFile(join(root, "src", "app.ts"), [
      "export function rawFetch() {",
      "  return fetch('/api/users');",
      "}",
      ""
    ].join("\n"));
    await writeFile(join(root, "src", "controllers.ts"), [
      "export const controller = 'users';",
      "export const token = 'public-token';",
      ""
    ].join("\n"));
    await writeFile(join(root, "src", "admin.controller.ts"), "export const admin = true;\n");
    await writeFile(join(root, "src", "users.controller.ts"), "export const users = true;\n");
    await writeFile(join(root, "docs", "guide.md"), "# Guide\nSearchable docs\n");
    await writeFile(join(root, ".env"), "API_TOKEN=super-secret\n");
    await writeFile(join(root, "config.key"), "private-key\n");
    await writeFile(join(root, "node_modules", "pkg", "index.js"), "module.exports = 'ignored';\n");
    await writeFile(join(root, "dist", "bundle.js"), "console.log('generated');\n");
    await writeFile(join(root, "binary.bin"), Buffer.from([0, 1, 2, 3]));
    await writeFile(join(root, "vendor", "nested", "index.ts"), "export const nested = true;\n");
    await writeFile(join(root, "vendor", "submodule", ".git"), "gitdir: ../.git/modules/vendor/submodule\n");
    await writeFile(join(root, "vendor", "submodule", "README.md"), "# submodule\n");
    await writeFile(join(outside, "secret.txt"), "outside secret\n");
    return { root, outside };
  }
}

describe("FileReader", () => {
  test("reads a normal text file with line bounds and metadata", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));

    const result = await reader.read({ path: "src/app.ts", start_line: 2, end_line: 2 });

    expect(result.path).toBe("src/app.ts");
    expect(result.language).toBe("typescript");
    expect(result.total_lines).toBe(4);
    expect(result.start_line).toBe(2);
    expect(result.end_line).toBe(2);
    expect(result.truncated).toBe(false);
    expect(result.has_more).toBe(true);
    expect(result.next_start_line).toBe(3);
    expect(result.bytes_returned).toBe(Buffer.byteLength("  return fetch('/api/users');", "utf8"));
    expect(result.text).toBe("  return fetch('/api/users');");
    expect(result.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(() => FileContentSchema.parse(result)).not.toThrow();
  });

  test("blocks secret candidates even when default excludes are overridden", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));

    await expect(reader.read({ path: ".env", override_default_excludes: true })).rejects.toMatchObject({
      code: "SECRET_CANDIDATE_BLOCKED"
    });
  });

  test("reads safe files whose paths mention secret or credential", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    await writeFile(join(fixture.root, "docs", "secret-management.md"), "# Secret Management\nUse placeholders.\n");

    const result = await reader.read({ path: "docs/secret-management.md" });

    expect(result.path).toBe("docs/secret-management.md");
    expect(result.text).toContain("Use placeholders.");
  });

  test("still blocks files inside secrets directories", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    await mkdir(join(fixture.root, "secrets"), { recursive: true });
    await writeFile(join(fixture.root, "secrets", "foo.txt"), "not secret\n");

    await expect(reader.read({ path: "secrets/foo.txt" })).rejects.toMatchObject({
      code: "SECRET_CANDIDATE_BLOCKED"
    });
  });

  test("reads public env templates with placeholder-safe content", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    const safeContent = [
      "GPT_REPO_CONFIG=./config.local.json",
      "PORT=8787",
      "CONTROL_PLANE_API_KEY=",
      "TUNNEL_CLIENT_BIN=/path/to/tunnel-client",
      ""
    ].join("\n");

    for (const path of [".env.example", ".env.sample", ".env.template", "example.env"]) {
      await writeFile(join(fixture.root, path), safeContent);
      const result = await reader.read({ path, override_default_excludes: true });
      expect(result.path).toBe(path);
      expect(result.text).toContain("GPT_REPO_CONFIG=./config.local.json");
      expect(result.text).toContain("CONTROL_PLANE_API_KEY=");
    }
  });

  test("still blocks real env files and arbitrary env suffixes", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    await writeFile(join(fixture.root, ".env.local"), "PORT=8787\n");
    await writeFile(join(fixture.root, ".env.production"), "PORT=8787\n");
    await writeFile(join(fixture.root, ".env.anything"), "PORT=8787\n");

    for (const path of [".env", ".env.local", ".env.production", ".env.anything"]) {
      await expect(reader.read({ path, override_default_excludes: true })).rejects.toMatchObject({
        code: "SECRET_CANDIDATE_BLOCKED"
      });
    }
  });

  test("blocks public env templates containing secret-looking values even when requesting a clean line range", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    const content = [
      "PORT=8787",
      "HOST=127.0.0.1",
      ...Array.from({ length: 20 }, (_, index) => `SAFE_VAR_${index}=placeholder`),
      "OPENAI_API_KEY=sk-realSecretValue123",
      ""
    ].join("\n");
    await writeFile(join(fixture.root, ".env.example"), content);

    await expect(
      reader.read({ path: ".env.example", start_line: 1, end_line: 2, override_default_excludes: true })
    ).rejects.toMatchObject({
      code: "SECRET_CANDIDATE_BLOCKED"
    });
  });

  test("rejects oversized public env templates above the full-file scan cap", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    await writeFile(join(fixture.root, ".env.example"), "A=1\n".repeat(70_000));

    await expect(
      reader.read({ path: ".env.example", start_line: 1, end_line: 5, override_default_excludes: true })
    ).rejects.toMatchObject({
      code: "SIZE_LIMIT_EXCEEDED"
    });
  });

  test("blocks binary files", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));

    await expect(reader.read({ path: "binary.bin" })).rejects.toMatchObject({
      code: "BINARY_FILE_REJECTED"
    });
  });

  test("allows generated files only with an explicit override warning", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));

    await expect(reader.read({ path: "dist/bundle.js" })).rejects.toMatchObject({
      code: "DEFAULT_EXCLUDE_BLOCKED"
    });

    const result = await reader.read({ path: "dist/bundle.js", override_default_excludes: true });
    expect(result.warnings).toEqual(["Read default-excluded path with override: dist/bundle.js"]);
  });

  test("returns a bounded truncated chunk with continuation metadata when max_bytes is smaller than the file", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));

    const result = await reader.read({ path: "src/app.ts", max_bytes: 10 });

    expect(result.truncated).toBe(true);
    expect(result.has_more).toBe(true);
    expect(result.next_start_line).toBe(2);
    expect(result.start_line).toBe(1);
    expect(result.end_line).toBe(1);
    expect(result.bytes_returned).toBeLessThanOrEqual(10);
    expect(result.bytes_returned).toBe(Buffer.byteLength(result.text, "utf8"));
    expect(result.size_bytes).toBeGreaterThan(10);
    expect(result.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.warnings.some((warning) => warning.includes("max_bytes"))).toBe(true);
    expect(() => FileContentSchema.parse(result)).not.toThrow();
  });

  test("streams multi-megabyte line ranges with exact full-file sha256", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    const lines = Array.from(
      { length: 6_000 },
      (_, index) => `export const line_${index + 1} = "${"x".repeat(180)}";`
    );
    const fullContent = `${lines.join("\n")}\n`;
    expect(Buffer.byteLength(fullContent, "utf8")).toBeGreaterThan(1_000_000);
    const expectedSha = createHash("sha256").update(fullContent).digest("hex");
    await writeFile(join(fixture.root, "src", "large.ts"), fullContent);

    const result = await reader.read({ path: "src/large.ts", start_line: 5_000, end_line: 5_020 });

    expect(result.sha256).toBe(expectedSha);
    expect(result.size_bytes).toBe(Buffer.byteLength(fullContent, "utf8"));
    expect(result.total_lines).toBe(6_001);
    expect(result.start_line).toBe(5_000);
    expect(result.end_line).toBe(5_020);
    expect(result.truncated).toBe(false);
    expect(result.has_more).toBe(true);
    expect(result.next_start_line).toBe(5_021);
    expect(result.text.split("\n")).toHaveLength(21);
    expect(result.text).toContain("export const line_5000 =");
    expect(result.text).toContain("export const line_5020 =");
    expect(result.bytes_returned).toBe(Buffer.byteLength(result.text, "utf8"));
  });

  test("rejects files exceeding max_file_bytes with SIZE_LIMIT_EXCEEDED", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root), { max_file_bytes: 1_024 });
    await writeFile(join(fixture.root, "src", "too-big.ts"), "a".repeat(2_048));

    await expect(reader.read({ path: "src/too-big.ts", start_line: 1, end_line: 1 })).rejects.toMatchObject({
      code: "SIZE_LIMIT_EXCEEDED"
    });
  });

  test("redacts mid-PEM private key blocks even when reading an interior line range", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    const pemContent = [
      "// header",
      "const fixtureKey = `",
      "-----BEGIN RSA PRIVATE KEY-----",
      "MIIEowIBAAKCAQEAsecretBodyLineOne1111111111111111111111",
      "MIIEowIBAAKCAQEAsecretBodyLineTwo2222222222222222222222",
      "MIIEowIBAAKCAQEAsecretBodyLineThree33333333333333333333",
      "-----END RSA PRIVATE KEY-----",
      "`;",
      "// footer"
    ].join("\n");
    await writeFile(join(fixture.root, "src", "pem-fixture.ts"), pemContent);

    const result = await reader.read({ path: "src/pem-fixture.ts", start_line: 4, end_line: 6 });

    expect(result.text).not.toContain("secretBodyLineOne");
    expect(result.text).not.toContain("secretBodyLineTwo");
    expect(result.text).not.toContain("secretBodyLineThree");
    expect(result.text).toContain("[REDACTED_SECRET]");
    expect(result.warnings.some((warning) => warning.includes("Redacted"))).toBe(true);
  });

  test("handles empty files and start_line past EOF cleanly", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    await writeFile(join(fixture.root, "src", "empty.ts"), "");

    const emptyResult = await reader.read({ path: "src/empty.ts" });
    expect(emptyResult.total_lines).toBe(0);
    expect(emptyResult.start_line).toBe(1);
    expect(emptyResult.end_line).toBe(0);
    expect(emptyResult.text).toBe("");
    expect(emptyResult.bytes_returned).toBe(0);
    expect(emptyResult.truncated).toBe(false);
    expect(emptyResult.has_more).toBe(false);
    expect(emptyResult.next_start_line).toBeUndefined();
    expect(() => FileContentSchema.parse(emptyResult)).not.toThrow();

    const pastEofResult = await reader.read({ path: "src/app.ts", start_line: 50 });
    expect(pastEofResult.total_lines).toBe(4);
    expect(pastEofResult.start_line).toBe(50);
    expect(pastEofResult.end_line).toBe(0);
    expect(pastEofResult.text).toBe("");
    expect(pastEofResult.bytes_returned).toBe(0);
    expect(pastEofResult.truncated).toBe(false);
    expect(pastEofResult.has_more).toBe(false);
    expect(pastEofResult.next_start_line).toBeUndefined();
    expect(() => FileContentSchema.parse(pastEofResult)).not.toThrow();
  });

  test("rejects end_line < start_line in both schema and service", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));

    await expect(reader.read({ path: "src/app.ts", start_line: 3, end_line: 1 })).rejects.toMatchObject({
      code: "VALIDATION_ERROR"
    });

    const parsed = FetchFileInputSchema.safeParse({
      repo_id: "fixture",
      path: "src/app.ts",
      start_line: 3,
      end_line: 1
    });
    expect(parsed.success).toBe(false);
  });

  test("propagates config.limits overrides through fetchFileHandler", async () => {
    const fixture = await createTestFixture();
    const payload = `${"export const x = '0123456789';\n".repeat(10_000)}`;
    const payloadBytes = Buffer.byteLength(payload, "utf8");
    expect(payloadBytes).toBeGreaterThan(256_000);
    expect(payloadBytes).toBeLessThan(512_000);
    await writeFile(join(fixture.root, "src", "medium.ts"), payload);

    const defaultRegistry = await RootRegistry.fromConfig({
      repos: [{ repo_id: "fixture", display_name: "Fixture", root: fixture.root }]
    });
    const defaultResponse = await fetchFileHandler(
      { repo_id: "fixture", path: "src/medium.ts" },
      { registry: defaultRegistry }
    );
    const defaultContent = FileContentSchema.parse(defaultResponse.structuredContent);
    expect(defaultContent.truncated).toBe(true);
    expect(defaultContent.has_more).toBe(true);
    expect(defaultContent.bytes_returned).toBeLessThanOrEqual(256_000);

    const raisedRegistry = await RootRegistry.fromConfig({
      repos: [{ repo_id: "fixture", display_name: "Fixture", root: fixture.root }],
      limits: { max_bytes_per_file: 512_000 }
    });
    const raisedResponse = await fetchFileHandler(
      { repo_id: "fixture", path: "src/medium.ts" },
      { registry: raisedRegistry }
    );
    const raisedContent = FileContentSchema.parse(raisedResponse.structuredContent);
    expect(raisedContent.truncated).toBe(false);
    expect(raisedContent.has_more).toBe(false);
    expect(raisedContent.bytes_returned).toBe(payloadBytes);
  });

  test("redacts quoted secrets before max_bytes truncation to prevent mid-token leakage", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    await writeFile(
      join(fixture.root, "src", "secret-line.ts"),
      'const db_password = "SuperSecretProdPassword123";\nexport const ok = true;\n'
    );

    const result = await reader.read({ path: "src/secret-line.ts", max_bytes: 47 });

    expect(result.text).not.toContain("SuperSecret");
    expect(result.text).toContain("[REDACTED_SECRET]");
    expect(result.bytes_returned).toBeLessThanOrEqual(47);
    expect(result.bytes_returned).toBe(Buffer.byteLength(result.text, "utf8"));
    expect(result.warnings.some((warning) => warning.includes("Redacted"))).toBe(true);
    expect(() => FileContentSchema.parse(result)).not.toThrow();
  });

  test("enforces max_bytes strictly after redaction expansion on short repeated secrets", async () => {
    const fixture = await createTestFixture();
    const reader = new FileReader(new PathSandbox(fixture.root));
    await writeFile(
      join(fixture.root, "src", "short-secrets.txt"),
      "pwd=1234\n".repeat(10)
    );

    const result = await reader.read({ path: "src/short-secrets.txt", max_bytes: 40 });

    expect(result.text).not.toContain("1234");
    expect(result.text).toContain("[REDACTED_SECRET]");
    expect(result.bytes_returned).toBeLessThanOrEqual(40);
    expect(result.bytes_returned).toBe(Buffer.byteLength(result.text, "utf8"));
    expect(result.truncated).toBe(true);
    expect(result.has_more).toBe(true);
    expect(result.next_start_line).toBe(result.end_line + 1);
    expect(result.end_line).toBeGreaterThanOrEqual(1);
    expect(result.warnings.some((warning) => warning.includes("Redacted"))).toBe(true);
    expect(() => FileContentSchema.parse(result)).not.toThrow();
  });
});
