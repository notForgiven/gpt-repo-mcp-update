import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { SecretScanner } from "../src/services/secret-scanner.js";
import { redactSensitiveText as redactResultText } from "../src/runtime/result-envelope.js";
import { readFileLineWindow, readFilePrefix } from "../src/services/bounded-read.js";

const scanner = new SecretScanner();
const joined = (...parts: string[]): string => parts.join("");
const fakeGitHubPat = joined("ghp_", "0123456789", "abcdefghijklmnopqrstuvwxyz");
const fakeBearer = joined("bearer-token-", "0123456789");

describe("credential detection and redaction", () => {
  test.each([
    ["OpenAI key", joined("sk", "-proj-", "0123456789", "abcdefghijklmnop")],
    ["GitHub PAT", fakeGitHubPat],
    ["fine-grained GitHub PAT", joined("github_pat_", "01ABCDEF23456789_", "abcdefghijklmnopqrstuvwxyz")],
    ["AWS access key", joined("AWS_ACCESS_KEY_ID=", "AKIA", "0123456789ABCDEF")],
    ["Slack token", joined("xoxb-", "123456789012-", "abcdefghijklmnopqrstuvwx")],
    ["Google API key", joined("AIzaSyD", "0123456789", "abcdefghijklmnopqrstuv")],
    ["JSON access token", JSON.stringify({ access_token: joined("gho_", "0123456789", "abcdefghijklmnopqrstuvwxyz") })],
    ["YAML client secret", joined("client_secret: ", "client-secret-", "0123456789")],
    ["Bearer header", `Authorization: Bearer ${fakeBearer}`],
    [
      "private key block",
      "-----BEGIN PRIVATE KEY-----\nZmFrZS1wcml2YXRlLWtleQ==\n-----END PRIVATE KEY-----"
    ]
  ])("detects %s", (_label, value) => {
    expect(scanner.hasSecretValue(value)).toBe(true);
  });

  test.each([
    "OPENAI_API_KEY=replace-me",
    "token=your-api-key-here",
    "token=[REDACTED_SECRET]",
    "token_count=42",
    "public_key=used-for-signature-verification",
    "Use sk-... only as a placeholder.",
    "Authorization: Bearer"
  ])("does not flag placeholder or non-secret text: %s", (value) => {
    expect(scanner.hasSecretValue(value)).toBe(false);
  });

  test("redacts only credential values while preserving useful labels", () => {
    const input = `request failed: ${JSON.stringify({ access_token: fakeGitHubPat })}`;
    const expected = "request failed: {\"access_token\":\"[REDACTED_SECRET]\"}";

    expect(scanner.redact(input)).toBe(expected);
    expect(redactResultText(input)).toBe(expected);
  });

  test("redacts bearer values and complete private key blocks", () => {
    const input = [
      `Authorization: Bearer ${fakeBearer}`,
      "-----BEGIN PRIVATE KEY-----",
      "ZmFrZS1wcml2YXRlLWtleQ==",
      "-----END PRIVATE KEY-----"
    ].join("\n");
    const redacted = scanner.redact(input);

    expect(redacted).toContain("Authorization: Bearer [REDACTED_SECRET]");
    expect(redacted).not.toContain(fakeBearer);
    expect(redacted).not.toContain("ZmFrZS1wcml2YXRlLWtleQ==");
  });

  test("detects only newly introduced credential values", () => {
    const existing = `Authorization: Bearer ${fakeBearer}`;

    expect(scanner.hasNewSecretValue(existing, existing)).toBe(false);
    expect(scanner.hasNewSecretValue(
      existing,
      `Authorization: Bearer ${joined("different-token-", "9876543210")}`
    )).toBe(true);
  });

  test("redacts large text with thousands of secrets in O(N) time", () => {
    const secretCount = 2_000;
    const lines = Array.from({ length: secretCount }, (_, index) =>
      `line_${index} = "safe padding text"; api_key = "real-secret-value-${String(index).padStart(4, "0")}"`
    );
    const largeInput = lines.join("\n");

    const startedAt = performance.now();
    const redacted = scanner.redact(largeInput);
    const elapsedMs = performance.now() - startedAt;

    expect(elapsedMs).toBeLessThan(2_000);
    expect(redacted).not.toContain("real-secret-value-");
    expect(redacted.split("[REDACTED_SECRET]").length - 1).toBe(secretCount);
  });

  test("avoids quadratic backtracking on very long underscore and hyphenated keys while redacting deep prefixes", () => {
    const longUnderscoreKey = `${"a_".repeat(5_000)}notsecret = "harmless-value"`;
    const longHyphenKey = `${"a-".repeat(5_000)}notsecret = "harmless-value"`;

    const startedAt = performance.now();
    expect(scanner.hasSecretValue(longUnderscoreKey)).toBe(false);
    expect(scanner.hasSecretValue(longHyphenKey)).toBe(false);
    const elapsedMs = performance.now() - startedAt;

    expect(elapsedMs).toBeLessThan(500);
    expect(scanner.hasSecretValue("MY_SERVICE_PROD_API_KEY = \"super-secret-value\"")).toBe(true);
    const nineSegment = "A_B_C_D_E_F_G_H_I_API_KEY=\"super-secret-value-1234\"";
    expect(scanner.hasSecretValue(nineSegment)).toBe(true);
    expect(scanner.redact(nineSegment)).toBe("A_B_C_D_E_F_G_H_I_API_KEY=\"[REDACTED_SECRET]\"");
  });

  test("handles unclosed PEM header in large text without scanning to EOF", () => {
    const hugeTail = "normal log line without closing marker\n".repeat(15_000);
    const unclosedPem = `-----BEGIN RSA PRIVATE KEY-----\n${hugeTail}`;

    const startedAt = performance.now();
    const hasSecret = scanner.hasSecretValue(unclosedPem);
    const elapsedMs = performance.now() - startedAt;

    expect(hasSecret).toBe(false);
    expect(elapsedMs).toBeLessThan(500);
  });
});

describe("bounded streaming reader safety", () => {
  test("redacts mid-PEM private key slices even when startLine begins inside the block", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bounded-read-pem-"));
    const filePath = join(dir, "keys.txt");
    const content = [
      "header line",
      "-----BEGIN RSA PRIVATE KEY-----",
      "MIIEpAIBAAKCAQEAmockSecretBodyLineOne==",
      "MIIEpAIBAAKCAQEAmockSecretBodyLineTwo==",
      "-----END RSA PRIVATE KEY-----",
      "trailing safe line",
      ""
    ].join("\n");
    await writeFile(filePath, content, "utf8");

    const midSlice = await readFileLineWindow({
      filePath,
      maxFileBytes: 1_000_000,
      maxBytes: 10_000,
      startLine: 3,
      endLine: 4
    });

    expect(midSlice.pem_redacted).toBe(true);
    expect(midSlice.text).toBe("[REDACTED_SECRET]\n[REDACTED_SECRET]");
    expect(midSlice.text).not.toContain("mockSecretBody");
    expect(midSlice.sha256).toBe(createHash("sha256").update(content).digest("hex"));
    expect(midSlice.total_lines).toBe(7);
    expect(midSlice.start_line).toBe(3);
    expect(midSlice.end_line).toBe(4);
    expect(midSlice.has_more).toBe(true);
    expect(midSlice.next_start_line).toBe(5);

    const afterSlice = await readFileLineWindow({
      filePath,
      maxFileBytes: 1_000_000,
      maxBytes: 10_000,
      startLine: 6,
      endLine: 6
    });
    expect(afterSlice.pem_redacted).toBe(false);
    expect(afterSlice.text).toBe("trailing safe line");
  });

  test("rejects binary files early and rejects files larger than maxFileBytes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bounded-read-errors-"));
    const binaryPath = join(dir, "data.bin");
    const oversizedPath = join(dir, "large.txt");
    await writeFile(binaryPath, Buffer.concat([Buffer.from("hello"), Buffer.from([0]), Buffer.alloc(100_000, 65)]));
    await writeFile(oversizedPath, "a".repeat(2_048), "utf8");

    await expect(readFileLineWindow({
      filePath: binaryPath,
      maxFileBytes: 1_000_000,
      maxBytes: 10_000
    })).rejects.toMatchObject({ code: "BINARY_FILE_REJECTED" });

    await expect(readFileLineWindow({
      filePath: oversizedPath,
      maxFileBytes: 1_024,
      maxBytes: 512
    })).rejects.toMatchObject({ code: "SIZE_LIMIT_EXCEEDED" });
  });

  test("truncates single over-budget UTF-8 lines without corrupting multi-byte characters", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bounded-read-utf8-"));
    const filePath = join(dir, "emoji.txt");
    const line1 = "😀😀😀😀";
    const content = `${line1}\nsecond line\n`;
    await writeFile(filePath, content, "utf8");

    const result = await readFileLineWindow({
      filePath,
      maxFileBytes: 100_000,
      maxBytes: 10
    });

    expect(result.text).toBe("😀😀");
    expect(result.bytes_returned).toBe(8);
    expect(result.line_truncated).toBe(true);
    expect(result.truncated).toBe(true);
    expect(result.has_more).toBe(true);
    expect(result.next_start_line).toBe(2);
    expect(result.text).not.toContain("\uFFFD");
  });

  test("handles empty files, CRLF endings, past-EOF startLine, and stat-sized readFilePrefix", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bounded-read-edge-"));
    const emptyPath = join(dir, "empty.txt");
    const crlfPath = join(dir, "crlf.txt");
    await writeFile(emptyPath, "", "utf8");
    await writeFile(crlfPath, "alpha\r\nbeta\r\ngamma\r\n", "utf8");

    const emptyResult = await readFileLineWindow({
      filePath: emptyPath,
      maxFileBytes: 1_000,
      maxBytes: 1_000
    });
    expect(emptyResult).toMatchObject({
      text: "",
      size_bytes: 0,
      total_lines: 0,
      start_line: 1,
      end_line: 0,
      bytes_returned: 0,
      truncated: false,
      has_more: false,
      line_truncated: false,
      pem_redacted: false
    });

    const crlfResult = await readFileLineWindow({
      filePath: crlfPath,
      maxFileBytes: 10_000,
      maxBytes: 10_000,
      startLine: 2,
      endLine: 3
    });
    expect(crlfResult.text).toBe("beta\ngamma");
    expect(crlfResult.total_lines).toBe(4);
    expect(crlfResult.has_more).toBe(true);
    expect(crlfResult.next_start_line).toBe(4);

    const pastEof = await readFileLineWindow({
      filePath: crlfPath,
      maxFileBytes: 10_000,
      maxBytes: 10_000,
      startLine: 99
    });
    expect(pastEof).toMatchObject({
      text: "",
      start_line: 99,
      end_line: 0,
      bytes_returned: 0,
      truncated: false,
      has_more: false
    });

    const prefixFull = await readFilePrefix(crlfPath, 2_097_152);
    expect(prefixFull.truncated).toBe(false);
    expect(prefixFull.buffer.toString("utf8")).toBe("alpha\r\nbeta\r\ngamma\r\n");

    const prefixCut = await readFilePrefix(crlfPath, 5);
    expect(prefixCut.truncated).toBe(true);
    expect(prefixCut.buffer.toString("utf8")).toBe("alpha");
  });

  test("preserves PEM tracking across >16 KB prefix lines and 64 KB chunk boundaries", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bounded-read-pem-chunk-"));

    // Case 1: 25 KB prefix on line 1 ending with -----BEGIN RSA PRIVATE KEY-----
    const longPrefixPath = join(dir, "long-prefix-pem.txt");
    const longPrefixContent = [
      `${"x".repeat(25_000)}-----BEGIN RSA PRIVATE KEY-----`,
      "MIIEpAIBAAKCAQEASecretBodyAfter25KBPrefix==",
      "-----END RSA PRIVATE KEY-----",
      "safe tail line"
    ].join("\n");
    await writeFile(longPrefixPath, longPrefixContent, "utf8");

    const after25Kb = await readFileLineWindow({
      filePath: longPrefixPath,
      maxFileBytes: 1_000_000,
      maxBytes: 10_000,
      startLine: 2,
      endLine: 2
    });
    expect(after25Kb.pem_redacted).toBe(true);
    expect(after25Kb.text).toBe("[REDACTED_SECRET]");
    expect(after25Kb.text).not.toContain("SecretBodyAfter25KBPrefix");

    // Case 2: -----BEGIN RSA PRIVATE KEY----- split directly across byte 65536 (64 KB chunk boundary)
    const boundaryPath = join(dir, "chunk-boundary-pem.txt");
    const marker = "-----BEGIN RSA PRIVATE KEY-----";
    const splitPrefixLen = 65_536 - 10; // puts "-----BEGIN" at end of chunk 1 and " RSA PRIVATE KEY-----" at start of chunk 2
    const boundaryContent = [
      `${"a".repeat(splitPrefixLen)}${marker}`,
      "MIIEpAIBAAKCAQEASecretBodyAcross64KBBoundary==",
      "-----END RSA PRIVATE KEY-----",
      "clean line after boundary"
    ].join("\n");
    await writeFile(boundaryPath, boundaryContent, "utf8");

    const afterBoundary = await readFileLineWindow({
      filePath: boundaryPath,
      maxFileBytes: 1_000_000,
      maxBytes: 10_000,
      startLine: 2,
      endLine: 2
    });
    expect(afterBoundary.pem_redacted).toBe(true);
    expect(afterBoundary.text).toBe("[REDACTED_SECRET]");
    expect(afterBoundary.text).not.toContain("SecretBodyAcross64KBBoundary");

    const cleanAfterBoundary = await readFileLineWindow({
      filePath: boundaryPath,
      maxFileBytes: 1_000_000,
      maxBytes: 10_000,
      startLine: 4,
      endLine: 4
    });
    expect(cleanAfterBoundary.pem_redacted).toBe(false);
    expect(cleanAfterBoundary.text).toBe("clean line after boundary");
  });

  test("applies redactLine before byte budgeting and truncation without leaking secrets or overshooting maxBytes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bounded-read-redact-hook-"));

    const midQuotePath = join(dir, "mid-quote.ts");
    await writeFile(midQuotePath, "const db_password = \"SuperSecretProdPassword123\";\n", "utf8");

    const midQuoteResult = await readFileLineWindow({
      filePath: midQuotePath,
      maxFileBytes: 100_000,
      maxBytes: 47,
      redactLine: (line) => scanner.redact(line)
    });
    expect(midQuoteResult.secret_redacted).toBe(true);
    expect(midQuoteResult.text).toBe("const db_password = \"[REDACTED_SECRET]\";\n");
    expect(midQuoteResult.text).not.toContain("SuperSecretProdPassword123");
    expect(midQuoteResult.bytes_returned).toBeLessThanOrEqual(47);

    const tightMidQuoteResult = await readFileLineWindow({
      filePath: midQuotePath,
      maxFileBytes: 100_000,
      maxBytes: 30,
      redactLine: (line) => scanner.redact(line)
    });
    expect(tightMidQuoteResult.secret_redacted).toBe(true);
    expect(tightMidQuoteResult.line_truncated).toBe(true);
    expect(tightMidQuoteResult.bytes_returned).toBeLessThanOrEqual(30);
    expect(tightMidQuoteResult.text).not.toContain("SuperSecret");

    const expandedPath = join(dir, "short-secrets.env");
    await writeFile(expandedPath, "pwd=1234\npwd=1234\npwd=1234\npwd=1234\n", "utf8");

    const expandedResult = await readFileLineWindow({
      filePath: expandedPath,
      maxFileBytes: 100_000,
      maxBytes: 40,
      redactLine: (line) => scanner.redact(line)
    });
    expect(expandedResult.secret_redacted).toBe(true);
    expect(expandedResult.bytes_returned).toBeLessThanOrEqual(40);
    expect(expandedResult.text).toBe("pwd=[REDACTED_SECRET]");
    expect(expandedResult.truncated).toBe(true);
    expect(expandedResult.has_more).toBe(true);
    expect(expandedResult.next_start_line).toBe(2);
  });
});
