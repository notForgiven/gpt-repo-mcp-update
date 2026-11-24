export type SecretValueMatch = {
  start: number;
  end: number;
  value: string;
};

export const PEM_PRIVATE_KEY_BEGIN_PATTERN =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/;

export const PEM_PRIVATE_KEY_END_PATTERN =
  /-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/;

export const PEM_PRIVATE_KEY_MAX_BLOCK_BYTES = 16_384;

const SENSITIVE_KEY =
  String.raw`(?<![A-Za-z0-9])(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|client[_-]?secret|refresh[_-]?token|private[_-]?key|apiKey|accessToken|authToken|bearerToken|clientSecret|refreshToken|privateKey|token|secret|password|passwd|pwd)`;

type SecretValuePatternDefinition = {
  pattern: RegExp;
  valueGroup: number;
  prefilter?: (text: string) => boolean;
};

const SECRET_VALUE_PATTERNS: ReadonlyArray<SecretValuePatternDefinition> = [
  {
    pattern:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{0,16384}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
    valueGroup: 0,
    prefilter: (text) => text.includes("-----BEGIN")
  },
  {
    pattern: /\b(?:Authorization|Proxy-Authorization)[ \t]*:[ \t]*Bearer[ \t]+([A-Za-z0-9._~+/-]{8,}={0,2})/gi,
    valueGroup: 1
  },
  {
    pattern:
      /\b(?:sk-[A-Za-z0-9_-]{3,}|gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[A-Za-z0-9_-]{35}|(?:sk|rk)_live_[A-Za-z0-9]{16,})\b/g,
    valueGroup: 0
  },
  {
    pattern: new RegExp(String.raw`${SENSITIVE_KEY}\b["']?[ \t]*[:=][ \t]*["']([^"'\r\n]{4,})["']`, "gi"),
    valueGroup: 1
  },
  {
    pattern: new RegExp(String.raw`${SENSITIVE_KEY}\b["']?[ \t]*[:=][ \t]*([^\s,;#}{"']{4,})`, "gi"),
    valueGroup: 1
  }
];

export function findSecretValues(text: string): SecretValueMatch[] {
  const matches: SecretValueMatch[] = [];
  for (const definition of SECRET_VALUE_PATTERNS) {
    if (definition.prefilter && !definition.prefilter(text)) {
      continue;
    }
    const pattern = new RegExp(definition.pattern.source, definition.pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      const value = match[definition.valueGroup];
      if (!value || isPlaceholderSecret(value)) {
        continue;
      }
      const relativeStart = match[0].lastIndexOf(value);
      if (relativeStart < 0) {
        continue;
      }
      matches.push({
        start: match.index + relativeStart,
        end: match.index + relativeStart + value.length,
        value
      });
    }
  }
  return removeOverlappingMatches(matches);
}

export function redactSecretValues(text: string): string {
  const matches = findSecretValues(text);
  if (matches.length === 0) {
    return text;
  }

  const parts: string[] = [];
  let cursor = 0;
  for (const match of matches) {
    if (match.start > cursor) {
      parts.push(text.slice(cursor, match.start));
    }
    parts.push("[REDACTED_SECRET]");
    cursor = match.end;
  }
  if (cursor < text.length) {
    parts.push(text.slice(cursor));
  }
  return parts.join("");
}

function removeOverlappingMatches(matches: SecretValueMatch[]): SecretValueMatch[] {
  const sorted = matches.sort((left, right) => left.start - right.start || right.end - left.end);
  const result: SecretValueMatch[] = [];
  for (const match of sorted) {
    const previous = result.at(-1);
    if (previous && match.start < previous.end) {
      continue;
    }
    result.push(match);
  }
  return result;
}

function isPlaceholderSecret(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.includes("[redacted_secret]") ||
    normalized.includes("replace-me") ||
    normalized.includes("your-api-key-here") ||
    ["changeme", "example", "dummy", "not-a-secret", "null", "undefined"].includes(normalized) ||
    normalized === "sk-..." ||
    /^\$\{[a-z0-9_]+\}$/.test(normalized) ||
    /^<[^>]*(?:key|token|secret|password)[^>]*>$/.test(normalized)
  );
}
