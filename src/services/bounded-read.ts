import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { StringDecoder } from "node:string_decoder";
import {
  PEM_PRIVATE_KEY_BEGIN_PATTERN,
  PEM_PRIVATE_KEY_END_PATTERN,
  PEM_PRIVATE_KEY_MAX_BLOCK_BYTES
} from "../policies/secret-patterns.js";
import { RepoReaderError } from "../runtime/errors.js";

const READ_CHUNK_BYTES = 64 * 1024;
const BINARY_CHECK_BYTES = 8 * 1024;
const PEM_OVERLAP_CHARS = 64;
const PEM_REDACTION_MARKER = "[REDACTED_SECRET]";

export type BoundedReadResult = {
  buffer: Buffer;
  truncated: boolean;
};

export type ReadFileLineWindowOptions = {
  filePath: string;
  maxFileBytes: number;
  maxBytes: number;
  startLine?: number;
  endLine?: number;
  redactLine?: (line: string) => string;
};

export type ReadFileLineWindowResult = {
  text: string;
  sha256: string;
  size_bytes: number;
  total_lines: number;
  start_line: number;
  end_line: number;
  bytes_returned: number;
  truncated: boolean;
  has_more: boolean;
  next_start_line?: number;
  line_truncated: boolean;
  pem_redacted: boolean;
  secret_redacted: boolean;
};

export async function readFilePrefix(absolutePath: string, maxBytes: number): Promise<BoundedReadResult> {
  const safeMaxBytes = Math.max(0, Math.floor(maxBytes));
  const handle = await open(absolutePath, "r");
  try {
    const fileStat = await handle.stat();
    const limit = safeMaxBytes + 1;
    const chunks: Buffer[] = [];
    let totalRead = 0;

    while (totalRead < limit) {
      const remaining = limit - totalRead;
      const statRemainingHint = fileStat.size > totalRead ? fileStat.size - totalRead + 1 : 1;
      const chunkSize = Math.min(READ_CHUNK_BYTES, statRemainingHint, remaining);
      const chunk = Buffer.allocUnsafe(chunkSize);
      const { bytesRead } = await handle.read(chunk, 0, chunkSize, null);
      if (bytesRead === 0) {
        break;
      }
      chunks.push(bytesRead === chunkSize ? chunk : chunk.subarray(0, bytesRead));
      totalRead += bytesRead;
    }

    const combined = chunks.length === 0
      ? Buffer.alloc(0)
      : chunks.length === 1
        ? chunks[0]!
        : Buffer.concat(chunks, totalRead);
    const truncated = totalRead > safeMaxBytes;
    return {
      buffer: truncated ? combined.subarray(0, safeMaxBytes) : combined,
      truncated
    };
  } finally {
    await handle.close();
  }
}

export async function readFileLineWindow(options: ReadFileLineWindowOptions): Promise<ReadFileLineWindowResult> {
  const maxFileBytes = Math.max(0, Math.floor(options.maxFileBytes));
  const maxBytes = Math.max(1, Math.floor(options.maxBytes));
  const requestedStartLine = options.startLine !== undefined ? Math.max(1, Math.floor(options.startLine)) : 1;
  const requestedEndLine = options.endLine !== undefined ? Math.floor(options.endLine) : undefined;

  if (requestedEndLine !== undefined && requestedEndLine < requestedStartLine) {
    throw new RepoReaderError("VALIDATION_ERROR", "end_line must be greater than or equal to start_line.");
  }

  const handle = await open(options.filePath, "r");
  try {
    const fileStat = await handle.stat();
    if (!fileStat.isFile()) {
      throw new RepoReaderError("UNSUPPORTED_FILE_TYPE", `Not a regular file: ${options.filePath}`);
    }
    if (fileStat.size > maxFileBytes) {
      throw new RepoReaderError(
        "SIZE_LIMIT_EXCEEDED",
        `File size (${fileStat.size} bytes) exceeds max_file_bytes (${maxFileBytes}): ${options.filePath}`
      );
    }

    const hash = createHash("sha256");
    if (fileStat.size === 0) {
      return {
        text: "",
        sha256: hash.digest("hex"),
        size_bytes: 0,
        total_lines: 0,
        start_line: requestedStartLine,
        end_line: 0,
        bytes_returned: 0,
        truncated: false,
        has_more: false,
        line_truncated: false,
        pem_redacted: false,
        secret_redacted: false
      };
    }

    const decoder = new StringDecoder("utf8");
    const chunkBuffer = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, Math.max(fileStat.size, 1)));

    let sizeBytes = 0;
    let binaryCheckedBytes = 0;
    let totalLines = 0;
    let sawAnyBytes = false;

    const collectedLines: string[] = [];
    let bytesReturned = 0;
    let lastReturnedLine = 0;
    let budgetExceeded = false;
    let lineTruncated = false;
    let pemRedacted = false;
    let secretRedacted = false;

    let inPemBlock = false;
    let pemBytesSinceBegin = 0;

    // State for the line currently being streamed.
    const maxBufferedLineChars = Math.max(maxBytes + 1_024, 16_384);
    let currentLineBuffer = "";
    let currentLineOverflowed = false;
    let currentLineOverlap = "";
    let currentLineStartsInPem = false;

    const isLineCollectable = (lineNumber: number): boolean =>
      !budgetExceeded &&
      lineNumber >= requestedStartLine &&
      (requestedEndLine === undefined || lineNumber <= requestedEndLine);

    const addPemBodyBytes = (byteCount: number): void => {
      if (!inPemBlock || byteCount <= 0) {
        return;
      }
      pemBytesSinceBegin += byteCount;
      if (pemBytesSinceBegin > PEM_PRIVATE_KEY_MAX_BLOCK_BYTES) {
        inPemBlock = false;
        pemBytesSinceBegin = 0;
      }
    };

    const advancePemState = (segment: string): void => {
      if (segment.length === 0) {
        return;
      }
      const overlapLen = currentLineOverlap.length;
      const window = currentLineOverlap + segment;
      let searchFrom = 0;
      let accountedTo = overlapLen;

      if (window.includes("-----")) {
        while (searchFrom < window.length) {
          const rest = window.slice(searchFrom);
          if (!inPemBlock) {
            const beginMatch = PEM_PRIVATE_KEY_BEGIN_PATTERN.exec(rest);
            if (!beginMatch) {
              break;
            }
            const beginEnd = searchFrom + beginMatch.index + beginMatch[0].length;
            inPemBlock = true;
            pemBytesSinceBegin = 0;
            searchFrom = beginEnd;
            accountedTo = Math.max(accountedTo, beginEnd);
          } else {
            const endMatch = PEM_PRIVATE_KEY_END_PATTERN.exec(rest);
            if (!endMatch) {
              if (accountedTo < window.length) {
                addPemBodyBytes(Buffer.byteLength(window.slice(accountedTo), "utf8"));
                accountedTo = window.length;
              }
              break;
            }
            const endEnd = searchFrom + endMatch.index + endMatch[0].length;
            inPemBlock = false;
            pemBytesSinceBegin = 0;
            searchFrom = endEnd;
            accountedTo = Math.max(accountedTo, endEnd);
          }
        }
      } else if (inPemBlock) {
        addPemBodyBytes(Buffer.byteLength(segment, "utf8"));
        accountedTo = window.length;
      }

      if (inPemBlock && accountedTo < window.length) {
        addPemBodyBytes(Buffer.byteLength(window.slice(accountedTo), "utf8"));
      }

      const unmatchedTail = searchFrom > 0 ? window.slice(searchFrom) : window;
      currentLineOverlap = unmatchedTail.length > PEM_OVERLAP_CHARS
        ? unmatchedTail.slice(-PEM_OVERLAP_CHARS)
        : unmatchedTail;
    };

    const transformCollectedLineForPem = (line: string): string => {
      if (!inPemBlock && !line.includes("-----")) {
        return line;
      }

      let cursor = 0;
      const parts: string[] = [];

      while (cursor < line.length) {
        const rest = line.slice(cursor);
        if (inPemBlock) {
          const endMatch = PEM_PRIVATE_KEY_END_PATTERN.exec(rest);
          pemRedacted = true;
          parts.push(PEM_REDACTION_MARKER);
          if (!endMatch) {
            addPemBodyBytes(Buffer.byteLength(rest, "utf8") + 1);
            return parts.join("");
          }
          inPemBlock = false;
          pemBytesSinceBegin = 0;
          cursor += endMatch.index + endMatch[0].length;
          continue;
        }

        const beginMatch = PEM_PRIVATE_KEY_BEGIN_PATTERN.exec(rest);
        if (!beginMatch) {
          parts.push(rest);
          break;
        }
        if (beginMatch.index > 0) {
          parts.push(rest.slice(0, beginMatch.index));
        }
        pemRedacted = true;
        inPemBlock = true;
        pemBytesSinceBegin = 0;
        const afterBeginOffset = cursor + beginMatch.index + beginMatch[0].length;
        const afterBegin = line.slice(afterBeginOffset);
        const endMatch = PEM_PRIVATE_KEY_END_PATTERN.exec(afterBegin);
        parts.push(PEM_REDACTION_MARKER);
        if (!endMatch) {
          addPemBodyBytes(Buffer.byteLength(afterBegin, "utf8") + 1);
          return parts.join("");
        }
        inPemBlock = false;
        pemBytesSinceBegin = 0;
        cursor = afterBeginOffset + endMatch.index + endMatch[0].length;
      }

      return parts.join("");
    };

    const appendSegmentToCurrentLine = (segment: string): void => {
      if (segment.length === 0) {
        return;
      }
      const lineNumber = totalLines + 1;

      if (isLineCollectable(lineNumber)) {
        if (!currentLineOverflowed) {
          if (currentLineBuffer.length + segment.length <= maxBufferedLineChars) {
            currentLineBuffer += segment;
          } else {
            const room = Math.max(0, maxBufferedLineChars - currentLineBuffer.length);
            if (room > 0) {
              currentLineBuffer += segment.slice(0, room);
            }
            currentLineOverflowed = true;
            currentLineStartsInPem = inPemBlock;
            currentLineOverlap = "";
            advancePemState(currentLineBuffer);
            advancePemState(segment.slice(room));
          }
        } else {
          advancePemState(segment);
        }
      } else {
        advancePemState(segment);
      }
    };

    const finalizeCurrentLine = (terminatedByNewline: boolean): void => {
      totalLines += 1;
      const lineNumber = totalLines;

      if (isLineCollectable(lineNumber)) {
        let lineText = currentLineBuffer;
        if (terminatedByNewline && !currentLineOverflowed && lineText.endsWith("\r")) {
          lineText = lineText.slice(0, -1);
        }

        if (!currentLineOverflowed) {
          lineText = transformCollectedLineForPem(lineText);
        } else {
          if (currentLineStartsInPem || PEM_PRIVATE_KEY_BEGIN_PATTERN.test(lineText)) {
            const savedInPem = inPemBlock;
            const savedPemBytes = pemBytesSinceBegin;
            inPemBlock = currentLineStartsInPem;
            pemBytesSinceBegin = 0;
            lineText = transformCollectedLineForPem(lineText);
            inPemBlock = savedInPem;
            pemBytesSinceBegin = savedPemBytes;
          }
          if (terminatedByNewline) {
            addPemBodyBytes(1);
          }
        }

        if (options.redactLine && lineText.length > 0) {
          const redactedLine = options.redactLine(lineText);
          if (redactedLine !== lineText) {
            secretRedacted = true;
            lineText = redactedLine;
          }
        }

        const sepBytes = collectedLines.length > 0 ? 1 : 0;
        const lineByteLength = Buffer.byteLength(lineText, "utf8");
        const fitsWholeLine = !currentLineOverflowed && bytesReturned + sepBytes + lineByteLength <= maxBytes;

        if (fitsWholeLine) {
          collectedLines.push(lineText);
          bytesReturned += sepBytes + lineByteLength;
          lastReturnedLine = lineNumber;
        } else if (collectedLines.length === 0) {
          const truncatedLine = truncateUtf8(lineText, maxBytes);
          collectedLines.push(truncatedLine);
          bytesReturned = Buffer.byteLength(truncatedLine, "utf8");
          lastReturnedLine = lineNumber;
          lineTruncated = true;
          budgetExceeded = true;
        } else {
          budgetExceeded = true;
        }
      } else if (terminatedByNewline) {
        addPemBodyBytes(1);
      }

      currentLineBuffer = "";
      currentLineOverflowed = false;
      currentLineOverlap = "";
      currentLineStartsInPem = inPemBlock;
    };

    const processDecodedText = (text: string): void => {
      let start = 0;
      while (start < text.length) {
        const nlIndex = text.indexOf("\n", start);
        if (nlIndex === -1) {
          appendSegmentToCurrentLine(text.slice(start));
          break;
        }
        appendSegmentToCurrentLine(text.slice(start, nlIndex));
        finalizeCurrentLine(true);
        start = nlIndex + 1;
      }
    };

    while (true) {
      const { bytesRead } = await handle.read(chunkBuffer, 0, chunkBuffer.length, null);
      if (bytesRead === 0) {
        break;
      }
      sawAnyBytes = true;
      sizeBytes += bytesRead;
      if (sizeBytes > maxFileBytes) {
        throw new RepoReaderError(
          "SIZE_LIMIT_EXCEEDED",
          `File size exceeded max_file_bytes (${maxFileBytes}) while reading: ${options.filePath}`
        );
      }

      const slice = chunkBuffer.subarray(0, bytesRead);
      if (binaryCheckedBytes < BINARY_CHECK_BYTES) {
        const checkLen = Math.min(bytesRead, BINARY_CHECK_BYTES - binaryCheckedBytes);
        if (slice.subarray(0, checkLen).includes(0)) {
          throw new RepoReaderError("BINARY_FILE_REJECTED", `Binary file blocked: ${options.filePath}`);
        }
        binaryCheckedBytes += checkLen;
      }

      hash.update(slice);
      processDecodedText(decoder.write(slice));
    }

    const tail = decoder.end();
    if (tail.length > 0) {
      processDecodedText(tail);
    }

    if (sawAnyBytes) {
      finalizeCurrentLine(false);
    }

    const text = collectedLines.join("\n");
    const hasMore = lastReturnedLine > 0 && lastReturnedLine < totalLines;
    return {
      text,
      sha256: hash.digest("hex"),
      size_bytes: sizeBytes,
      total_lines: totalLines,
      start_line: requestedStartLine,
      end_line: lastReturnedLine,
      bytes_returned: Buffer.byteLength(text, "utf8"),
      truncated: budgetExceeded,
      has_more: hasMore,
      next_start_line: hasMore ? lastReturnedLine + 1 : undefined,
      line_truncated: lineTruncated,
      pem_redacted: pemRedacted,
      secret_redacted: secretRedacted
    };
  } finally {
    await handle.close();
  }
}

function truncateUtf8(text: string, maxBytes: number): string {
  if (maxBytes <= 0) {
    return "";
  }
  if (Buffer.byteLength(text, "utf8") <= maxBytes) {
    return text;
  }

  let low = 0;
  let high = text.length;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    let candidate = mid;
    if (candidate > 0 && candidate < text.length) {
      const code = text.charCodeAt(candidate - 1);
      if (code >= 0xd800 && code <= 0xdbff) {
        candidate -= 1;
      }
    }
    if (candidate === low) {
      const pairEnd = Math.min(low + 2, text.length);
      if (Buffer.byteLength(text.slice(0, pairEnd), "utf8") <= maxBytes) {
        low = pairEnd;
      }
      break;
    }
    if (Buffer.byteLength(text.slice(0, candidate), "utf8") <= maxBytes) {
      low = candidate;
    } else {
      high = candidate - 1;
    }
  }
  return text.slice(0, low);
}
