export interface UnifiedDiff {
  patch: string;
  additions: number;
  deletions: number;
}

type Op = { kind: "same" | "add" | "del"; line: string };

function splitLines(value: string): string[] {
  if (value === "") return [];
  const lines = value.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

function lcsOps(before: string[], after: string[]): Op[] {
  const n = before.length;
  const m = after.length;
  const limit = 4_000_000;
  if (n * m > limit) {
    // Large files: keep the common prefix/suffix and treat the middle as one
    // change block. The result is still a valid unified hunk.
    let start = 0;
    while (start < n && start < m && before[start] === after[start]) start += 1;
    let endBefore = n;
    let endAfter = m;
    while (endBefore > start && endAfter > start && before[endBefore - 1] === after[endAfter - 1]) {
      endBefore -= 1;
      endAfter -= 1;
    }
    return [
      ...before.slice(0, start).map((line) => ({ kind: "same" as const, line })),
      ...before.slice(start, endBefore).map((line) => ({ kind: "del" as const, line })),
      ...after.slice(start, endAfter).map((line) => ({ kind: "add" as const, line })),
      ...before.slice(endBefore).map((line) => ({ kind: "same" as const, line })),
    ];
  }

  const width = m + 1;
  const dp = new Uint32Array((n + 1) * width);
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i * width + j] =
        before[i] === after[j]
          ? 1 + dp[(i + 1) * width + j + 1]!
          : Math.max(dp[(i + 1) * width + j]!, dp[i * width + j + 1]!);
    }
  }

  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (before[i] === after[j]) {
      ops.push({ kind: "same", line: before[i]! });
      i += 1;
      j += 1;
    } else if (dp[(i + 1) * width + j]! >= dp[i * width + j + 1]!) {
      ops.push({ kind: "del", line: before[i]! });
      i += 1;
    } else {
      ops.push({ kind: "add", line: after[j]! });
      j += 1;
    }
  }
  while (i < n) ops.push({ kind: "del", line: before[i++]! });
  while (j < m) ops.push({ kind: "add", line: after[j++]! });
  return ops;
}

/** One-hunk unified diff, with three lines of context. */
export function unifiedDiff(beforeValue: string, afterValue: string, path = "file"): UnifiedDiff {
  const before = splitLines(beforeValue);
  const after = splitLines(afterValue);
  const ops = lcsOps(before, after);
  let first = -1;
  let last = -1;
  let additions = 0;
  let deletions = 0;
  for (let index = 0; index < ops.length; index += 1) {
    if (ops[index]!.kind !== "same") {
      if (first < 0) first = index;
      last = index;
    }
    if (ops[index]!.kind === "add") additions += 1;
    if (ops[index]!.kind === "del") deletions += 1;
  }
  if (first < 0) return { patch: "", additions: 0, deletions: 0 };

  const context = 3;
  const start = Math.max(0, first - context);
  const end = Math.min(ops.length, last + context + 1);
  let oldLine = 1;
  let newLine = 1;
  for (let index = 0; index < start; index += 1) {
    if (ops[index]!.kind !== "add") oldLine += 1;
    if (ops[index]!.kind !== "del") newLine += 1;
  }
  let oldCount = 0;
  let newCount = 0;
  for (let index = start; index < end; index += 1) {
    if (ops[index]!.kind !== "add") oldCount += 1;
    if (ops[index]!.kind !== "del") newCount += 1;
  }

  const body: string[] = [];
  for (let index = start; index < end; index += 1) {
    const op = ops[index]!;
    body.push(`${op.kind === "same" ? " " : op.kind === "add" ? "+" : "-"}${op.line}`);
  }
  const header = `@@ -${oldCount === 0 ? 0 : oldLine},${oldCount} +${newCount === 0 ? 0 : newLine},${newCount} @@`;
  return {
    patch: [`--- a/${path}`, `+++ b/${path}`, header, ...body].join("\n"),
    additions,
    deletions,
  };
}

/** Applies a standard unified diff to one file's text. */
export function applyUnifiedPatch(beforeValue: string, patch: string): string {
  const before = splitLines(beforeValue);
  const lines = patch.replace(/\r\n/g, "\n").split("\n");
  const hunks: Array<{
    oldStart: number;
    oldCount: number;
    lines: Array<{ kind: "same" | "add" | "del"; line: string }>;
  }> = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    const header = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (!header) continue;
    const oldStart = Number(header[1]);
    const oldCount = header[2] === undefined ? 1 : Number(header[2]);
    const hunkLines: Array<{ kind: "same" | "add" | "del"; line: string }> = [];
    index += 1;
    while (index < lines.length) {
      const next = lines[index]!;
      if (/^@@ /.test(next)) {
        index -= 1;
        break;
      }
      if (next.startsWith("\\ No newline")) {
        index += 1;
        continue;
      }
      if (next.startsWith("--- ") || next.startsWith("+++ ") || next.startsWith("diff ") || next.startsWith("index ")) {
        index += 1;
        continue;
      }
      if (next.startsWith(" ")) hunkLines.push({ kind: "same", line: next.slice(1) });
      else if (next.startsWith("+")) hunkLines.push({ kind: "add", line: next.slice(1) });
      else if (next.startsWith("-")) hunkLines.push({ kind: "del", line: next.slice(1) });
      else if (next.trim() === "") hunkLines.push({ kind: "same", line: "" });
      else break;
      index += 1;
    }
    hunks.push({ oldStart, oldCount, lines: hunkLines });
  }

  if (hunks.length === 0) throw new Error("patch contains no unified-diff hunks");
  const output: string[] = [];
  let cursor = 0;
  for (const hunk of hunks) {
    const start = hunk.oldStart === 0 ? 0 : hunk.oldStart - 1;
    if (start < cursor || start > before.length) throw new Error(`patch hunk starts outside the file: line ${hunk.oldStart}`);
    output.push(...before.slice(cursor, start));
    let position = start;
    for (const line of hunk.lines) {
      if (line.kind === "same") {
        if (before[position] !== line.line) {
          throw new Error(`patch context mismatch at line ${position + 1}: expected ${JSON.stringify(line.line)}`);
        }
        output.push(before[position]!);
        position += 1;
      } else if (line.kind === "del") {
        if (before[position] !== line.line) {
          throw new Error(`patch removal mismatch at line ${position + 1}: expected ${JSON.stringify(line.line)}`);
        }
        position += 1;
      } else {
        output.push(line.line);
      }
    }
    cursor = position;
    if (hunk.oldCount > 0 && position !== start + hunk.oldCount) {
      // Counts are advisory in some editors; the line-level checks above are
      // authoritative. Keep applying instead of rejecting a valid hunk.
    }
  }
  output.push(...before.slice(cursor));
  return output.length === 0 ? "" : `${output.join("\n")}\n`;
}
