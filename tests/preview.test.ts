import { describe, expect, test } from "bun:test";
import { languageFor, previewNote, previewRows, previewSubtitle, previewTitle, textPreview } from "../src/tui/preview";

describe("preview model", () => {
  test("numbers and slices a file for a text preview", () => {
    const content = Array.from({ length: 10 }, (_, index) => `line ${index + 1}`).join("\n");
    const payload = textPreview("src/a.ts", content, { start: 3, end: 5 });

    expect(payload.mode).toBe("text");
    expect(payload.exists).toBe(true);
    expect(payload.totalLines).toBe(10);
    expect(payload.start).toBe(3);
    expect(payload.end).toBe(5);
    expect(payload.truncated).toBe(true);

    const rows = previewRows(payload);
    expect(rows.map((row) => row.no)).toEqual([3, 4, 5]);
    expect(rows[0]?.text).toBe("line 3");
    expect(rows[0]?.tone).toBe("text");
  });

  test("parses a unified diff into gutter-marked rows", () => {
    const payload = {
      path: "src/a.ts",
      mode: "diff" as const,
      exists: true,
      diff: ["@@ -1,2 +1,2 @@", "-const a = 1;", "+const a = 2;", " const b = 3;"].join("\n"),
      additions: 1,
      deletions: 1,
    };

    const rows = previewRows(payload);
    expect(rows.map((row) => row.tone)).toEqual(["hunk", "del", "add", "text"]);
    expect(rows[1]?.marker).toBe("-");
    expect(rows[1]?.text).toBe("const a = 1;");
    expect(rows[2]?.marker).toBe("+");
    expect(previewSubtitle(payload)).toContain("+1/-1");
    expect(previewTitle(payload)).toBe("Preview a.ts");
  });

  test("labels languages and keeps the transcript note short", () => {
    expect(languageFor("src/core/http.ts")).toBe("typescript");
    expect(languageFor("Dockerfile")).toBe("dockerfile");
    expect(languageFor("assets/logo.png")).toBe("text");

    const note = previewNote(textPreview("src/core/http.ts", "a\nb\n"));
    expect(note).toContain("src/core/http.ts");
    expect(note).toContain("esc closes");
  });

  test("previews a file that has no trailing newline without inventing a line", () => {
    const payload = textPreview("notes.txt", "one\ntwo");
    expect(payload.totalLines).toBe(2);
    expect(previewRows(payload).map((row) => row.text)).toEqual(["one", "two"]);
  });
});
