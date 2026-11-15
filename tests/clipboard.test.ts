import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { copyText, transcriptToText } from "../src/tui/clipboard";
import type { TranscriptEntry } from "../src/tui/state";

beforeEach(() => {
  process.env.ARGUS_CLIPBOARD = "off";
});

afterEach(() => {
  delete process.env.ARGUS_CLIPBOARD;
});

describe("clipboard", () => {
  test("uses OSC 52 and reports the channel", async () => {
    let seen = "";
    const result = await copyText({ copyToClipboardOSC52: (text) => ((seen = text), true) }, "hello");
    expect(seen).toBe("hello");
    expect(result.ok).toBe(true);
    expect(result.channels).toEqual(["terminal"]);
  });

  test("rejects empty text", async () => {
    const result = await copyText({ copyToClipboardOSC52: () => true }, "   ");
    expect(result.ok).toBe(false);
    expect(result.error).toContain("nothing to copy");
  });

  test("gives an actionable error when the terminal rejects OSC 52", async () => {
    const result = await copyText({ copyToClipboardOSC52: () => false }, "hello");
    expect(result.ok).toBe(false);
    expect(result.error).toContain("clipboard unavailable");
  });

  test("serializes the transcript with readable prefixes", () => {
    const entries: TranscriptEntry[] = [
      { id: 1, kind: "user", text: "audit example.com" },
      { id: 2, kind: "ok", text: "verified findings | 1" },
      { id: 3, kind: "finding", text: "Missing CSP", severity: "medium" },
      { id: 4, kind: "error", text: "probe failed" },
    ];
    expect(transcriptToText(entries)).toBe(
      "> audit example.com\n+ verified findings | 1\n[MED] Missing CSP\nx probe failed",
    );
  });
});
