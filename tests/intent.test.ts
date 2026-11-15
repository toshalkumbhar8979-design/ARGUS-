import { describe, expect, test } from "bun:test";
import { interpretLocalPrompt, isAssessmentPrompt } from "../src/tui/intent";

describe("local natural-language intent", () => {
  test("routes scan requests with named and inferred targets", () => {
    const named = interpretLocalPrompt("can you check example.com and find real bugs?");
    expect(named).toMatchObject({ kind: "scan", target: "example.com" });
    expect(named?.kind === "scan" ? named.line : "").not.toContain("--yes-authorized");

    const inferred = interpretLocalPrompt("is my site safe?", { scopeTargets: ["https://staging.example.com"] });
    expect(inferred).toMatchObject({ kind: "scan", target: "https://staging.example.com" });

    const local = interpretLocalPrompt("check http://127.0.0.1:54321/ and find real bugs");
    expect(local).toMatchObject({ kind: "scan", target: "http://127.0.0.1:54321/" });
  });

  test("understands 'scan the whole code base' without magic words", () => {
    const intent = interpretLocalPrompt("Hi can you scan whole code base find vuln and rank them", {
      workspace: process.cwd(),
    });
    expect(intent?.kind).toBe("scan");
    expect(intent?.kind === "scan" ? intent.target : "").toBe(process.cwd());
    expect(intent?.kind === "scan" ? intent.line : "").toContain("--profile repo");
  });

  test("treats a repository request as a repo scan, not a help request", () => {
    const intent = interpretLocalPrompt("help me find bugs in this repo", { workspace: process.cwd() });
    expect(intent?.kind).toBe("scan");
    expect(intent?.kind === "scan" ? intent.line : "").toContain("--profile repo");
    expect(intent?.kind === "scan" ? intent.line : "").not.toContain("/help");
  });

  test("routes findings, runs, reports, scope and setup actions", () => {
    expect(interpretLocalPrompt("show me the findings")).toEqual({ kind: "command", line: "/findings" });
    expect(interpretLocalPrompt("what did you find?")).toEqual({ kind: "command", line: "/findings" });
    expect(interpretLocalPrompt("show recent runs")).toEqual({ kind: "command", line: "/runs" });
    expect(interpretLocalPrompt("write the report")).toEqual({ kind: "command", line: "/report" });
    expect(interpretLocalPrompt("preview src/cli.ts")).toEqual({ kind: "command", line: '/preview "src/cli.ts"' });
    expect(interpretLocalPrompt("show me src/core/http.ts")).toEqual({
      kind: "command",
      line: '/preview "src/core/http.ts"',
    });
    expect(interpretLocalPrompt("am i authorized?")).toEqual({ kind: "command", line: "/scope" });
    expect(interpretLocalPrompt("doctor")).toEqual({ kind: "command", line: "/doctor" });
  });

  test("opens dashboards, provider, model and key flows", () => {
    expect(interpretLocalPrompt("open the dashboard")).toEqual({ kind: "modal", modal: "dashboard" });
    expect(interpretLocalPrompt("which providers do you have?")).toEqual({ kind: "modal", modal: "providers" });
    expect(interpretLocalPrompt("switch model")).toEqual({ kind: "modal", modal: "models" });
    expect(interpretLocalPrompt("add nvidia api key")).toMatchObject({ kind: "connect", keyFor: "nvidia", startInKey: true });
  });

  test("handles web, JWT and HTTP shortcuts without a model", () => {
    expect(interpretLocalPrompt("search the web for CVE-2025-1234")).toEqual({
      kind: "command",
      line: "/web CVE-2025-1234",
    });
    expect(interpretLocalPrompt("jwt eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1In0.")).toEqual({
      kind: "command",
      line: "/jwt eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1In0.",
    });
    expect(interpretLocalPrompt("http https://example.com/admin")).toEqual({
      kind: "command",
      line: '/http "https://example.com/admin" --method GET',
    });
  });

  test("keeps a scan sentence out of the keyword shortcuts when it mentions a report", () => {
    const intent = interpretLocalPrompt("audit https://example.com and give me the vuln report here in chat please");
    expect(intent?.kind).toBe("scan");
    expect(intent?.kind === "scan" ? intent.line : "").not.toContain("/report");
  });

  test("leaves long prose to the model instead of matching a keyword inside it", () => {
    expect(
      interpretLocalPrompt("please put together a detailed report of everything you found in the last run"),
    ).toBeUndefined();
    expect(isAssessmentPrompt("audit https://example.com")).toBe(true);
    expect(isAssessmentPrompt("explain the difference between SSRF and CSRF")).toBe(false);
  });

  test("leaves genuine reasoning questions to the model", () => {
    expect(interpretLocalPrompt("explain the difference between SSRF and CSRF")).toBeUndefined();
    expect(interpretLocalPrompt("show me the findings")).toEqual({ kind: "command", line: "/findings" });
    expect(interpretLocalPrompt("preview this file and tell me if it looks safe")).toBeUndefined();
    expect(interpretLocalPrompt("/scan example.com")).toBeUndefined();
    expect(interpretLocalPrompt("check two sites")).toBeUndefined();
  });
});
