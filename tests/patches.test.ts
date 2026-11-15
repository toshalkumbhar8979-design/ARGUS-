import { describe, expect, test } from "bun:test";
import { buildPipeline } from "../src/core/pipeline";
import { lineDiff, patchFileFor, repoLocation } from "../src/core/patches";
import type { Finding } from "../src/core/types";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "finding-1",
    runId: "run-1",
    title: "Raw HTML sink in public/js/main.js",
    severity: "low",
    category: "code",
    confidence: "likely",
    target: "public/js/main.js",
    evidence: "public/js/main.js:236\ntermBody.innerHTML = \"\";",
    description: "Raw HTML sink.",
    remediation: "Sanitize with a vetted library and prefer textContent.",
    references: [],
    tool: "argus-code",
    timestamp: "2026-10-24T10:00:00.000Z",
    fingerprint: "fp",
    metadata: {
      path: "public/js/main.js",
      line: 236,
      rule: "innerhtml",
      source: '    termBody.innerHTML = "";',
    },
    ...overrides,
  };
}

describe("candidate patches", () => {
  test("a repo finding resolves to its exact path and line", () => {
    expect(repoLocation(finding({}))).toEqual({
      path: "public/js/main.js",
      line: 236,
      rule: "innerhtml",
      source: '    termBody.innerHTML = "";',
    });
  });

  test("evidence is the fallback when metadata is absent", () => {
    const location = repoLocation(finding({ metadata: undefined }));
    expect(location?.path).toBe("public/js/main.js");
    expect(location?.line).toBe(236);
  });

  test("a safe mechanical fix becomes an exact one-line diff", () => {
    const file = patchFileFor(finding({}));
    expect(file?.diff).toBeDefined();
    expect(file?.change).toContain("textContent");
    expect(file?.diff).toBe(
      [
        "--- a/public/js/main.js",
        "+++ b/public/js/main.js",
        "@@ -236,1 +236,1 @@",
        '-    termBody.innerHTML = "";',
        '+    termBody.textContent = "";',
      ].join("\n"),
    );
  });

  test("rules without a safe rewrite still name the file and line", () => {
    const file = patchFileFor(
      finding({
        category: "secrets",
        metadata: { path: ".env", line: 12, rule: "aws-access-key" },
        remediation: "Move the secret to a secret manager and rotate it.",
      }),
    );
    expect(file?.path).toBe(".env");
    expect(file?.line).toBe(12);
    expect(file?.change).toContain("rotate");
    expect(file?.diff).toBeUndefined();
  });

  test("web findings never fabricate a file patch", () => {
    expect(
      patchFileFor(
        finding({
          category: "misconfiguration",
          target: "https://example.com/",
          url: "https://example.com/",
          metadata: undefined,
          evidence: "content-security-policy absent",
        }),
      ),
    ).toBeUndefined();
  });

  test("line diffs keep the original indentation", () => {
    expect(lineDiff("a.txt", 3, "\tvalue = 1", "\tvalue = 2")).toContain("-\tvalue = 1");
  });

  test("a privileged IaC line becomes a concrete diff", () => {
    const file = patchFileFor(
      finding({
        category: "iac",
        target: "pod.yaml",
        metadata: { path: "pod.yaml", line: 7, rule: "k8s-priv", source: "        privileged: true" },
        remediation: "Remove privileged mode; use granular capabilities.",
      }),
    );
    expect(file?.change).toBe("privileged: true  ->  privileged: false");
    expect(file?.diff).toContain("+        privileged: false");
  });

  test("the pipeline patch stage carries concrete diffs for repo findings", () => {
    const pipeline = buildPipeline([finding({})]);
    const patchStage = pipeline.stages.find((stage) => stage.id === "patch")!;
    expect(patchStage.status).toBe("done");
    expect(patchStage.items.some((item) => item.diff?.includes("+    termBody.textContent"))).toBe(true);
  });

  test("exploitability is not done when nothing was confirmed", () => {
    const pipeline = buildPipeline([finding({ severity: "medium", category: "misconfiguration", confidence: "confirmed" })]);
    const stage = pipeline.stages.find((entry) => entry.id === "exploitability")!;
    expect(stage.count).toBe(0);
    expect(stage.status).toBe("partial");
  });
});
