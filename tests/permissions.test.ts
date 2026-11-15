import { describe, expect, test } from "bun:test";
import {
  defaultPermissionPolicy,
  inferPermissionPolicy,
  isPackageInstallCommand,
  permissionSummary,
} from "../src/core/permissions";

describe("prompt-independent permissions", () => {
  test("applies the same guarded posture to every kind of prompt", () => {
    const prompts = [
      "fix the parser",
      "scan example.com",
      "what does this function do?",
      "make it better",
      "review the authentication flow",
      "install zod",
      "find bugs in the repository",
      "refactor the request layer and run tests",
    ];
    for (const prompt of prompts) {
      const policy = inferPermissionPolicy(prompt, { hasTarget: true });
      expect(policy.source).toBe("default");
      expect(policy.write).toBe("ask");
      expect(policy.shell).toBe("ask");
      expect(policy.install).toBe("ask");
      expect(policy.network).toBe("allow");
      expect(policy.subagents).toBe("allow");
    }
  });

  test("allows scoped network work without inspecting the sentence", () => {
    const policy = inference("could you look at this");
    expect(policy.network).toBe("allow");
    expect(policy.source).toBe("default");
  });

  test("honors an explicit read-only instruction", () => {
    const policy = inferPermissionPolicy("read-only: explain the bug, don't change anything");
    expect(policy.source).toBe("read-only");
    expect(policy.write).toBe("deny");
    expect(policy.shell).toBe("deny");
    expect(policy.install).toBe("deny");
    expect(policy.network).toBe("allow");
  });

  test("honors an explicit no-confirmations instruction", () => {
    const policy = inferPermissionPolicy("just do it without asking: fix the parser and install zod");
    expect(policy.source).toBe("auto");
    expect(policy.write).toBe("allow");
    expect(policy.shell).toBe("allow");
    expect(policy.install).toBe("allow");
    expect(policy.network).toBe("allow");
  });

  test("leaves the default policy intact for ordinary prose", () => {
    expect(defaultPermissionPolicy()).toEqual(inferPermissionPolicy("anything at all"));
  });

  test("prints a compact policy line", () => {
    const summary = permissionSummary(defaultPermissionPolicy());
    expect(summary).toContain("default");
    expect(summary).toContain("write=ask");
    expect(summary).toContain("network=auto");
    expect(summary).toContain("agents=auto");
  });

  test("recognizes package-manager commands without matching test runs", () => {
    expect(isPackageInstallCommand("bun add zod")).toBe(true);
    expect(isPackageInstallCommand("npm install --save-dev vitest")).toBe(true);
    expect(isPackageInstallCommand("python -m pip install requests")).toBe(true);
    expect(isPackageInstallCommand("go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")).toBe(true);
    expect(isPackageInstallCommand("npm test")).toBe(false);
    expect(isPackageInstallCommand("git status")).toBe(false);
  });
});

function inference(prompt: string) {
  return inferPermissionPolicy(prompt, { hasTarget: true });
}
