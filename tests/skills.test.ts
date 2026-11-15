import { describe, expect, test } from "bun:test";
import { findSkill, formatSkill, SKILLS, skillNames } from "../src/core/skills";

describe("skill packs", () => {
  test("looks up by id beyond the core classes", () => {
    for (const id of skillNames()) {
      expect(findSkill(id)?.id).toBe(id);
    }
  });

  test("resolves aliases and loose topics", () => {
    expect(findSkill("IDOR")?.id).toBe("idor");
    expect(findSkill("bola")?.id).toBe("idor");
    expect(findSkill("blind sqli")?.id).toBe("sqli");
    expect(findSkill("path traversal")?.id).toBe("traversal");
    expect(findSkill("rce")?.id).toBe("command-injection");
    expect(findSkill("file upload")?.id).toBe("upload");
    expect(findSkill("jku")?.id).toBe("jwt");
  });

  test("returns undefined for an unrelated topic", () => {
    expect(findSkill("kubernetes hardening")).toBeUndefined();
    expect(findSkill("")).toBeUndefined();
  });

  test("formats a playbook with steps, proof and guardrails", () => {
    const text = formatSkill(findSkill("ssrf")!);
    expect(text).toContain("SKILL ssrf");
    expect(text).toContain("Steps:");
    expect(text).toContain("Confirm with:");
    expect(text).toContain("Do not:");
    expect(text).toContain("report_finding");
  });

  test("every pack has the required structure", () => {
    for (const skill of SKILLS) {
      expect(skill.title.length).toBeGreaterThan(10);
      expect(skill.steps.length).toBeGreaterThanOrEqual(3);
      expect(skill.confirm.length).toBeGreaterThan(0);
      expect(skill.avoid.length).toBeGreaterThan(0);
      expect(skill.aliases.every((alias) => /^[a-z0-9-]+$/.test(alias))).toBe(true);
    }
  });
});
