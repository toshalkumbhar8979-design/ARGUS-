import { describe, expect, test } from "bun:test";
import { normalizeCvss, parseCvssVector, severityForScore } from "../src/core/cvss";

describe("CVSS v3.1 base", () => {
  test("scores the canonical critical vectors", () => {
    expect(parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")?.score).toBe(9.8);
    // Log4Shell scope-changed profile.
    expect(parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")?.score).toBe(10);
    expect(parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")?.score).toBe(9.9);
  });

  test("scores mid and low vectors", () => {
    expect(parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")?.score).toBe(6.1);
    expect(parseCvssVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N")?.score).toBe(3.7);
    expect(parseCvssVector("AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")?.score).toBe(0);
  });

  test("maps scores to the severity scale", () => {
    expect(severityForScore(9.8)).toBe("critical");
    expect(severityForScore(7)).toBe("high");
    expect(severityForScore(4)).toBe("medium");
    expect(severityForScore(0.1)).toBe("low");
    expect(severityForScore(0)).toBe("info");
  });

  test("rejects malformed or incomplete vectors", () => {
    expect(parseCvssVector("")).toBeUndefined();
    expect(parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H") ).toBeUndefined();
    expect(parseCvssVector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeUndefined();
    expect(parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H")).toBeUndefined();
    expect(parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/Z:Z")).toBeUndefined();
    expect(parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:Q")).toBeUndefined();
  });

  test("computes temporal scores from optional metrics", () => {
    const result = parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C");
    expect(result?.baseScore).toBe(9.8);
    // 9.8 × 0.91 (E:U) × 1.0 (RL:O official fix) × 1.0 (RC:C) = 8.918 -> 9.0
    expect(result?.temporalScore).toBe(9);
    expect(result?.environmentalScore).toBeUndefined();
  });

  test("computes environmental scores, defaulting to base impact", () => {
    const same = parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:X");
    expect(same?.environmentalScore).toBe(9.8);
    const reduced = parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:L");
    expect(reduced?.environmentalScore).toBeLessThan(9.8);
    expect(reduced?.environmentalScore).toBeGreaterThan(0);
  });

  test("normalizes vectors and bare numbers", () => {
    expect(normalizeCvss("8.1")?.score).toBe(8.1);
    expect(normalizeCvss(7.5)?.severity).toBe("high");
    expect(normalizeCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")?.severity).toBe("critical");
    expect(normalizeCvss("11")).toBeUndefined();
    expect(normalizeCvss(undefined)).toBeUndefined();
  });
});
