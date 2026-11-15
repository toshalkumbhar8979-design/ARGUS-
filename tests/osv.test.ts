import { describe, expect, test } from "bun:test";
import { inferEcosystem, lookupPackageVulns, packagesFromLockfile, parsePackageSpec } from "../src/core/osv";

describe("OSV research", () => {
  test("parses package specs and ecosystems", () => {
    expect(parsePackageSpec("lodash@4.17.20")).toEqual({ package: "lodash", version: "4.17.20" });
    expect(parsePackageSpec("@scope/pkg@1.2.3")).toEqual({ package: "@scope/pkg", version: "1.2.3" });
    expect(parsePackageSpec("@scope/pkg")).toEqual({ package: "@scope/pkg" });
    expect(inferEcosystem("@scope/pkg")).toBe("npm");
    expect(inferEcosystem("Newtonsoft.Json")).toBe("NuGet");
  });

  test("normalizes advisories and fixed versions", async () => {
    const calls: Array<{ url: string; body: unknown }> = [];
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), body: JSON.parse(String(init?.body ?? "{}")) });
      return new Response(
        JSON.stringify({
          vulns: [
            {
              id: "GHSA-aaaa-bbbb-cccc",
              aliases: ["CVE-2021-23337"],
              summary: "Prototype pollution in lodash",
              severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
              published: "2021-02-15T00:00:00Z",
              affected: [
                {
                  package: { name: "lodash", ecosystem: "npm" },
                  ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
                },
              ],
              references: [{ type: "ADVISORY", url: "https://example.com/advisory" }],
            },
          ],
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const result = await lookupPackageVulns(
      { package: "lodash", version: "4.17.20", ecosystem: "npm" },
      { fetchImpl },
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]?.body).toEqual({ package: { name: "lodash", ecosystem: "npm" }, version: "4.17.20" });
    expect(result.advisories).toHaveLength(1);
    expect(result.advisories[0]?.aliases).toContain("CVE-2021-23337");
    expect(result.advisories[0]?.fixedVersions).toEqual(["4.17.21"]);
    expect(result.advisories[0]?.cvss).toContain("CVSS:3.1");
  });

  test("reports no advisories without inventing one", async () => {
    const fetchImpl = (async () => new Response(JSON.stringify({}), { status: 200 })) as unknown as typeof fetch;
    const result = await lookupPackageVulns({ package: "left-pad", version: "1.3.0" }, { fetchImpl });
    expect(result.advisories).toEqual([]);
  });

  test("surfaces HTTP and network failures", async () => {
    const failing = (async () => new Response("nope", { status: 503 })) as unknown as typeof fetch;
    await expect(lookupPackageVulns({ package: "x" }, { fetchImpl: failing })).rejects.toThrow(/HTTP 503/);
    const offline = (async () => {
      throw new Error("getaddrinfo ENOTFOUND");
    }) as unknown as typeof fetch;
    await expect(lookupPackageVulns({ package: "x" }, { fetchImpl: offline })).rejects.toThrow(/OSV lookup failed/);
  });

  test("rejects an unsupported ecosystem", async () => {
    await expect(
      lookupPackageVulns({ package: "x", ecosystem: "NotReal" as never }, { fetchImpl: (async () => new Response("{}")) as unknown as typeof fetch }),
    ).rejects.toThrow(/unsupported ecosystem/);
  });

  test("extracts packages from a lockfile without duplicates", () => {
    const npmLock = JSON.stringify({
      packages: {
        "": { name: "app", version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.20" },
        "node_modules/express": { version: "4.18.2" },
      },
    });
    const found = packagesFromLockfile(npmLock, "npm");
    expect(found).toContainEqual({ package: "lodash", version: "4.17.20" });
    expect(found).toContainEqual({ package: "express", version: "4.18.2" });
    const requirements = packagesFromLockfile("flask==2.0.1\nrequests==2.31.0\n", "PyPI");
    expect(requirements).toEqual([
      { package: "flask", version: "2.0.1" },
      { package: "requests", version: "2.31.0" },
    ]);
  });
});
