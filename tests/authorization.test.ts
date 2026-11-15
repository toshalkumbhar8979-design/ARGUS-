import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  acceptTerms,
  consentPath,
  isAuthorizedOperator,
  readConsent,
  revokeConsent,
  TERMS_VERSION,
  termsText,
} from "../src/core/authorization";
import { inferPermissionPolicy, permissionSummary } from "../src/core/permissions";

let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "argus-consent-"));
});

afterAll(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("authorized-use agreement", () => {
  test("states the boundary and is not just a click", () => {
    const text = termsText();
    expect(text).toContain("AUTHORIZED USE AGREEMENT");
    expect(text).toContain("written permission");
    expect(text).toContain("cloud metadata");
    expect(text).toContain("destructive");
    expect(text).toContain("not legal advice");
  });

  test("is unaccepted until the operator accepts, then persists", async () => {
    expect(await readConsent(dir)).toBeUndefined();
    expect(await isAuthorizedOperator(dir)).toBe(false);
    const record = await acceptTerms(dir, "  tosha  ");
    expect(record.version).toBe(TERMS_VERSION);
    expect(record.acceptedBy).toBe("tosha");
    expect(record.basis).toBe("written-authorization");
    expect(await isAuthorizedOperator(dir)).toBe(true);
    const reloaded = await readConsent(dir);
    expect(reloaded?.acceptedAt).toBe(record.acceptedAt);
  });

  test("a different terms version is not accepted", async () => {
    await writeFile(consentPath(dir), JSON.stringify({ version: 999, acceptedAt: new Date().toISOString() }));
    expect(await readConsent(dir)).toBeUndefined();
  });

  test("revocation removes the record", async () => {
    await acceptTerms(dir);
    await revokeConsent(dir);
    expect(await isAuthorizedOperator(dir)).toBe(false);
    await expect(revokeConsent(dir)).resolves.toBeUndefined();
  });
});

describe("operator mode permissions", () => {
  test("acceptance turns on autonomy for an assessment", () => {
    const summary = permissionSummary(inferPermissionPolicy("attack example.com", { authorizedOperator: true }));
    expect(summary).toContain("auto | write=auto | shell=auto | install=auto | network=auto");
    expect(summary).toContain("agents=auto");
  });

  test("without acceptance the default still asks for local changes", () => {
    const policy = inferPermissionPolicy("attack example.com");
    expect(policy.source).toBe("default");
    expect(policy.shell).toBe("ask");
    expect(policy.network).toBe("allow");
  });

  test("read-only still wins over operator mode", () => {
    const policy = inferPermissionPolicy("read only, do not change anything", { authorizedOperator: true });
    expect(policy.source).toBe("read-only");
    expect(policy.write).toBe("deny");
    expect(policy.shell).toBe("deny");
  });
});
