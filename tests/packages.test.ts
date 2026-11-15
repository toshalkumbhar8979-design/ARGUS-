import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildPackageInstallPlan,
  detectPackageManager,
  PackageInputError,
} from "../src/core/packages";

let temp: string;

beforeEach(async () => {
  temp = await mkdtemp(join(tmpdir(), "argus-packages-"));
});

afterEach(async () => {
  await rm(temp, { recursive: true, force: true });
});

async function touch(name: string, content = "{}"): Promise<void> {
  await writeFile(join(temp, name), content, "utf8");
}

describe("package install planning", () => {
  test("detects bun from its lockfile and keeps the command as argv", async () => {
    await touch("package.json");
    await touch("bun.lock");
    const plan = buildPackageInstallPlan({ name: "zod", cwd: temp });
    expect(plan.manager).toBe("bun");
    expect(plan.argv).toEqual(["bun", "add", "zod"]);
    expect(plan.display).toBe("bun add zod");
  });

  test("supports npm, versions and development dependencies", async () => {
    await touch("package.json");
    await touch("package-lock.json");
    const plan = buildPackageInstallPlan({ name: "vitest", version: "2.1.0", dev: true, cwd: temp });
    expect(plan.manager).toBe("npm");
    expect(plan.argv).toEqual(["npm", "install", "--save-dev", "vitest@2.1.0"]);
  });

  test("uses the available Python binary for pip", async () => {
    await touch("pyproject.toml");
    const plan = buildPackageInstallPlan(
      { name: "requests", version: "2.32.0", cwd: temp },
      { which: (binary) => (binary === "python3" ? "/usr/bin/python3" : null) },
    );
    expect(plan.manager).toBe("pip");
    expect(plan.argv).toEqual(["python3", "-m", "pip", "install", "requests==2.32.0"]);
  });

  test("maps composer and cargo development flags", async () => {
    await touch("composer.json");
    const composer = buildPackageInstallPlan({ name: "phpunit/phpunit", dev: true, cwd: temp });
    expect(composer.argv).toEqual(["composer", "require", "--dev", "phpunit/phpunit"]);

    const cargoDir = await mkdtemp(join(tmpdir(), "argus-cargo-"));
    try {
      await writeFile(join(cargoDir, "Cargo.toml"), "[package]\nname = \"demo\"\n", "utf8");
      const cargo = buildPackageInstallPlan({ name: "serde", version: "1.0", dev: true, cwd: cargoDir });
      expect(cargo.argv).toEqual(["cargo", "add", "--dev", "serde@1.0"]);
    } finally {
      await rm(cargoDir, { recursive: true, force: true });
    }
  });

  test("rejects shell metacharacters and flag injection", () => {
    expect(() => buildPackageInstallPlan({ name: "zod; rm -rf /", cwd: temp })).toThrow(PackageInputError);
    expect(() => buildPackageInstallPlan({ name: "--save-dev", cwd: temp })).toThrow(PackageInputError);
    expect(() => buildPackageInstallPlan({ name: "zod", version: "1.0 --save-dev", cwd: temp })).toThrow(
      PackageInputError,
    );
  });

  test("reports a missing manager rather than guessing", () => {
    expect(() => detectPackageManager(temp)).toThrow(/could not detect/i);
  });
});
