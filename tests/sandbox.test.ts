import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import { DEFAULT_SANDBOX_IMAGE, dockerAvailable, sandboxArgs, SANDBOX_MOUNT } from "../src/core/sandbox";

const workspace = process.cwd();

describe("docker sandbox", () => {
  test("mounts the workspace at /work and keeps the network off by default", () => {
    const args = sandboxArgs({ workspace }, "nmap -sT example.com");
    expect(args.slice(0, 2)).toEqual(["run", "--rm"]);
    expect(args).toContain("--network");
    expect(args[args.indexOf("--network") + 1]).toBe("none");
    expect(args).toContain(`${resolve(workspace)}:${SANDBOX_MOUNT}`);
    expect(args[args.indexOf("-w") + 1]).toBe(SANDBOX_MOUNT);
    expect(args).not.toContain("NET_RAW");
    expect(args.slice(-4)).toEqual([DEFAULT_SANDBOX_IMAGE, "sh", "-lc", "nmap -sT example.com"]);
  });

  test("adds raw-socket capabilities and the host gateway when networked", () => {
    const args = sandboxArgs({ workspace, network: "host", readOnly: true }, "id");
    expect(args[args.indexOf("--network") + 1]).toBe("host");
    expect(args).toContain("NET_RAW");
    expect(args).toContain("NET_ADMIN");
    expect(args).toContain("host.docker.internal:host-gateway");
    expect(args).toContain(`${resolve(workspace)}:${SANDBOX_MOUNT}:ro`);
  });

  test("bounds logs and applies optional resource caps", () => {
    const args = sandboxArgs({ workspace, memory: "1g", cpus: "2", pidsLimit: 128 }, "true");
    expect(args).toContain("max-size=50m");
    expect(args).toContain("max-file=3");
    expect(args[args.indexOf("--memory") + 1]).toBe("1g");
    expect(args[args.indexOf("--cpus") + 1]).toBe("2");
    expect(args[args.indexOf("--pids-limit") + 1]).toBe("128");
  });

  test("rejects invalid limits instead of passing them to docker", () => {
    expect(() => sandboxArgs({ workspace, memory: "lots" }, "true")).toThrow(/Invalid memory limit/);
    expect(() => sandboxArgs({ workspace, cpus: "0" }, "true")).toThrow(/Invalid cpu limit/);
  });

  test("availability probe reports a boolean without throwing", async () => {
    expect(typeof (await dockerAvailable())).toBe("boolean");
  }, 20_000);
});
