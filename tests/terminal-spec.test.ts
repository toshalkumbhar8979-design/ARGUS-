import { describe, expect, test } from "bun:test";
import { buildTerminalSpec, buildVimSpec, toWslPath } from "../src/tui/terminal-spec";

const workspace = "C:\\Users\\tosha\\Downloads\\Pentest";

describe("embedded terminal specs", () => {
  test("translates Windows paths for Kali", () => {
    expect(toWslPath("C:\\Users\\tosha\\Downloads\\Pentest\\src\\cli.ts")).toBe(
      "/mnt/c/Users/tosha/Downloads/Pentest/src/cli.ts",
    );
    expect(toWslPath("/home/kali/x")).toBe("/home/kali/x");
  });

  test("opens vim through the Kali distro with a quoted path", () => {
    const spec = buildVimSpec("argus-workspace/recon/scan.sh", workspace, { distro: "kali-linux" });
    expect(spec.argv.slice(0, 5)).toEqual(["wsl.exe", "-d", "kali-linux", "--", "bash"]);
    expect(spec.argv[6]).toBe("vim '/mnt/c/Users/tosha/Downloads/Pentest/argus-workspace/recon/scan.sh'");
    expect(spec.title).toContain("scan.sh");
    expect(spec.cwd).toBe(workspace);
  });

  test("uses the host bash when no distro is given", () => {
    const spec = buildVimSpec("src/cli.ts", "/work", {});
    expect(spec.argv[0]).toBe("bash");
    expect(spec.argv[1]).toBe("-lc");
    expect(spec.argv[2]).toContain("vim '");
    expect(spec.argv[2]).toContain("cli.ts'");
  });

  test("a bare /terminal opens a login shell and /terminal <cmd> runs it", () => {
    expect(buildTerminalSpec(undefined, "/work").argv).toEqual(["bash", "-lc", "bash -l"]);
    expect(buildTerminalSpec("nmap -sV 127.0.0.1", "/work").argv).toEqual([
      "bash",
      "-lc",
      "nmap -sV 127.0.0.1",
    ]);
  });
});
