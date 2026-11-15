import { describe, expect, test } from "bun:test";
import { decodeWslOutput, findKali, parseWslDistros, shellQuote, WSL_INSTALL_ARGS, wslArgs } from "../src/core/wsl";

const LISTING = [
  "  NAME              STATE           VERSION",
  "* kali-linux        Running         2",
  "  Ubuntu-22.04      Stopped         2",
  "  docker-desktop    Stopped         2",
  "",
].join("\r\n");

describe("WSL detection", () => {
  test("parses the distro table and marks the default", () => {
    const distros = parseWslDistros(LISTING);
    expect(distros.map((entry) => entry.name)).toEqual(["kali-linux", "Ubuntu-22.04", "docker-desktop"]);
    expect(distros[0]).toEqual({ name: "kali-linux", state: "Running", version: "2", default: true });
    expect(distros[1]?.default).toBe(false);
  });

  test("normalizes UTF-16 output that still carries NUL bytes", () => {
    const utf16 = Buffer.from("  NAME   STATE   VERSION\r\n* kali-linux  Running  2\r\n", "utf16le");
    expect(decodeWslOutput(utf16)).toContain("kali-linux");
    expect(parseWslDistros(decodeWslOutput(utf16))[0]?.name).toBe("kali-linux");
  });

  test("prefers canonical Kali but accepts a renamed Kali distro", () => {
    expect(findKali(parseWslDistros(LISTING))).toBe("kali-linux");
    const renamed = parseWslDistros("  NAME    STATE   VERSION\n  Kali-Rolling  Stopped  2\n");
    expect(findKali(renamed)).toBe("Kali-Rolling");
    expect(findKali(parseWslDistros("  NAME  STATE  VERSION\n  Ubuntu  Stopped  2\n"))).toBeUndefined();
  });

  test("builds an argv that runs bash inside the chosen distro", () => {
    expect(wslArgs({ distro: "kali-linux", command: "nmap --version" })).toEqual([
      "-d",
      "kali-linux",
      "--",
      "bash",
      "-lc",
      "nmap --version",
    ]);
    expect(wslArgs({ command: "id" })).toEqual(["--", "bash", "-lc", "id"]);
    expect(wslArgs({ distro: "kali-linux", command: "ls", cwd: "/tmp/x y" })).toEqual([
      "-d",
      "kali-linux",
      "--",
      "bash",
      "-lc",
      "cd '/tmp/x y' && ls",
    ]);
    expect(wslArgs({ distro: "kali-linux", command: "apt-get install -y sqlmap", root: true })).toEqual([
      "-d",
      "kali-linux",
      "-u",
      "root",
      "--",
      "bash",
      "-lc",
      "apt-get install -y sqlmap",
    ]);
  });

  test("quotes single quotes without breaking out of the shell word", () => {
    expect(shellQuote("/tmp/it's")).toBe(`'/tmp/it'\\''s'`);
  });

  test("the install request targets Kali without launching it", () => {
    expect([...WSL_INSTALL_ARGS]).toEqual(["--install", "-d", "kali-linux", "--no-launch"]);
  });
});
