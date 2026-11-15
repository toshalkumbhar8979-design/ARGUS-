import { describe, expect, test } from "bun:test";
import type { ToolAvailability } from "../src/core/types";
import { buildInstallPlans, runInstallPlan } from "../src/core/installer";

function tool(id: string, install = `install ${id}`): ToolAvailability {
  return {
    id,
    name: id,
    category: "test",
    binary: id,
    installed: false,
    install,
    intrusive: false,
    description: "test adapter",
  };
}

const tools = [
  tool("subfinder"),
  tool("nmap"),
  tool("whatweb"),
  tool("semgrep"),
  tool("unknown-tool", "curl -fsSL https://example.com/install | sh"),
];

describe("installer planning", () => {
  test("chooses go and winget on Windows", () => {
    const which = (binary: string) => (binary === "winget" || binary === "go" ? `C:/bin/${binary}.exe` : null);
    const plans = buildInstallPlans(tools, { platform: "win32", which });
    const subfinder = plans.find((plan) => plan.id === "subfinder");
    const nmap = plans.find((plan) => plan.id === "nmap");
    const whatweb = plans.find((plan) => plan.id === "whatweb");
    const unknown = plans.find((plan) => plan.id === "unknown-tool");
    expect(subfinder?.manager).toBe("go");
    expect(subfinder?.available).toBe(true);
    expect(nmap?.manager).toBe("winget");
    expect(nmap?.requiresAdmin).toBe(false);
    expect(nmap?.display).toContain("Insecure.Nmap");
    expect(whatweb?.manager).toBe("gem");
    expect(whatweb?.available).toBe(false);
    expect(unknown?.manager).toBe("manual");
    expect(unknown?.command).toBeNull();
    expect(unknown?.display).toContain("curl");
  });

  test("marks apt plans as admin and prefers user-level go/pip on Linux", () => {
    const which = (binary: string) => (["apt-get", "go", "python"].includes(binary) ? `/usr/bin/${binary}` : null);
    const plans = buildInstallPlans(tools, { platform: "linux", which });
    const nmap = plans.find((plan) => plan.id === "nmap");
    const subfinder = plans.find((plan) => plan.id === "subfinder");
    const semgrep = plans.find((plan) => plan.id === "semgrep");
    expect(nmap?.manager).toBe("apt-get");
    expect(nmap?.requiresAdmin).toBe(true);
    expect(nmap?.display.startsWith("sudo ")).toBe(true);
    expect(subfinder?.manager).toBe("go");
    expect(subfinder?.requiresAdmin).toBe(false);
    expect(semgrep?.manager).toBe("python");
    expect(semgrep?.requiresAdmin).toBe(false);
  });

  test("uses brew on macOS and never executes an admin plan", async () => {
    const which = (binary: string) => (binary === "brew" ? "/opt/homebrew/bin/brew" : null);
    const plans = buildInstallPlans(tools, { platform: "darwin", which });
    const nmap = plans.find((plan) => plan.id === "nmap");
    expect(nmap?.manager).toBe("brew");
    expect(nmap?.available).toBe(true);

    const linuxPlans = buildInstallPlans(tools, {
      platform: "linux",
      which: (binary) => (binary === "apt-get" ? "/usr/bin/apt-get" : null),
    });
    const admin = linuxPlans.find((plan) => plan.id === "nmap");
    expect(admin?.requiresAdmin).toBe(true);
    const result = await runInstallPlan(admin!);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("elevated shell");
  });
});
