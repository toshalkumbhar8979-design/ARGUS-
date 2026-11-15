/**
 * Dependency-free browser automation over the Chrome DevTools Protocol.
 *
 * Strix ships Playwright plus a proxy. Argus instead drives a browser the
 * operator already has installed (Chrome, Edge or Chromium) through its
 * remote-debugging endpoint, so authenticated UI testing works without adding a
 * 150 MB dependency or downloading a browser. Everything is scope-gated by the
 * caller; this module never decides what may be visited.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

export interface BrowserOptions {
  workspace: string;
  executable?: string;
  /** Route page traffic through a local proxy (used when ARGUS's proxy is on). */
  proxyUrl?: string;
  width?: number;
  height?: number;
  timeoutMs?: number;
}

export interface BrowserSnapshot {
  url: string;
  title: string;
  text: string;
  links: Array<{ text: string; href: string }>;
  forms: Array<{ action: string; method: string; inputs: string[] }>;
  buttons: string[];
}

interface PendingCall {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

const WINDOWS_CANDIDATES = [
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
];
const MAC_CANDIDATES = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
];
const LINUX_CANDIDATES = [
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/microsoft-edge",
];

/** Finds a Chromium-family browser already installed on this machine. */
export function findBrowserExecutable(): string | undefined {
  const explicit = [process.env.ARGUS_BROWSER, process.env.CHROME_PATH, process.env.EDGE_PATH];
  for (const candidate of explicit) {
    if (candidate && existsSync(candidate)) return candidate;
  }
  const platform =
    process.platform === "win32" ? WINDOWS_CANDIDATES : process.platform === "darwin" ? MAC_CANDIDATES : LINUX_CANDIDATES;
  return platform.find((candidate) => existsSync(candidate));
}

function sleep(ms: number): Promise<void> {
  return new Promise((done) => setTimeout(done, ms));
}

export class CdpBrowser {
  private readonly calls = new Map<number, PendingCall>();
  private seq = 0;
  private closed = false;
  private deviation = "";

  private constructor(
    private readonly child: ChildProcess,
    private readonly socket: WebSocket,
    private sessionId: string,
    private readonly workspace: string,
    private readonly timeoutMs: number,
  ) {}

  static async launch(options: BrowserOptions): Promise<CdpBrowser> {
    const executable = options.executable ?? findBrowserExecutable();
    if (!executable) {
      throw new Error(
        "No Chrome, Edge or Chromium found. Install one, or set ARGUS_BROWSER to its full path.",
      );
    }
    const timeoutMs = options.timeoutMs ?? 30_000;
    const profile = resolve(options.workspace, ".argus", "browser-profile");
    await mkdir(profile, { recursive: true });

    const args = [
      "--headless=new",
      "--disable-gpu",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--disable-background-networking",
      "--remote-debugging-port=0",
      `--user-data-dir=${profile}`,
      "--window-size=1280,800",
      ...(options.proxyUrl ? [`--proxy-server=${options.proxyUrl}`, "--proxy-bypass-list=<-loopback>"] : []),
      "about:blank",
    ];
    if (process.platform !== "win32") args.unshift("--no-sandbox");
    const child = spawn(executable, args, { stdio: ["ignore", "ignore", "pipe"], windowsHide: true });

    const endpoint = await new Promise<string>((done, fail) => {
      let buffer = "";
      const timer = setTimeout(() => fail(new Error("Browser did not expose a debugging endpoint in time.")), timeoutMs);
      const onData = (chunk: Buffer | string) => {
        buffer += String(chunk);
        const match = buffer.match(/DevTools listening on (ws:\/\/\S+)/);
        if (match?.[1]) {
          clearTimeout(timer);
          done(match[1]);
        }
      };
      child.stderr?.on("data", onData);
      child.on("error", (error) => {
        clearTimeout(timer);
        fail(error);
      });
      child.on("exit", (code) => {
        clearTimeout(timer);
        fail(new Error(`Browser exited before it was ready (code ${code ?? "unknown"}).`));
      });
    });

    const socket = await new Promise<WebSocket>((done, fail) => {
      const ws = new WebSocket(endpoint);
      const timer = setTimeout(() => fail(new Error("Timed out connecting to the browser.")), timeoutMs);
      ws.addEventListener("open", () => {
        clearTimeout(timer);
        done(ws);
      });
      ws.addEventListener("error", () => {
        clearTimeout(timer);
        fail(new Error("Could not open the browser debugging socket."));
      });
    });

    const browser = new CdpBrowser(child, socket, "", options.workspace, timeoutMs);
    socket.addEventListener("message", (event) => browser.onMessage(event.data));
    socket.addEventListener("close", () => browser.failAll("Browser connection closed."));

    const target = await browser.send("Target.createTarget", { url: "about:blank" });
    const targetId = (target as { targetId?: string }).targetId;
    if (!targetId) throw new Error("Browser did not create a page target.");
    const attached = await browser.send("Target.attachToTarget", { targetId, flatten: true });
    const sessionId = (attached as { sessionId?: string }).sessionId;
    if (!sessionId) throw new Error("Browser did not attach to the page target.");
    browser.sessionId = sessionId;
    await browser.send("Page.enable", {});
    await browser.send("Runtime.enable", {});
    await browser.send("Emulation.setDeviceMetricsOverride", {
      width: options.width ?? 1280,
      height: options.height ?? 800,
      deviceScaleFactor: 1,
      mobile: false,
    });
    return browser;
  }

  private onMessage(raw: unknown): void {
    let payload: { id?: number; result?: unknown; error?: { message?: string } };
    try {
      payload = JSON.parse(String(raw)) as typeof payload;
    } catch {
      return;
    }
    if (payload.id === undefined) return;
    const call = this.calls.get(payload.id);
    if (!call) return;
    this.calls.delete(payload.id);
    clearTimeout(call.timer);
    if (payload.error) call.reject(new Error(payload.error.message ?? "Browser command failed."));
    else call.resolve(payload.result);
  }

  private failAll(message: string): void {
    for (const call of this.calls.values()) {
      clearTimeout(call.timer);
      call.reject(new Error(message));
    }
    this.calls.clear();
  }

  private send(method: string, params: Record<string, unknown> = {}): Promise<unknown> {
    if (this.closed) return Promise.reject(new Error("Browser is closed."));
    const id = ++this.seq;
    return new Promise((done, fail) => {
      const timer = setTimeout(() => {
        this.calls.delete(id);
        fail(new Error(`Browser command timed out: ${method}`));
      }, this.timeoutMs);
      this.calls.set(id, { resolve: done, reject: fail, timer });
      try {
        this.socket.send(
          JSON.stringify({ id, method, params, ...(this.sessionId ? { sessionId: this.sessionId } : {}) }),
        );
      } catch (error) {
        clearTimeout(timer);
        this.calls.delete(id);
        fail(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  private async evaluate<T>(expression: string): Promise<T> {
    const result = (await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
      userGesture: true,
    })) as { result?: { value?: unknown }; exceptionDetails?: { text?: string; exception?: { description?: string } } };
    if (result.exceptionDetails) {
      const text =
        result.exceptionDetails.exception?.description ??
        result.exceptionDetails.text ??
        "The page script raised an exception.";
      throw new Error(text.split("\n")[0]!.slice(0, 400));
    }
    return result.result?.value as T;
  }

  get currentUrl(): string {
    return this.deviation;
  }

  async navigate(url: string): Promise<{ url: string; title: string; status: number }> {
    this.deviation = url;
    await this.send("Page.navigate", { url });
    const deadline = Date.now() + this.timeoutMs;
    while (Date.now() < deadline) {
      const state = await this.evaluate<string>("document.readyState").catch(() => "loading");
      if (state === "complete") break;
      await sleep(200);
    }
    await sleep(250);
    const page = await this.evaluate<{ url: string; title: string }>(
      "({ url: location.href, title: document.title || '' })",
    );
    return { ...page, status: 0 };
  }

  async snapshot(): Promise<BrowserSnapshot> {
    return this.evaluate<BrowserSnapshot>(`(() => {
      const clean = (value) => String(value || "").replace(/\\s+/g, " ").trim();
      const text = document.body ? document.body.innerText : "";
      return {
        url: location.href,
        title: document.title || "",
        text: text.replace(/\\n{3,}/g, "\\n\\n").slice(0, 4000),
        links: Array.from(document.querySelectorAll("a[href]")).slice(0, 80).map((a) => ({
          text: clean(a.innerText).slice(0, 80),
          href: a.href,
        })),
        forms: Array.from(document.forms).slice(0, 20).map((form) => ({
          action: form.action || location.href,
          method: (form.method || "get").toUpperCase(),
          inputs: Array.from(form.elements).slice(0, 40).map((el) =>
            [el.tagName.toLowerCase(), el.getAttribute("name") || el.id || el.getAttribute("type") || ""].join(":"),
          ),
        })),
        buttons: Array.from(document.querySelectorAll("button, input[type=submit]")).slice(0, 40).map((el) =>
          clean(el.innerText || el.value || el.getAttribute("aria-label") || el.id).slice(0, 60),
        ),
      };
    })()`);
  }

  async click(selector: string): Promise<{ clicked: boolean; detail: string }> {
    const safe = JSON.stringify(selector);
    return this.evaluate(`(() => {
      const el = document.querySelector(${safe});
      if (!el) return { clicked: false, detail: "no element matches the selector" };
      el.scrollIntoView({ block: "center" });
      el.click();
      return { clicked: true, detail: (el.tagName || "") + " " + String(el.innerText || "").trim().slice(0, 60) };
    })()`);
  }

  async type(selector: string, text: string, submit = false): Promise<{ typed: boolean; detail: string }> {
    const safeSelector = JSON.stringify(selector);
    const safeText = JSON.stringify(text);
    return this.evaluate(`(() => {
      const el = document.querySelector(${safeSelector});
      if (!el) return { typed: false, detail: "no element matches the selector" };
      el.focus();
      const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, "value");
      if (setter && setter.set) setter.set.call(el, ${safeText});
      else el.value = ${safeText};
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      ${submit ? "if (el.form && el.form.requestSubmit) el.form.requestSubmit(); else if (el.form) el.form.submit();" : ""}
      return { typed: true, detail: (el.tagName || "") + " " + (el.getAttribute("name") || el.id || "") };
    })()`);
  }

  async screenshot(path: string): Promise<{ path: string; bytes: number }> {
    const shot = (await this.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false })) as {
      data?: string;
    };
    if (!shot.data) throw new Error("Browser returned an empty screenshot.");
    const buffer = Buffer.from(shot.data, "base64");
    const absolute = resolve(path);
    const root = resolve(this.workspace);
    if (absolute !== root && !absolute.startsWith(`${root}\\`) && !absolute.startsWith(`${root}/`)) {
      throw new Error("Screenshot path must stay inside the workspace.");
    }
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, buffer);
    return { path: absolute, bytes: buffer.length };
  }

  async evaluateInPage(expression: string): Promise<unknown> {
    return this.evaluate(expression);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      await this.send("Browser.close", {});
    } catch {
      // the process may already be gone
    }
    try {
      this.socket.close();
    } catch {
      // ignore
    }
    this.failAll("Browser closed.");
    const exited = await Promise.race([
      new Promise<boolean>((done) => this.child.once("exit", () => done(true))),
      sleep(2_000).then(() => false),
    ]);
    if (!exited) {
      try {
        this.child.kill();
      } catch {
        // ignore
      }
    }
  }
}
