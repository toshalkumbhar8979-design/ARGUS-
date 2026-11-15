import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  assertPublicUrl,
  decodeEntities,
  htmlToText,
  isPrivateAddress,
  isPrivateHostname,
  parseDuckDuckGo,
  readWebPage,
  searchWeb,
} from "../src/core/web";

const ddgFixture = `<!doctype html><html><head><title>Results</title></head><body>
<a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fadvisory&amp;rut=abc">Example <b>Advisory</b></a>
<a class="result__snippet" href="#">A <b>snippet</b> about the issue.</a>
<a rel="nofollow" class="result__a" href="https://vendor.example/notes">Vendor notes</a>
<div class="result__snippet">Second result text.</div>
</body></html>`;

let previousSearchUrl: string | undefined;

beforeEach(() => {
  previousSearchUrl = process.env.ARGUS_SEARCH_URL;
  delete process.env.ARGUS_SEARCH_URL;
});

afterEach(() => {
  if (previousSearchUrl === undefined) delete process.env.ARGUS_SEARCH_URL;
  else process.env.ARGUS_SEARCH_URL = previousSearchUrl;
});

describe("web content helpers", () => {
  test("decodes entities, extracts titles and strips executable markup", () => {
    expect(decodeEntities("A &amp; B &#x41; &nbsp; &#39;quoted&#39;")).toBe("A & B A   'quoted'");
    const html = "<title>Advisory &amp; notes</title><script>alert(1)</script><style>x{}</style><p>Hello <b>world</b></p>";
    expect(htmlToText(html)).toBe("Hello world");
  });

  test("parses DuckDuckGo result links and unwraps redirects", () => {
    const results = parseDuckDuckGo(ddgFixture, 5);
    expect(results).toHaveLength(2);
    expect(results[0]?.url).toBe("https://example.com/advisory");
    expect(results[0]?.title).toBe("Example Advisory");
    expect(results[0]?.snippet).toContain("A snippet about the issue.");
    expect(results[1]?.url).toBe("https://vendor.example/notes");
    expect(results[1]?.snippet).toContain("Second result text.");
  });
});

describe("url safety", () => {
  test("rejects private and local literals", () => {
    for (const value of ["127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1", "fe80::1"]) {
      expect(isPrivateAddress(value)).toBe(true);
    }
    expect(isPrivateAddress("8.8.8.8")).toBe(false);
    expect(isPrivateAddress("93.184.216.34")).toBe(false);
    expect(isPrivateHostname("localhost")).toBe(true);
    expect(isPrivateHostname("api.internal")).toBe(true);
    expect(isPrivateHostname("example.com")).toBe(false);
  });

  test("rejects private hosts and embedded credentials before fetching", async () => {
    await expect(assertPublicUrl("http://127.0.0.1:8080/")).rejects.toThrow(/private or local/);
    await expect(assertPublicUrl("https://user:pass@example.com/")).rejects.toThrow(/credentials/);
    await expect(assertPublicUrl("file:///etc/passwd")).rejects.toThrow(/http and https/);
  });
});

describe("web search", () => {
  test("uses DuckDuckGo with no key and caches the result", async () => {
    let calls = 0;
    const fetchImpl = (async (input: string | URL | Request) => {
      calls += 1;
      expect(String(input)).toContain("html.duckduckgo.com/html/");
      expect(String(input)).toContain("argus-test-ddg");
      return new Response(ddgFixture, { status: 200, headers: { "content-type": "text/html" } });
    }) as unknown as typeof fetch;

    const first = await searchWeb("argus-test-ddg", { fetchImpl, limit: 2 });
    const second = await searchWeb("argus-test-ddg", { fetchImpl, limit: 2 });
    expect(first).toHaveLength(2);
    expect(first[0]?.url).toBe("https://example.com/advisory");
    expect(second[0]?.url).toBe(first[0]?.url);
    expect(calls).toBe(1);
  });

  test("supports a user-owned SearXNG JSON endpoint", async () => {
    process.env.ARGUS_SEARCH_URL = "https://search.example/search";
    let seen = "";
    const fetchImpl = (async (input: string | URL | Request) => {
      seen = String(input);
      return Response.json({
        results: [
          { title: "CVE advisory", url: "https://vendor.example/cve", content: "Affected versions" },
          { title: "Duplicate", url: "https://vendor.example/cve", content: "duplicate" },
        ],
      });
    }) as unknown as typeof fetch;
    const results = await searchWeb("argus-test-searx", { fetchImpl, limit: 3 });
    expect(seen).toContain("format=json");
    expect(seen).toContain("q=argus-test-searx");
    expect(results).toHaveLength(1);
    expect(results[0]?.title).toBe("CVE advisory");
  });
});

describe("page reading", () => {
  const publicDns = async () => ["93.184.216.34"];

  test("returns readable text and refuses scripts", async () => {
    const fetchImpl = (async () =>
      new Response(
        "<html><head><title>Advisory title</title></head><body><script>bad()</script><p>Use version 2.</p></body></html>",
        { status: 200, headers: { "content-type": "text/html; charset=utf-8" } },
      )) as unknown as typeof fetch;
    const page = await readWebPage("https://example.com/advisory", {
      fetchImpl,
      resolveHost: publicDns,
      maxChars: 1_000,
    });
    expect(page.title).toBe("Advisory title");
    expect(page.text).toContain("Use version 2.");
    expect(page.text).not.toContain("bad()");
    expect(page.truncated).toBe(false);
  });

  test("rejects a redirect to a private address", async () => {
    const fetchImpl = (async () =>
      new Response("", { status: 302, headers: { location: "http://127.0.0.1/secret" } })) as unknown as typeof fetch;
    await expect(
      readWebPage("https://example.com/advisory", { fetchImpl, resolveHost: publicDns }),
    ).rejects.toThrow(/private or local/);
  });
});
