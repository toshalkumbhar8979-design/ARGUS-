import { describe, expect, test } from "bun:test";
import {
  detectSqlError,
  detectSsrf,
  detectTraversal,
  extractScriptSources,
  parseForms,
} from "../src/core/probes/attacks";

describe("active attack helpers", () => {
  test("recognizes database error signatures without flagging normal pages", () => {
    expect(detectSqlError("You have an error in your SQL syntax; check the manual")?.id).toBe("mysql");
    expect(detectSqlError('ERROR: syntax error at or near "\'" at character 42')?.id).toBe("postgres");
    expect(detectSqlError("<html><body>Welcome back</body></html>")).toBeUndefined();
  });

  test("recognizes file disclosure content", () => {
    expect(detectTraversal("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")?.id).toBe("passwd");
    expect(detectTraversal("[fonts]\r\n; for 16-bit app support")?.id).toBe("winini");
    expect(detectTraversal("<html>not a file</html>")).toBeUndefined();
  });

  test("recognizes cloud metadata responses", () => {
    expect(detectSsrf('{"Code":"Success","AccessKeyId":"ASIAEXAMPLE"}')?.id).toBe("aws-role");
    expect(detectSsrf("ami-id\ninstance-id\nplacement/availability-zone")?.id).toBe("aws-meta");
    expect(detectSsrf("ordinary page")).toBeUndefined();
  });

  test("parses password forms, fields and the effective action", () => {
    const html = `
      <form action="/session" method="POST">
        <input name="email" type="email" />
        <input name="password" type="password" />
        <input type="hidden" name="csrf" value="token-1" />
        <input type="submit" value="Sign in" />
      </form>
      <form action="/newsletter"><input name="email" /></form>`;
    const forms = parseForms(html, "https://example.com/login");
    expect(forms).toHaveLength(1);
    expect(forms[0]).toEqual({
      action: "https://example.com/session",
      method: "post",
      hasPassword: true,
      fields: { email: "", password: "", csrf: "token-1" },
    });
  });

  test("extracts same-page script sources and ignores inline data", () => {
    const html = `
      <script src="/static/app.js"></script>
      <script src="https://cdn.example.com/vendor.js" defer></script>
      <script src="data:text/javascript;base64,AAAA"></script>
      <script>inline()</script>`;
    expect(extractScriptSources(html, "https://example.com/login")).toEqual([
      "https://example.com/static/app.js",
      "https://cdn.example.com/vendor.js",
    ]);
  });
});
