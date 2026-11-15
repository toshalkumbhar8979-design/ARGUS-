import { afterAll, describe, expect, test } from "bun:test";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { HttpClient, readPeerTls } from "../src/core/http";
import { ScopeGuard } from "../src/core/scope";
import type { ScopePolicy } from "../src/core/types";

/**
 * Test-only self-signed certificate for 127.0.0.1. It exists so the suite can
 * exercise the real TLS handshake path; it is not a secret and never leaves the
 * test process.
 */
const TEST_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYGvo04JxYlK+s2MZ
zfYOLKWfefh2nrc9bavUJgl6p1ChRANCAAQlUgtzpDnA67Kik70/odaJHTYXlNj2
++lrk918lhj0XboklTmGjVuJuPb6ZCa11bPgEim+XPGcuw9CFAIplbEZ
-----END PRIVATE KEY-----
`;

const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIBxDCCAWmgAwIBAgIUXijlvoTSQtrrdBKS3aCVLJVkFF0wCgYIKoZIzj0EAwIw
KTESMBAGA1UEAwwJMTI3LjAuMC4xMRMwEQYDVQQKDApBcmd1cyBUZXN0MB4XDTI2
MTAyNzEzNDExOVoXDTM2MTAyNDEzNDExOVowKTESMBAGA1UEAwwJMTI3LjAuMC4x
MRMwEQYDVQQKDApBcmd1cyBUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
JVILc6Q5wOuyopO9P6HWiR02F5TY9vvpa5PdfJYY9F26JJU5ho1bibj2+mQmtdWz
4BIpvlzxnLsPQhQCKZWxGaNvMG0wHQYDVR0OBBYEFPuuAnuwiKY7jAuGuYHKBTnR
sl5yMB8GA1UdIwQYMBaAFPuuAnuwiKY7jAuGuYHKBTnRsl5yMA8GA1UdEwEB/wQF
MAMBAf8wGgYDVR0RBBMwEYcEfwAAAYIJbG9jYWxob3N0MAoGCCqGSM49BAMCA0kA
MEYCIQC5rRlF9nipPqWdUv1savc2Da2DU+fv7RNtLlWz/+UxjAIhAPXroSyTUEsm
pZxyr23VuxEcRFc4uOgptps9u60NB3Vz
-----END CERTIFICATE-----
`;

let server: Server | undefined;
let baseUrl = "";

const scope: ScopePolicy = {
  version: 1,
  name: "TLS test",
  authorizedBy: "Security Team",
  authorizationRef: "TICKET-TLS-1",
  expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
  allow: ["https://127.0.0.1"],
  allowActive: true,
  allowIntrusive: false,
};

afterAll(async () => {
  if (!server) return;
  await new Promise<void>((resolve, reject) => server!.close((error) => (error ? reject(error) : resolve())));
});

async function tlsTarget(handler: "ok" | "abrupt"): Promise<string> {
  if (!server) {
    server = createServer({ key: TEST_KEY, cert: TEST_CERT }, (request, response) => {
      response.writeHead(200, { "content-type": "text/plain", connection: "close" });
      response.end("tls-ok");
      if (new URL(request.url ?? "/", "https://127.0.0.1").pathname === "/abrupt") {
        // Close the socket the moment the body is flushed: this is the shape that
        // used to leave the response handler holding a released socket.
        response.socket?.end();
      }
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const address = server.address() as AddressInfo;
    baseUrl = `https://127.0.0.1:${address.port}`;
  }
  return `${baseUrl}/${handler}`;
}

describe("TLS peer certificate handling", () => {
  test("returns no peer details for a socket that is already gone", () => {
    expect(readPeerTls(null, "127.0.0.1")).toBeUndefined();
    expect(readPeerTls(undefined, "127.0.0.1")).toBeUndefined();
    expect(readPeerTls({}, "127.0.0.1")).toBeUndefined();
    expect(readPeerTls({ getPeerCertificate: () => null }, "127.0.0.1")).toBeUndefined();
  });

  test("reports the handshake for a live HTTPS response", async () => {
    const client = new HttpClient(new ScopeGuard(scope), { timeoutMs: 5_000, maxRps: 20, userAgent: "Argus test" });
    try {
      const response = await client.get(await tlsTarget("ok"));
      expect(response.status).toBe(200);
      expect(response.body).toBe("tls-ok");
      if (!response.tls) {
        // Bun 1.3 exposes no peer certificate even on a direct TLS socket. Only
        // accept the missing details when the runtime itself cannot provide them.
        const port = Number(new URL(baseUrl).port);
        const supported = await new Promise<boolean>((resolve) => {
          const socket = tlsConnect(
            { host: "127.0.0.1", port, rejectUnauthorized: false },
            () => {
              const cert = socket.getPeerCertificate(false);
              socket.destroy();
              resolve(Boolean(cert && cert.subject));
            },
          );
          socket.on("error", () => resolve(false));
        });
        expect(supported).toBe(false);
        return;
      }
      expect(response.tls).toBeDefined();
      expect(response.tls?.selfSigned).toBe(true);
      expect(response.tls?.hostnameMatch).toBe(true);
      expect(response.tls?.subject).toContain("CN=127.0.0.1");
    } finally {
      client.close();
    }
  });

  test("serves a response whose socket closes immediately after the body", async () => {
    const client = new HttpClient(new ScopeGuard(scope), { timeoutMs: 5_000, maxRps: 20, userAgent: "Argus test" });
    try {
      const response = await client.get(await tlsTarget("abrupt"));
      expect(response.status).toBe(200);
      expect(response.body).toBe("tls-ok");
    } finally {
      client.close();
    }
  });
});
