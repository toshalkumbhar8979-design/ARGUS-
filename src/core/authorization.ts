/**
 * Authorized-use agreement.
 *
 * This is a gate, not a legal document: it records that the operator has read
 * and accepted the rules Argus already enforces, once, so a later "attack this"
 * runs autonomously instead of re-asking. Acceptance does not grant access to
 * any host - the prompt scope and deny list still decide that.
 */
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

export const TERMS_VERSION = 1;

export interface ConsentRecord {
  version: number;
  acceptedAt: string;
  acceptedBy?: string;
  basis: "written-authorization";
}

export function consentPath(dataDir: string): string {
  return resolve(dataDir, "authorization.json");
}

export function termsLines(): string[] {
  return [
    "AUTHORIZED USE AGREEMENT",
    "",
    "Argus is an offensive security tool. By accepting, you confirm all of the following:",
    "1. You have written permission to test every target you name, and you can produce it on request.",
    "2. Targets are limited to what you name in a prompt or scope file. Nothing else is in bounds.",
    "3. You will not use it against third parties, cloud metadata endpoints, shared infrastructure",
    "   you do not own, or any system outside that authorization.",
    "4. You will not run destructive, persistence, denial-of-service or data-exfiltration actions.",
    "5. You own the consequences of the commands the agent runs, including installed packages,",
    "   Docker containers, proxy traffic and any requests it sends.",
    "6. Findings and evidence may contain sensitive data; you will store and share them lawfully.",
    "7. Acceptance is recorded locally in the Argus data directory with a timestamp.",
    "",
    "This is not legal advice. If any of the above is not true, do not accept and do not scan.",
  ];
}

export function termsText(): string {
  return termsLines().join("\n");
}

export async function readConsent(dataDir: string): Promise<ConsentRecord | undefined> {
  try {
    const raw = await readFile(consentPath(dataDir), "utf8");
    const parsed = JSON.parse(raw) as Partial<ConsentRecord>;
    if (parsed.version !== TERMS_VERSION || !parsed.acceptedAt) return undefined;
    return {
      version: TERMS_VERSION,
      acceptedAt: parsed.acceptedAt,
      ...(parsed.acceptedBy ? { acceptedBy: parsed.acceptedBy } : {}),
      basis: "written-authorization",
    };
  } catch {
    return undefined;
  }
}

export async function acceptTerms(dataDir: string, acceptedBy?: string): Promise<ConsentRecord> {
  const record: ConsentRecord = {
    version: TERMS_VERSION,
    acceptedAt: new Date().toISOString(),
    ...(acceptedBy?.trim() ? { acceptedBy: acceptedBy.trim().slice(0, 120) } : {}),
    basis: "written-authorization",
  };
  const path = consentPath(dataDir);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(record, null, 2)}\n`);
  return record;
}

export async function revokeConsent(dataDir: string): Promise<void> {
  await rm(consentPath(dataDir), { force: true });
}

export async function isAuthorizedOperator(dataDir: string): Promise<boolean> {
  return Boolean(await readConsent(dataDir));
}
