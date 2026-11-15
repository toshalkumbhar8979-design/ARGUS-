import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

const ENV_NAME = /^[A-Z][A-Z0-9_]*$/;

/** Keys live beside the run store, never in the project or the config file. */
export function credentialsPath(dataDir: string): string {
  if (process.env.ARGUS_CREDENTIALS) return resolve(process.env.ARGUS_CREDENTIALS);
  return join(dataDir, "credentials.json");
}

export async function loadCredentials(dataDir: string): Promise<Record<string, string>> {
  const path = credentialsPath(dataDir);
  try {
    const raw = await readFile(path, "utf8");
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const output: Record<string, string> = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (ENV_NAME.test(key) && typeof value === "string" && value.length > 0) output[key] = value;
    }
    return output;
  } catch {
    return {};
  }
}

/** Saves one provider key with owner-only permissions and applies it to this process. */
export async function saveCredential(dataDir: string, envName: string, secret: string): Promise<string> {
  if (!ENV_NAME.test(envName)) throw new Error("key name must look like OPENAI_API_KEY");
  const value = secret.trim();
  if (!value) throw new Error("the key is empty");
  const path = credentialsPath(dataDir);
  await mkdir(dirname(path), { recursive: true });
  const existing = await loadCredentials(dataDir);
  existing[envName] = value;
  await writeFile(path, `${JSON.stringify(existing, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  try {
    await chmod(path, 0o600);
  } catch {
    // best effort on platforms without chmod
  }
  process.env[envName] = value;
  return path;
}

/** Loads stored keys into the environment without overriding exported variables. */
export async function hydrateCredentials(dataDir: string): Promise<string[]> {
  const stored = await loadCredentials(dataDir);
  const loaded: string[] = [];
  for (const [key, value] of Object.entries(stored)) {
    if (!process.env[key]) {
      process.env[key] = value;
      loaded.push(key);
    }
  }
  return loaded;
}
