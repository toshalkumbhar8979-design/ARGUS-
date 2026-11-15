/**
 * Local vector memory, in the spirit of PentAGI's flow memory and Strix's notes,
 * without an embedding provider or a database.
 *
 * Text is tokenised, hashed into fixed buckets and weighted with TF-IDF; search
 * is cosine similarity over the sparse vectors. It is lexical rather than
 * neural, so it is honest about being a retrieval aid: it finds related
 * techniques, endpoints and prior findings, and never invents evidence.
 *
 * Persistence is one JSONL file. Tokens are stored so document frequencies can
 * be rebuilt on load without embedding anything.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { newId } from "./util";

const BUCKETS = 512;
const STOPWORDS = new Set([
  "the", "and", "for", "with", "that", "this", "from", "into", "not", "but", "are", "was",
  "were", "has", "have", "had", "you", "your", "its", "our", "can", "will", "may", "also",
  "when", "what", "which", "how", "why", "who", "use", "used", "using", "any", "all", "via",
  "than", "then", "there", "their", "them", "they", "been", "being", "does", "did", "doing",
]);

export interface VectorEntry {
  id: string;
  text: string;
  kind: string;
  source?: string;
  at: string;
}

interface StoredEntry extends VectorEntry {
  tokens: Record<string, number>;
}

export interface VectorMatch {
  entry: VectorEntry;
  score: number;
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9_./-]+/)
    .map((token) => token.replace(/^[./-]+|[./-]+$/g, ""))
    .filter((token) => token.length >= 2 && !STOPWORDS.has(token));
}

function bucket(token: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < token.length; index += 1) {
    hash ^= token.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash % BUCKETS;
}

export class VectorMemory {
  private entries: StoredEntry[] = [];
  private documentFrequency = new Map<string, number>();
  private loaded = false;

  constructor(private readonly file: string) {}

  get path(): string {
    return this.file;
  }

  get size(): number {
    return this.entries.length;
  }

  async load(): Promise<void> {
    if (this.loaded) return;
    this.loaded = true;
    let raw: string;
    try {
      raw = await readFile(this.file, "utf8");
    } catch {
      return;
    }
    for (const line of raw.split(/\r?\n/)) {
      if (!line.trim()) continue;
      try {
        const parsed = JSON.parse(line) as StoredEntry;
        if (!parsed?.id || !parsed.text || !parsed.tokens) continue;
        this.entries.push(parsed);
        for (const token of Object.keys(parsed.tokens)) {
          this.documentFrequency.set(token, (this.documentFrequency.get(token) ?? 0) + 1);
        }
      } catch {
        // a corrupt line must not take the whole memory down
      }
    }
  }

  async add(input: { text: string; kind: string; source?: string; at?: string }): Promise<VectorEntry | undefined> {
    const text = input.text.replace(/\s+/g, " ").trim();
    if (!text) return undefined;
    await this.load();
    const seen = this.entries.some((entry) => entry.text === text && entry.kind === input.kind);
    if (seen) return undefined;
    const tokens: Record<string, number> = {};
    for (const token of tokenize(text)) tokens[token] = (tokens[token] ?? 0) + 1;
    if (Object.keys(tokens).length === 0) return undefined;
    const entry: StoredEntry = {
      id: newId("mem"),
      text: text.slice(0, 2_000),
      kind: input.kind.slice(0, 40),
      ...(input.source ? { source: input.source.slice(0, 300) } : {}),
      at: input.at ?? new Date().toISOString(),
      tokens,
    };
    this.entries.push(entry);
    for (const token of Object.keys(tokens)) {
      this.documentFrequency.set(token, (this.documentFrequency.get(token) ?? 0) + 1);
    }
    await mkdir(dirname(this.file), { recursive: true });
    await writeFile(this.file, `${JSON.stringify(entry)}\n`, { flag: "a" });
    return this.toPublic(entry);
  }

  search(query: string, limit = 5): VectorMatch[] {
    const tokens = tokenize(query);
    if (tokens.length === 0) return [];
    const total = this.entries.length;
    const queryWeights = new Map<number, number>();
    for (const token of tokens) {
      const df = this.documentFrequency.get(token) ?? 0;
      const weight = (1 + Math.log(queryWeights.get(bucket(token)) ?? 1)) * (Math.log((total + 1) / (df + 1)) + 1);
      queryWeights.set(bucket(token), (queryWeights.get(bucket(token)) ?? 0) + weight);
    }
    const scored = this.entries.map((entry) => ({
      entry: this.toPublic(entry),
      score: cosine(queryWeights, this.vectorOf(entry, total)),
    }));
    return scored
      .filter((match) => match.score > 0.01)
      .sort((a, b) => b.score - a.score)
      .slice(0, Math.max(1, Math.min(limit, 20)));
  }

  private vectorOf(entry: StoredEntry, total: number): Map<number, number> {
    const vector = new Map<number, number>();
    for (const [token, count] of Object.entries(entry.tokens)) {
      const df = this.documentFrequency.get(token) ?? 0;
      const weight = (1 + Math.log(count)) * (Math.log((total + 1) / (df + 1)) + 1);
      const key = bucket(token);
      vector.set(key, (vector.get(key) ?? 0) + weight);
    }
    return vector;
  }

  private toPublic(entry: StoredEntry): VectorEntry {
    const { tokens: _tokens, ...rest } = entry;
    return rest;
  }
}

function cosine(a: Map<number, number>, b: Map<number, number>): number {
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (const [key, value] of a) {
    normA += value * value;
    const other = b.get(key);
    if (other) dot += value * other;
  }
  for (const value of b.values()) normB += value * value;
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}
