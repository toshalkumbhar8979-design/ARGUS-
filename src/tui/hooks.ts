import { useEffect, useState } from "react";
import { loadScopeFile } from "../core/config";
import { validateScope } from "../core/scope";
import type { ScopePolicy, ScopeValidation } from "../core/types";

export interface ScopePreview {
  path: string;
  scope?: ScopePolicy;
  validation?: ScopeValidation;
  error?: string;
  loading: boolean;
}

/** Loads and validates the authorization file behind the given path. */
export function useScopePreview(path: string, revision = 0): ScopePreview {
  const [preview, setPreview] = useState<ScopePreview>({ path, loading: Boolean(path.trim()) });

  useEffect(() => {
    let cancelled = false;
    const trimmed = path.trim();
    if (!trimmed) {
      setPreview({ path, loading: false, error: "No scope yet. Name a target in the prompt." });
      return () => {
        cancelled = true;
      };
    }
    setPreview((previous) => ({ ...previous, path, loading: true, error: undefined }));
    loadScopeFile(trimmed)
      .then((scope) => {
        if (cancelled) return;
        setPreview({ path, scope, validation: validateScope(scope), loading: false });
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setPreview({
          path,
          loading: false,
          error: error instanceof Error ? error.message : String(error),
        });
      });
    return () => {
      cancelled = true;
    };
  }, [path, revision]);

  return preview;
}

/** Re-renders on an interval while active so elapsed clocks tick. */
export function useNow(active: boolean, intervalMs = 500): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [active, intervalMs]);
  return now;
}
