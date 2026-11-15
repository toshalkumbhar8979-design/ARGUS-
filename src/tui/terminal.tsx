/**
 * Embedded interactive terminal: a real PTY (Bun.Terminal) rendered into the
 * TUI by OpenTUI's EmbeddedTerminalRenderable. Vim, less, msfconsole or a plain
 * shell run with full keyboard and colour support; exiting the program returns
 * to Argus.
 */
import { EmbeddedTerminalRenderable } from "@opentui/core";
import { extend, useTerminalDimensions } from "@opentui/react";
import { useEffect, useRef } from "react";
import type { TerminalSpec } from "./terminal-spec";

declare module "@opentui/react" {
  interface OpenTUIComponents {
    argusTerminal: typeof EmbeddedTerminalRenderable;
  }
}

extend({ argusTerminal: EmbeddedTerminalRenderable });

export interface TerminalPanelProps {
  spec: TerminalSpec;
  onExit: (code: number) => void;
}

export function TerminalPanel({ spec, onExit }: TerminalPanelProps) {
  const ref = useRef<EmbeddedTerminalRenderable | null>(null);
  const { width, height } = useTerminalDimensions();
  const exitRef = useRef(onExit);
  exitRef.current = onExit;
  const sizeRef = useRef({ cols: Math.max(40, width - 4), rows: Math.max(10, height - 8) });
  sizeRef.current = { cols: Math.max(40, width - 4), rows: Math.max(10, height - 8) };

  useEffect(() => {
    const terminal = ref.current;
    if (!terminal) return;
    terminal.focus();
    let disposed = false;
    let pty: Bun.Terminal;
    try {
      pty = new Bun.Terminal({
        cols: sizeRef.current.cols,
        rows: sizeRef.current.rows,
        data(_term, data) {
          if (!disposed) terminal.write(data);
        },
      });
    } catch {
      exitRef.current(1);
      return;
    }

    terminal.onData = (data) => {
      try {
        pty.write(data);
      } catch {
        // the child may have exited between a key and its write
      }
    };
    terminal.onTerminalResize = (cols, rows) => {
      try {
        pty.resize(cols, rows);
      } catch {
        // resize after exit is harmless
      }
    };

    let proc: Bun.Subprocess<"ignore", "ignore", "ignore">;
    try {
      proc = Bun.spawn(spec.argv, {
        cwd: spec.cwd,
        terminal: pty,
        env: { ...process.env, TERM: "xterm-256color", COLORTERM: "truecolor" },
      });
    } catch {
      pty.close();
      exitRef.current(1);
      return;
    }

    void proc.exited.then((code) => {
      if (disposed) return;
      disposed = true;
      try {
        pty.close();
      } catch {
        // already closed
      }
      exitRef.current(code ?? 0);
    });

    return () => {
      disposed = true;
      try {
        pty.close();
      } catch {
        // already closed
      }
    };
    // Size changes are forwarded by onTerminalResize; a new spec starts a new PTY.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [spec]);

  return <argusTerminal ref={ref} flexGrow={1} />;
}
