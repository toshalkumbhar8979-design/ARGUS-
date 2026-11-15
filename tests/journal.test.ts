import { describe, expect, test } from "bun:test";
import { AttackJournal, journalTarget } from "../src/core/journal";

describe("attack journal", () => {
  test("picks the attacked surface from tool arguments", () => {
    expect(journalTarget({ target: "https://app.example.test" })).toBe("https://app.example.test");
    expect(journalTarget({ command: "nmap -sV 10.0.0.5" })).toBe("nmap -sV 10.0.0.5");
    expect(journalTarget({ nothing: true })).toBeUndefined();
  });

  test("aggregates tools and surfaces and renders a report section", () => {
    const journal = new AttackJournal();
    journal.record({ tool: "scan_target", target: "https://app.example.test", ok: true });
    journal.record({ tool: "http_request", target: "https://app.example.test/api/users/2", ok: true });
    journal.record({ tool: "http_request", target: "https://app.example.test/api/users/2", ok: false, detail: "403" });
    journal.record({ tool: "wsl", target: "nmap -sV app.example.test", ok: true });

    expect(journal.size).toBe(4);
    expect(journal.toolsUsed()).toEqual([
      { tool: "http_request", count: 2 },
      { tool: "scan_target", count: 1 },
      { tool: "wsl", count: 1 },
    ]);
    expect(journal.attacked()).toContain("https://app.example.test/api/users/2");

    const markdown = journal.toMarkdown();
    expect(markdown).toContain("## Attack journal");
    expect(markdown).toContain("`http_request` x2");
    expect(markdown).toContain("### Surfaces and packages touched");
    expect(markdown).toContain("| time | tool | target / action | result |");
    expect(markdown).toContain("failed");
  });

  test("an empty journal adds nothing to a report", () => {
    expect(new AttackJournal().toMarkdown()).toBe("");
  });
});
