import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { CveTable } from "../components/CveTable";
import { FindingsTable } from "../components/FindingsTable";
import type { CveEntry, CveLookupDetails, Finding, Scan, ToolRun } from "../lib/api";
import { findingsSummary } from "../lib/format";
import { pipelineSteps } from "../pages/ScanDetail";

const base: Omit<Finding, "id" | "severity" | "classification" | "title" | "source_tool"> = {
  fingerprint: "x",
  description: "desc",
  confidence: "high",
  rule_id: "r",
  affected_component: "fw > /etc/shadow",
  remediation: "fix it",
  evidence: [{ kind: "config", value: "root::", location: "/etc/shadow" }],
  cwe: "CWE-258",
  references: [],
  tags: ["corroborated-by:fwanalyzer"],
};

const findings: Finding[] = [
  { ...base, id: 1, severity: "critical", classification: "detected", title: "Empty root password", source_tool: "builtin:secrets" },
  { ...base, id: 2, severity: "low", classification: "suspicious", title: "Cleartext URL", source_tool: "builtin:binary", tags: [] },
  { ...base, id: 3, severity: "medium", classification: "unverified", title: "Old BusyBox", source_tool: "builtin:components", tags: [] },
];

describe("FindingsTable", () => {
  it("filters by severity and evidence class and expands evidence", () => {
    render(<FindingsTable findings={findings} />);
    expect(screen.getByText("3 of 3")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "critical" } });
    expect(screen.getByText("1 of 3")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Evidence"), { target: { value: "suspicious" } });
    expect(screen.getByText("Cleartext URL")).toBeInTheDocument();
    expect(screen.queryByText("Empty root password")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Evidence"), { target: { value: "" } });
    fireEvent.click(screen.getByText("Empty root password"));
    expect(screen.getByText("fix it")).toBeInTheDocument();
    expect(screen.getByText("root::")).toBeInTheDocument();
    expect(screen.getByText("Also reported by fwanalyzer")).toBeInTheDocument();
  });

  it("lists severity options with their counts", () => {
    render(<FindingsTable findings={findings} />);
    expect(screen.getByRole("option", { name: "Critical (1)" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Suspicious (1)" })).toBeInTheDocument();
  });

  it("searches", () => {
    render(<FindingsTable findings={findings} />);
    fireEvent.change(screen.getByPlaceholderText(/Search/), { target: { value: "busybox" } });
    expect(screen.getByText("1 of 3")).toBeInTheDocument();
  });

  it("explains an empty result honestly", () => {
    render(<FindingsTable findings={[]} />);
    expect(screen.getByText(/does not mean the firmware is free of vulnerabilities/)).toBeInTheDocument();
  });
});

describe("findingsSummary", () => {
  it("lists non-zero severities in order", () => {
    expect(findingsSummary({ critical: 3, high: 6, medium: 10, low: 4, info: 0 })).toBe("23 findings: 3 critical, 6 high, 10 medium, 4 low");
  });
  it("uses the singular for one finding", () => {
    expect(findingsSummary({ low: 1 })).toBe("1 finding: 1 low");
  });
  it("says so when there are none", () => {
    expect(findingsSummary({})).toBe("No findings");
    expect(findingsSummary(null)).toBe("No findings");
  });
});

describe("pipelineSteps", () => {
  const scan = {
    status: "completed",
    stage: "complete",
    tool_runs: [
      { tool: "builtin:secrets", status: "completed" },
      { tool: "fwanalyzer", status: "skipped" },
      { tool: "cwe_checker", status: "unavailable" },
    ],
  } as unknown as Scan;
  it("maps tool runs to step states", () => {
    const s = Object.fromEntries(pipelineSteps(scan).map((x) => [x.key, x.state]));
    expect(s).toMatchObject({ sandbox: "done", fwanalyzer: "skipped", cwe_checker: "unavailable", report: "done" });
    expect(s).not.toHaveProperty("fact");
    const failedRun = { ...scan, tool_runs: [{ tool: "cwe_checker", status: "failed" }] } as unknown as Scan;
    const f = Object.fromEntries(pipelineSteps(failedRun).map((x) => [x.key, x.state]));
    expect(f.cwe_checker).toBe("failed");
  });
  it("marks the active tool while running", () => {
    const running = { ...scan, status: "running", stage: "tool:cwe_checker", tool_runs: [{ tool: "builtin:secrets", status: "completed" }] } as unknown as Scan;
    const s = Object.fromEntries(pipelineSteps(running).map((x) => [x.key, x.state]));
    expect(s.cwe_checker).toBe("active");
    expect(s.report).toBe("pending");
  });
  it("runs the CVE lookup first among the tools", () => {
    const withCve = { ...scan, tool_runs: [...(scan.tool_runs ?? []), { tool: "cve_lookup", status: "completed" }] } as unknown as Scan;
    const steps = pipelineSteps(withCve);
    expect(steps.map((x) => x.key)).toEqual(["upload", "sandbox", "cve_lookup", "fwanalyzer", "cwe_checker", "report"]);
    expect(steps.find((x) => x.key === "cve_lookup")).toMatchObject({ label: "CVE lookup", state: "done" });
    const active = { ...scan, status: "running", stage: "tool:cve_lookup", tool_runs: [] } as unknown as Scan;
    expect(pipelineSteps(active).find((x) => x.key === "cve_lookup")?.state).toBe("active");
  });
});

const cveBase: CveEntry = {
  id: "CVE-2014-0160",
  score: 7.5,
  severity: "high",
  cvss_version: "3.1",
  kev: true,
  ransomware: false,
  exploits: ["32745"],
  summary: "Heartbleed: the TLS heartbeat extension leaks memory.",
  published: "2014-04-07",
  match: "nvd",
};

function cveRun(details: Partial<CveLookupDetails> | Record<string, unknown>, status = "completed", message: string | null = null): ToolRun {
  return {
    tool: "cve_lookup",
    display_name: "CVE lookup",
    status,
    message,
    started_at: null,
    finished_at: null,
    duration_s: 1.2,
    findings_count: 0,
    details: details as Record<string, unknown>,
  };
}

const cveDb = { built_at: "2026-11-01T10:00:00Z", nvd_timestamp: "2026-11-01T08:00:00Z", cve_count: 420009, age_days: 5, stale: false };
const cveTotals = { components: 3, cves: 2, critical: 0, high: 1, medium: 1, low: 0, known_exploited: 1, public_exploit: 1 };
const cveDetailsFixture: CveLookupDetails = {
  db: cveDb,
  totals: cveTotals,
  components: [
    {
      name: "openssl",
      version: "1.0.1e",
      method: "string-match",
      mapped: true,
      cpe: ["openssl:openssl"],
      cves: [
        cveBase,
        { ...cveBase, id: "CVE-2099-0001", score: null, cvss_version: null, severity: "medium", kev: false, exploits: [], match: "cna", summary: "Unscored." },
      ],
    },
    { name: "busybox", version: "1.36.1", method: "string-match", mapped: true, cpe: ["busybox:busybox"], cves: [] },
    { name: "uboot", version: "2019.07", method: "string-match", mapped: false, cpe: [], cves: [] },
  ],
};

describe("CveTable", () => {
  it("renders totals, badges and what was checked", () => {
    render(<CveTable run={cveRun(cveDetailsFixture)} running={false} />);
    expect(screen.getByText(/2 known CVEs in 1 component:/)).toHaveTextContent("2 known CVEs in 1 component: 1 high, 1 medium");
    expect(screen.getByText("1 actively exploited")).toHaveClass("tone-bad");
    expect(screen.getByText("1 with a public exploit")).toBeInTheDocument();
    expect(screen.getByText(/^CVE database built .* \(420.?009 CVEs\)\.$/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /openssl 1\.0\.1e — 2 CVEs/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "CVE-2014-0160" })).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2014-0160");
    expect(screen.getByText("Exploited")).toHaveClass("badge-exploited");
    expect(screen.getByText("Exploit")).toHaveClass("badge-exploit");
    expect(screen.queryByText("Ransomware")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "EDB-32745" })).toHaveAttribute("href", "https://www.exploit-db.com/exploits/32745");
    expect(screen.getByText("no CVSS score")).toBeInTheDocument();
    expect(screen.getByText("vendor data")).toBeInTheDocument();
    expect(screen.getByText(/No known CVEs: busybox 1\.36\.1\./)).toHaveTextContent("No CVE mapping, so not checked: uboot 2019.07.");
    expect(screen.getByText(/not verified/)).toBeInTheDocument();
    expect(screen.queryByText(/database is .* old/)).not.toBeInTheDocument();
  });

  it("collapses a large group and expands it on request", () => {
    const cves = Array.from({ length: 30 }, (_, i) => ({ ...cveBase, id: `CVE-2020-${String(i).padStart(4, "0")}`, kev: false, exploits: [] }));
    const details = { ...cveDetailsFixture, totals: { ...cveTotals, cves: 30 }, components: [{ ...cveDetailsFixture.components[0], cves }] };
    render(<CveTable run={cveRun(details)} running={false} />);
    expect(screen.getAllByRole("link", { name: /^CVE-2020-/ })).toHaveLength(25);
    fireEvent.click(screen.getByRole("button", { name: "Show all 30" }));
    expect(screen.getAllByRole("link", { name: /^CVE-2020-/ })).toHaveLength(30);
    expect(screen.getByRole("button", { name: "Show first 25" })).toBeInTheDocument();
  });

  it("warns about a stale database and says plainly when nothing matched", () => {
    const details = { db: { ...cveDb, stale: true, age_days: 45 }, totals: { ...cveTotals, components: 2, cves: 0, high: 0, medium: 0, known_exploited: 0, public_exploit: 0 }, components: cveDetailsFixture.components.slice(1) };
    render(<CveTable run={cveRun(details)} running={false} />);
    expect(screen.getByText("No known CVEs matched the 2 identified components.")).toBeInTheDocument();
    expect(screen.getByText(/The CVE database is 45 days old/)).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows why the lookup did not run", () => {
    const { container } = render(<CveTable run={cveRun({}, "unavailable", "CVE database not installed — run `make cve-db`")} running={false} />);
    expect(container.querySelector(".warn-box")).toHaveTextContent("CVE lookup unavailable: CVE database not installed — run make cve-db");
    expect(screen.getByText("make cve-db").tagName).toBe("CODE");
  });

  it("explains a missing run", () => {
    const { rerender } = render(<CveTable run={undefined} running />);
    expect(screen.getByText("CVE results appear when the scan completes.")).toBeInTheDocument();
    rerender(<CveTable run={undefined} running={false} />);
    expect(screen.getByText("CVE lookup did not run for this scan.")).toBeInTheDocument();
  });
});

describe("routing smoke", () => {
  it("renders inside a router", () => {
    render(
      <MemoryRouter>
        <FindingsTable findings={findings} />
      </MemoryRouter>,
    );
    expect(screen.getAllByText(/builtin:/).length).toBeGreaterThan(0);
  });
});

describe("Dropzone", () => {
  it("rejects oversize and empty files before uploading", async () => {
    const { Dropzone } = await import("../components/Dropzone");
    render(
      <MemoryRouter>
        <Dropzone maxMb={1} />
      </MemoryRouter>,
    );
    const input = screen.getByTestId("file-input") as HTMLInputElement;
    const big = new File([new Uint8Array(2 * 1024 * 1024)], "big.bin");
    const empty = new File([], "empty.bin");
    fireEvent.change(input, { target: { files: [big, empty] } });
    expect(await screen.findByRole("alert")).toHaveTextContent(/big\.bin: .*exceeds the 1 MiB limit/);
    expect(screen.getByRole("alert")).toHaveTextContent(/empty\.bin: file is empty/);
  });
});
