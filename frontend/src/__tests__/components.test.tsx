import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { SeverityDonut } from "../components/charts";
import { FindingsTable } from "../components/FindingsTable";
import type { Finding, Scan } from "../lib/api";
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
  it("filters by severity and classification and expands evidence", () => {
    render(<FindingsTable findings={findings} />);
    expect(screen.getByText("3 / 3")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /critical 1/i }));
    expect(screen.getByText("1 / 3")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /critical 1/i }));
    fireEvent.click(screen.getByRole("button", { name: /suspicious 1/i }));
    expect(screen.getByText("Cleartext URL")).toBeInTheDocument();
    expect(screen.queryByText("Empty root password")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /suspicious 1/i }));
    fireEvent.click(screen.getByText("Empty root password"));
    expect(screen.getByText("fix it")).toBeInTheDocument();
    expect(screen.getByText("root::")).toBeInTheDocument();
    expect(screen.getByText(/✓ fwanalyzer/)).toBeInTheDocument();
  });

  it("searches", () => {
    render(<FindingsTable findings={findings} />);
    fireEvent.change(screen.getByPlaceholderText(/Search/), { target: { value: "busybox" } });
    expect(screen.getByText("1 / 3")).toBeInTheDocument();
  });

  it("explains an empty result honestly", () => {
    render(<FindingsTable findings={[]} />);
    expect(screen.getByText(/does not mean the firmware is free of vulnerabilities/)).toBeInTheDocument();
  });
});

describe("charts", () => {
  it("renders donut totals", () => {
    render(<SeverityDonut counts={{ critical: 2, high: 3 }} />);
    expect(screen.getByText("5")).toBeInTheDocument();
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
      { tool: "fact", status: "failed" },
    ],
  } as unknown as Scan;
  it("maps tool runs to step states", () => {
    const s = Object.fromEntries(pipelineSteps(scan).map((x) => [x.key, x.state]));
    expect(s).toMatchObject({ sandbox: "done", fwanalyzer: "skipped", cwe_checker: "unavailable", fact: "failed", report: "done" });
  });
  it("marks the active tool while running", () => {
    const running = { ...scan, status: "running", stage: "tool:cwe_checker", tool_runs: [{ tool: "builtin:secrets", status: "completed" }] } as unknown as Scan;
    const s = Object.fromEntries(pipelineSteps(running).map((x) => [x.key, x.state]));
    expect(s.cwe_checker).toBe("active");
    expect(s.report).toBe("pending");
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
