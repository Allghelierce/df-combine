import { buildLine, formatBytes, formatDuration, imageSummary, inventoryCount, riskLabel, shortHash, toolStatusTone } from "../lib/format";

describe("format helpers", () => {
  it("formats bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1536)).toBe("1.50 KiB");
    expect(formatBytes(9 * 1024 * 1024)).toBe("9.00 MiB");
    expect(formatBytes(null)).toBe("-");
  });
  it("labels risk", () => {
    expect(riskLabel(98).label).toBe("Critical");
    expect(riskLabel(30).tone).toBe("medium");
    expect(riskLabel(0).label).toBe("Minimal");
    expect(riskLabel(null).label).toBe("n/a");
  });
  it("maps tool status tones", () => {
    expect(toolStatusTone("completed")).toBe("ok");
    expect(toolStatusTone("unavailable")).toBe("warn");
    expect(toolStatusTone("timeout")).toBe("bad");
  });
  it("shortens hashes and durations", () => {
    expect(shortHash("abcdef0123456789", 6)).toBe("abcdef…");
    expect(formatDuration("2026-01-01T00:00:00Z", "2026-01-01T00:01:05Z")).toBe("1m 5s");
  });
});

describe("build and image facts", () => {
  it("summarises a build-information block", () => {
    // as extracted from the official INAV 7.1.2 Matek F405 build
    expect(buildLine({ version: "7.1.2", board: "MATEKF405", revision: "4e1e59eb", date: "May 31 2024", time: "23:40:27" }))
      .toBe("git 4e1e59eb · May 31 2024 · 23:40:27");
    expect(buildLine(null)).toBeNull();
    expect(buildLine({})).toBeNull();
  });
  it("summarises raw MCU images and where their symbols come from", () => {
    expect(imageSummary({ flash_base: "0x8004000", symbol_count: 6934, symbols_from: "b.tar > /px4_fmu-v2_default.elf", identical_to: 3 }))
      .toBe("load address 0x8004000 · 6,934 function symbols from b.tar > /px4_fmu-v2_default.elf · identical to artifact #3");
    expect(imageSummary({ flash_base: "0x8004000", symbol_count: 6934, derived_from_elf: true }))
      .toBe("load address 0x8004000 · 6,934 function symbols (derived from the ELF)");
    expect(imageSummary({ flash_base: "0x8000000" })).toBe("load address 0x8000000");
    expect(imageSummary({})).toBeNull();
  });
});

describe("inventory counter", () => {
  it("says when rows are cut off", () => {
    expect(inventoryCount(95, 95, 95)).toBe("95 matching · 95 artifacts");
    // Debian 11 rootfs: 3,000+ artifacts, more than the rendered rows
    expect(inventoryCount(3033, 3033, 3033)).toBe("showing 1,500 of 3,033 matching · 3,033 artifacts — filter to narrow");
    expect(inventoryCount(12, 5000, 20000)).toBe("12 matching · 20,000 artifacts (first 5,000 loaded)");
  });
});
