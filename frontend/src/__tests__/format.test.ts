import { formatBytes, formatDuration, riskLabel, shortHash, toolStatusTone } from "../lib/format";

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
