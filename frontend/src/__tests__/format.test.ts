import { buildLine, externalUrl, formatBytes, formatDuration, imageSummary, inventoryCount, riskLabel, shortHash, shown, toolStatusTone } from "../lib/format";

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

describe("finding references", () => {
  it("links only absolute http(s) URLs", () => {
    expect(externalUrl("https://nvd.nist.gov/vuln/detail/CVE-2021-3711")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2021-3711");
    expect(externalUrl("HTTP://example.org")).toBe("http://example.org/");
    expect(externalUrl("javascript:alert(1)")).toBeNull();
    expect(externalUrl("httpx:alert(1)")).toBeNull();
    expect(externalUrl("http:javascript:alert(1)")).toBeNull();
    expect(externalUrl("data:text/html,<script>alert(1)</script>")).toBeNull();
    expect(externalUrl("//evil.example/x")).toBeNull();
    expect(externalUrl("http-proxy/../../api/scans")).toBeNull();
    expect(externalUrl("CVE-2021-3711")).toBeNull();
    expect(externalUrl("https://")).toBeNull();
  });
});

describe("artifact placement", () => {
  it("says where carved and trailing content came from", () => {
    expect(imageSummary({ carved_offset: "0x1840000" })).toBe("found at 0x1840000");
    expect(imageSummary({ prepended_bytes: 1032 })).toBe("1,032 bytes before the archive (e.g. a vendor header)");
    expect(imageSummary({ trailing_padding_bytes: 4096 })).toBe("4,096 bytes of padding after the data");
    expect(imageSummary({ trailing_bytes: 4 })).toBe("4 bytes after the data (size field or checksum)");
    expect(imageSummary({ carved_offset: "0x10000", flash_base: "0x8000000" })).toBe("found at 0x10000 · load address 0x8000000");
    expect(imageSummary({})).toBeNull();
  });
});

describe("firmware-derived text", () => {
  it("shows characters that would act instead of applying them", () => {
    expect(shown("evil\u202etxt.exe")).toBe("evil\\u202etxt.exe");
    expect(shown("new\nline\ttab\u0000nul")).toBe("new\\u000aline\\u0009tab\\u0000nul");
    expect(shown("zero\u200bwidth\ufeff")).toBe("zero\\u200bwidth\\ufeff");
    expect(shown("/etc/été/中文/user\\x80dir")).toBe("/etc/été/中文/user\\x80dir");  // letters and \xNN text stay
    expect(shown(null)).toBe("");
    expect(shown("busy\u00adbox")).toBe("busy\\u00adbox"); // soft hyphen: renders as "busybox"
    expect(shown("a\u2028b\u3164c\ufe0fd")).toBe("a\\u2028b\\u3164c\\ufe0fd");
    expect(shown("tag\u{e0041}x")).toBe("tag\\u{e0041}x"); // tag characters lie beyond U+FFFF
    expect(shown("emoji 😀 stays")).toBe("emoji 😀 stays");
  });
});
