import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (relative: string) =>
  readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");

describe("Windows bundled Xray core", () => {
  it("stays visible as the active immutable service core", () => {
    const core = read("../../src-tauri/src/core.rs");
    const runtime = read("../../scripts/prepare-windows-runtime.sh");
    const settings = read("../routes/settings/+page.svelte");

    expect(core).toContain('BUNDLED_XRAY_VERSION: &str = "26.3.27"');
    expect(runtime).toContain('XRAY_VERSION="26.3.27"');
    expect(runtime).toContain("d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad");
    expect(runtime).toContain("35d4ed6ec21224fb22b07c2c3f672e2350cd536f2c74d309150175a76365ea88");
    expect(core).toContain("bundled: true");
    expect(core).toContain("installed: vec![InstalledVersion");
    expect(settings).toContain('t("core.bundled")');
    expect(settings).toContain("{#if !v.bundled}");
  });
});
