import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (relative: string) =>
  readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");

describe("Windows bundled Xray core", () => {
  it("stays visible as the active immutable service core", () => {
    const core = read("../../src-tauri/src/core.rs");
    const settings = read("../routes/settings/+page.svelte");

    expect(core).toContain("bundled: true");
    expect(core).toContain("installed: vec![InstalledVersion");
    expect(settings).toContain('t("core.bundled")');
    expect(settings).toContain("{#if !v.bundled}");
  });
});
