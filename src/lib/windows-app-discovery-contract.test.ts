import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (relative: string) =>
  readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");

describe("Windows split-tunnel application discovery", () => {
  it("covers both registry views and installed-program entries", () => {
    const apps = read("../../src-tauri/src/apps.rs");

    expect(apps).toContain("KEY_WOW64_64KEY");
    expect(apps).toContain("KEY_WOW64_32KEY");
    expect(apps).toContain("CurrentVersion\\App Paths");
    expect(apps).toContain("CurrentVersion\\Uninstall");
    expect(apps).toContain('get_value::<String, _>("DisplayIcon")');
    expect(apps).toContain('get_value::<String, _>("InstallLocation")');
  });

  it("extracts real executable icons and presents compact readable paths", () => {
    const apps = read("../../src-tauri/src/apps.rs");
    const split = read("../routes/split/+page.svelte");

    expect(apps).toContain("get_icon_base64_by_path_with_size");
    expect(apps).toContain('format!("data:image/png;base64,{encoded}")');
    expect(split).toContain("function appPathLabel");
    expect(split).toContain("title={app.id}");
    expect(split).toMatch(/\.app-id\s*\{[^}]*text-overflow:\s*ellipsis;/s);
  });
});
