import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (relative: string) =>
  readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");

describe("Proxy per-app split UI", () => {
  it("keeps Apps discoverable but unavailable with an accessible notice", () => {
    const page = read("../routes/split/+page.svelte");
    const i18n = read("./i18n.svelte.ts");

    expect(page).toContain("appSplitAvailable(settings.vpnMode)");
    expect(page).toContain("aria-disabled={!appsAvailable}");
    expect(page).toContain("onmouseenter={requestAppsTab}");
    expect(page).toContain("onfocus={requestAppsTab}");
    expect(page).toContain("onclick={requestAppsTab}");
    expect(page).toContain('role="status"');
    expect(page).toContain('aria-live="polite"');
    expect(page).toContain('t("split.appsProxyUnavailable")');
    expect(i18n.match(/"split\.appsProxyUnavailable":/g)).toHaveLength(2);
  });
});
