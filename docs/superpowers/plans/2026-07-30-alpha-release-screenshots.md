# Windows Alpha Release and Screenshots Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Default fresh installations to English, document the current GUI with safe real screenshots, and publish both Windows installers as an alpha pre-release.

**Architecture:** Keep language selection as a pure persisted-preference decision so it can be tested without a browser. Capture the existing frontend at the Tauri window viewport using only display-safe AegisVPN data, then rebuild and inspect both architecture-specific NSIS packages before publishing through GitHub CLI.

**Tech Stack:** TypeScript, SvelteKit, Vitest, Tauri 2, Rust, cargo-xwin, NSIS, GitHub CLI.

## Global Constraints

- Do not connect or disconnect any VPN and do not modify host routing, DNS, or firewall state.
- Preserve a valid saved `varmlen.lang` preference.
- Use a `440 × 720` viewport for every screenshot.
- Do not expose subscription URLs, UUIDs, credentials, JSON, or logs.
- Publish `v0.1.0-alpha.1` as a GitHub pre-release with unsigned x64 and ARM64 installers.

---

### Task 1: English first-run language

**Files:**
- Create: `src/lib/language.ts`
- Create: `src/lib/language.test.ts`
- Modify: `src/lib/i18n.svelte.ts`

**Interfaces:**
- Produces: `initialLanguage(stored: string | null): "en" | "ru"`.
- Consumes: the `varmlen.lang` localStorage value.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from "vitest";
import { initialLanguage } from "./language";

describe("initialLanguage", () => {
  it("defaults a fresh profile to English", () => {
    expect(initialLanguage(null)).toBe("en");
  });

  it("preserves a valid saved language", () => {
    expect(initialLanguage("ru")).toBe("ru");
    expect(initialLanguage("en")).toBe("en");
  });
});
```

- [ ] **Step 2: Verify the red state**

Run: `npm test -- --run src/lib/language.test.ts`

Expected: FAIL because `src/lib/language.ts` does not exist.

- [ ] **Step 3: Add the pure decision and use it**

```ts
export type Language = "en" | "ru";

export function initialLanguage(stored: string | null): Language {
  return stored === "ru" || stored === "en" ? stored : "en";
}
```

`detect()` reads `localStorage.getItem(KEY)` in a browser and returns
`initialLanguage(stored)`; it no longer inspects `navigator.language`.

- [ ] **Step 4: Verify the green state**

Run: `npm test -- --run src/lib/language.test.ts`

Expected: two passing tests.

### Task 2: Safe GUI screenshots

**Files:**
- Create: `docs/screenshots/home.png`
- Create: `docs/screenshots/split.png`
- Create: `docs/screenshots/settings.png`
- Modify: `README.md`

**Interfaces:**
- Consumes: current Varmlen frontend and display-safe AegisVPN locations.
- Produces: three `440 × 720` PNG files linked from README.

- [ ] **Step 1: Start the local frontend**

Run: `npm run dev -- --host 127.0.0.1`

Expected: the Vite server reports a localhost URL; no Tauri VPN command runs.

- [ ] **Step 2: Populate only display-safe state**

Set `varmlen.lang` to `en`, set a sanitized `varmlen.subs` object containing
the current AegisVPN display name and public location labels, and reload.

- [ ] **Step 3: Capture and inspect all views**

Set the browser viewport to `440 × 720`, capture Home, Split, and Settings,
then verify their pixel dimensions and visually inspect each PNG for clipping,
credentials, URLs, UUIDs, JSON, or logs.

- [ ] **Step 4: Add the README gallery**

Add a `## Screenshots` section with the three repository-relative PNG links and
short English labels.

### Task 3: Rebuild and publish alpha

**Files:**
- Modify: tracked files from Tasks 1 and 2.
- Build: `target/x86_64-pc-windows-msvc/release/bundle/nsis/Varmlen_0.1.0_x64-setup.exe`
- Build: `target/aarch64-pc-windows-msvc/release/bundle/nsis/Varmlen_0.1.0_arm64-setup.exe`

**Interfaces:**
- Consumes: verified source tree and pinned runtime archives.
- Produces: GitHub pre-release `v0.1.0-alpha.1` with two setup assets.

- [ ] **Step 1: Run source verification**

Run:

```text
npm test -- --run
npm run check
npm run build
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: every command exits zero.

- [ ] **Step 2: Cross-check and rebuild**

Run x64 and ARM64 `cargo xwin check`, then:

```text
./scripts/build-windows.sh x64
./scripts/build-windows.sh arm64
```

Expected: both NSIS installers are produced.

- [ ] **Step 3: Inspect packages**

Extract both installers with `7z`, verify embedded GUI/service/Xray/Wintun
architectures, compare runtime payloads with their pinned source files, and
compute SHA-256 values.

- [ ] **Step 4: Commit and push**

Commit with `feat: prepare Windows alpha release`, fast-forward/push `main`,
and verify `origin/main` matches local `HEAD`.

- [ ] **Step 5: Publish and read back the release**

Create `v0.1.0-alpha.1` with `gh release create --prerelease`, attach both
installers, then query the release and confirm `isPrerelease`, tag, and both
asset names.
