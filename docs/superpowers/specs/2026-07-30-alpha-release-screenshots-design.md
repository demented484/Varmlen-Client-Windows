# Alpha Release and Screenshots Design

## Goal

Publish the first Windows alpha with real GUI screenshots and make English the
default language for a fresh Varmlen profile.

## Language behavior

- A saved `varmlen.lang` value remains authoritative.
- A fresh profile with no saved language starts in English regardless of the
  Windows display language.
- Russian remains available in Settings.

## Screenshots

- Capture the actual current frontend at the configured `440 × 720` client
  viewport.
- Add Home, Split, and Settings screenshots under `docs/screenshots/`.
- Home may show the user's existing AegisVPN subscription and its public
  location names, but no subscription URL, UUID, credentials, JSON, or logs.
- The client remains disconnected while screenshots are prepared; no active
  host VPN or network policy is changed.
- README displays the screenshots in one compact GUI section.

## Release

- Tag: `v0.1.0-alpha.1`.
- GitHub release is marked as a pre-release.
- Attach both NSIS installers:
  `Varmlen_0.1.0_x64-setup.exe` and
  `Varmlen_0.1.0_arm64-setup.exe`.
- Release notes clearly state that installers are unsigned and that live
  Windows VPN acceptance remains outstanding.

## Verification

- A regression test proves that a missing saved language resolves to English
  while a valid saved language is preserved.
- Frontend tests, Svelte checks, Rust tests, formatting, clippy, x64/ARM64
  cross-checks, installer builds, embedded architecture inspection, and
  SHA-256 generation must pass before publication.
- GitHub's release metadata and uploaded asset list are read back after
  publication.
