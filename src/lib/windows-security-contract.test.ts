import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function read(path: string): string {
  return readFileSync(new URL(path, import.meta.url), "utf8");
}

describe("Windows security hardening", () => {
  it("keeps TLS strict and does not grant plaintext external URL opening", () => {
    const xray = read("../../src-tauri/src/xray.rs");
    const capabilities = read("../../src-tauri/capabilities/default.json");

    expect(xray).toContain('tls.insert("allowInsecure".into(), json!(false))');
    expect(xray).toContain("contains_insecure_tls_override");
    expect(capabilities).toContain('"url": "https://*"');
    expect(capabilities).not.toContain('"url": "http://*"');
  });
});
