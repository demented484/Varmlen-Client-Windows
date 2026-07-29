import { describe, expect, it } from "vitest";
import { initialLanguage } from "./language";

describe("initialLanguage", () => {
  it("defaults a fresh profile to English", () => {
    expect(initialLanguage(null)).toBe("en");
    expect(initialLanguage("de-DE")).toBe("en");
  });

  it("preserves a valid saved language", () => {
    expect(initialLanguage("ru")).toBe("ru");
    expect(initialLanguage("en")).toBe("en");
  });
});
