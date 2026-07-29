import { describe, expect, it } from "vitest";
import { isWindowsPlatform } from "./platform";

describe("Windows platform contract", () => {
  it("recognizes Windows values without treating Linux as Windows", () => {
    expect(isWindowsPlatform("win32")).toBe(true);
    expect(isWindowsPlatform("windows")).toBe(true);
    expect(isWindowsPlatform("linux")).toBe(false);
  });
});
