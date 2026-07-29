import { describe, expect, it } from "vitest";
import { appSplitAvailable } from "./split-availability";

describe("per-app split availability", () => {
  it("requires TUN mode", () => {
    expect(appSplitAvailable("tun")).toBe(true);
    expect(appSplitAvailable("proxy")).toBe(false);
  });
});
