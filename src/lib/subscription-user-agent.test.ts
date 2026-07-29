import { describe, expect, it } from "vitest";
import {
  SUBSCRIPTION_USER_AGENTS,
  normalizeSubscriptionUserAgent,
} from "./subscription-user-agent";

describe("subscription User-Agent setting", () => {
  it("offers exactly the four supported identities", () => {
    expect(SUBSCRIPTION_USER_AGENTS).toEqual([
      "varmlen",
      "happ",
      "incy",
      "v2raytun",
    ]);
  });

  it("defaults invalid or missing persisted values to Varmlen", () => {
    expect(normalizeSubscriptionUserAgent(undefined)).toBe("varmlen");
    expect(normalizeSubscriptionUserAgent("arbitrary\r\nheader")).toBe("varmlen");
    expect(normalizeSubscriptionUserAgent("happ")).toBe("happ");
  });
});
