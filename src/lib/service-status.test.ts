import { describe, expect, it } from "vitest";
import { serviceStatusLabel } from "./service-status";

describe("service status", () => {
  it("does not claim the VPN is disconnected when the service is unreachable", () => {
    expect(serviceStatusLabel(null, "access denied")).toBe(
      "Service unavailable",
    );
  });

  it("formats a trustworthy service phase for display", () => {
    expect(serviceStatusLabel({ phase: "blocked_error" }, null)).toBe(
      "blocked error",
    );
  });
});
