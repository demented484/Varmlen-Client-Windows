import type { VpnMode } from "./settings.svelte";

export function appSplitAvailable(mode: VpnMode): boolean {
  return mode === "tun";
}
