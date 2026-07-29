import { browser } from "$app/environment";

/** True inside the Android WebView (its UA contains "Android"; desktop
 *  WebKitGTK does not). Used to hide desktop-only UI on the mobile build. */
export const isAndroid = browser && /Android/i.test(navigator.userAgent);

export function isWindowsPlatform(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return normalized === "win32" || normalized === "windows";
}
