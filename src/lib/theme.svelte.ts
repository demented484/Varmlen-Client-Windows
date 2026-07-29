import { browser } from "$app/environment";

export type Theme = "dark" | "light";
const KEY = "varmlen.theme";

function read(): Theme {
  if (!browser) return "dark";
  const stored = localStorage.getItem(KEY);
  return stored === "light" ? "light" : "dark";
}

function apply(t: Theme): void {
  if (!browser) return;
  document.documentElement.setAttribute("data-theme", t);
  document.documentElement.style.colorScheme = t;
}

class ThemeStore {
  current = $state<Theme>(read());

  set(t: Theme): void {
    this.current = t;
    if (browser) localStorage.setItem(KEY, t);
    apply(t);
  }

  toggle(): void {
    this.set(this.current === "dark" ? "light" : "dark");
  }
}

export const theme = new ThemeStore();
// app.html's inline pre-paint script already wrote data-theme to
// <html>; reading theme.current at module scope would be a $state read
// outside a component/effect, which Svelte 5 forbids.
