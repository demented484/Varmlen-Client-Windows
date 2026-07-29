export type Lang = "en" | "ru";

export function initialLanguage(stored: string | null): Lang {
  return stored === "ru" || stored === "en" ? stored : "en";
}
