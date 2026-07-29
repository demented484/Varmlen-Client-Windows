export interface NavItem {
  path: string;
  /** i18n key, resolved in the layout via t(). */
  labelKey: string;
  /** SVG path data, used inside <svg viewBox="0 0 24 24"> with fill=currentColor. */
  icon: string;
}

export const NAV: NavItem[] = [
  {
    path: "/",
    labelKey: "nav.home",
    icon: "M12 3L2 12h3v8h6v-6h2v6h6v-8h3L12 3z",
  },
  {
    path: "/split",
    labelKey: "nav.split",
    // Material Symbols "call_split" — two diverging arrows, instantly readable
    // as a routing split.
    icon: "M14 4l2.29 2.29-2.88 2.88 1.42 1.42 2.88-2.88L20 10V4h-6zM10 4H4v6l2.29-2.29 4.71 4.71V20h2v-8.41l-5.29-5.3L10 4z",
  },
  {
    path: "/settings",
    labelKey: "nav.settings",
    icon: "M19.14 12.94a7.96 7.96 0 0 0 .06-1.88l2.03-1.58a.5.5 0 0 0 .12-.64l-1.92-3.32a.5.5 0 0 0-.61-.22l-2.39.96a8.06 8.06 0 0 0-1.63-.94l-.36-2.54A.5.5 0 0 0 13.94 2h-3.88a.5.5 0 0 0-.5.42l-.36 2.54c-.59.24-1.13.55-1.63.94l-2.39-.96a.5.5 0 0 0-.61.22L2.65 8.48a.5.5 0 0 0 .12.64l2.03 1.58a8.05 8.05 0 0 0 0 1.88l-2.03 1.58a.5.5 0 0 0-.12.64l1.92 3.32c.14.24.43.34.61.22l2.39-.96c.5.39 1.04.7 1.63.94l.36 2.54c.06.24.27.42.5.42h3.88c.23 0 .44-.18.5-.42l.36-2.54c.59-.24 1.13-.55 1.63-.94l2.39.96c.18.12.47.02.61-.22l1.92-3.32a.5.5 0 0 0-.12-.64l-2.03-1.58zM12 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7z",
  },
];
