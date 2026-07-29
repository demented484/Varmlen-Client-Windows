/** End the current browser editing session before replacing modal DOM. */
export function releaseActiveControl(doc: Document = document): void {
  const active = doc.activeElement;
  if (active instanceof HTMLElement) active.blur();
  doc.getSelection()?.removeAllRanges();
}
