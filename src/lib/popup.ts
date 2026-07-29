/** Move a node to document.body for its lifetime. A `position: fixed` popup
 *  inside a transformed/masked/filtered ancestor (e.g. our `.fade-y` scroll
 *  panels) would otherwise be positioned relative to that ancestor, not the
 *  viewport — pinning it to the wrong edge. Portalling to body avoids that. */
export function portal(node: HTMLElement) {
  document.body.appendChild(node);
  return {
    destroy() {
      node.remove();
    },
  };
}

/** Place a `position: fixed` popup next to its trigger, flipping to whichever
 *  side has room and clamping into the viewport. `width`/`height` are the
 *  popup's (estimated) size. Returns top + right (popups are right-aligned to
 *  the trigger, which sits on the right of its row). */
export function placePopup(
  trigger: DOMRect,
  width: number,
  height: number,
  gap = 4,
): { top: number; right: number } {
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const margin = 8;

  // Vertical: prefer opening below; if it would overflow the bottom, flip above
  // when there's more room there, otherwise clamp to the bottom.
  let top = trigger.bottom + gap;
  if (top + height > vh - margin) {
    const spaceAbove = trigger.top;
    const spaceBelow = vh - trigger.bottom;
    if (spaceAbove > spaceBelow) {
      top = Math.max(margin, trigger.top - gap - height);
    } else {
      top = Math.max(margin, vh - margin - height);
    }
  }

  // Horizontal: align the popup's right edge to the trigger's right edge, then
  // clamp so neither edge leaves the viewport.
  let right = vw - trigger.right;
  if (vw - right - width < margin) right = vw - width - margin;
  if (right < margin) right = margin;

  return { top, right };
}
