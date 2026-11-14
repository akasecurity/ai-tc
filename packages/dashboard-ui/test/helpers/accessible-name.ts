/**
 * The accessible name a control gets from its content, for the controls these
 * views render: text nodes in order, an `aria-hidden` subtree contributing
 * nothing, and an element with an `aria-label` contributing that label in place
 * of its content. `sr-only` text is included, because it is hidden only
 * visually. A gap or margin between children contributes nothing, which is the
 * difference from what a sighted reader sees.
 *
 * Not the full accessible-name algorithm: it ignores `aria-labelledby`, `alt`
 * and `title`. A caller asserting on a control that might carry one of those
 * should assert their absence first.
 */
export function accessibleName(node: Node): string {
  if (node.nodeType === Node.TEXT_NODE) return node.textContent ?? '';
  if (node instanceof Element) {
    if (node.getAttribute('aria-hidden') === 'true') return '';
    const label = node.getAttribute('aria-label');
    if (label !== null) return label;
  }
  return [...node.childNodes].map(accessibleName).join('');
}
