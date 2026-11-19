/**
 * Roles whose elements may not be named by their author: `aria-label` on one of
 * them is ignored, and the element contributes its content instead. `generic`
 * is the role of a bare `span` or `div`, so a label on one of those names
 * nothing. The list is WAI-ARIA 1.2's, plus the roles the 1.3 draft adds to
 * it (`definition`, `mark`, `suggestion`, `term`, `time`, `tooltip`), so a
 * label the newer rules ignore is not counted here either.
 */
const NAME_PROHIBITED_ROLES = new Set([
  'caption',
  'code',
  'definition',
  'deletion',
  'emphasis',
  'generic',
  'insertion',
  'mark',
  'none',
  'paragraph',
  'presentation',
  'strong',
  'subscript',
  'suggestion',
  'superscript',
  'term',
  'time',
  'tooltip',
]);

/** The implicit role of the elements these views render with no `role`. */
const IMPLICIT_ROLES: Record<string, string> = {
  a: 'link',
  b: 'generic',
  button: 'button',
  code: 'code',
  div: 'generic',
  em: 'emphasis',
  i: 'generic',
  li: 'listitem',
  nav: 'navigation',
  p: 'paragraph',
  span: 'generic',
  strong: 'strong',
  ul: 'list',
};

function roleOf(el: Element): string | undefined {
  return el.getAttribute('role') ?? IMPLICIT_ROLES[el.localName];
}

/**
 * The accessible name a control gets from its content, for the controls these
 * views render: text nodes in order, an `aria-hidden` subtree contributing
 * nothing, and an element with an `aria-label` contributing that label in place
 * of its content — but only where its role permits a name, so a label on a bare
 * `span` is ignored as it is by assistive technology. `sr-only` text is
 * included, because it is hidden only visually. A gap or margin between
 * children contributes nothing, which is the difference from what a sighted
 * reader sees.
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
    const role = roleOf(node);
    if (label !== null && (role === undefined || !NAME_PROHIBITED_ROLES.has(role))) return label;
  }
  return [...node.childNodes].map(accessibleName).join('');
}

/** The text a sighted reader sees: everything except `sr-only` content. */
export function visibleText(node: Node): string {
  if (node.nodeType === Node.TEXT_NODE) return node.textContent ?? '';
  if (node instanceof Element && node.classList.contains('sr-only')) return '';
  return [...node.childNodes].map(visibleText).join('');
}
