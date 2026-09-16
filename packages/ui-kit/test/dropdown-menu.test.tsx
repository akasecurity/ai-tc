import { describe, expect, it } from 'vitest';

import { DropdownMenuItem, type DropdownMenuItemProps } from '../src/dropdown-menu.tsx';

// Same style as badge.test.ts/card.test.tsx: no DOM, no renderer — the
// component is called as a plain function and its returned element's props
// are read directly. `tone` never got its own runtime coverage: emptying the
// `danger` branch of dropdownMenuItemVariants (or losing the base
// `data-[disabled]` token entirely) would still leave both this package and
// dashboard-ui green.
function classOf(tone: DropdownMenuItemProps['tone']): string {
  const el = DropdownMenuItem({ tone, children: null }) as { props: { className: string } };
  return el.props.className;
}

describe('DropdownMenuItem tone', () => {
  it('carries the base disabled/pointer-events tokens regardless of tone', () => {
    for (const tone of ['default', 'danger'] as const) {
      const classes = classOf(tone).split(' ');
      expect(classes).toContain('data-[disabled]:pointer-events-none');
      expect(classes).toContain('data-[disabled]:opacity-50');
    }
  });

  it('defaults to the ordinary item color when tone is omitted', () => {
    const classes = classOf(undefined).split(' ');
    expect(classes).toContain('text-text-2');
    expect(classes).toContain('focus:bg-surface-2');
    expect(classes).toContain('focus:text-text');
    // Not the destructive pair, or "omitted" and "danger" would be
    // indistinguishable.
    expect(classes).not.toContain('text-sev-critical-ink');
  });

  it('carries the destructive pair for tone="danger", not the ordinary one', () => {
    const classes = classOf('danger').split(' ');
    expect(classes).toContain('text-sev-critical-ink');
    expect(classes).toContain('focus:bg-sev-critical-fill');
    expect(classes).toContain('focus:text-sev-critical-ink');
    // The positive control's own property, reached the other way round: a
    // `danger` item must not ALSO carry the ordinary color it replaces.
    expect(classes).not.toContain('text-text-2');
  });
});
