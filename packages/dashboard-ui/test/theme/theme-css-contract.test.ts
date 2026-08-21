import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

import { describe, expect, it } from 'vitest';

import { DARK_CLASS } from '../../src/theme/theme.ts';

// DARK_CLASS is one half of a contract whose other half is CSS in a DIFFERENT
// package, and nothing asserted the two agreed.
//
// `applyTheme` writes this class onto <html>; it re-themes the app only because
// @akasecurity/ui-kit's theme.css declares a `@custom-variant` for it AND an
// unlayered rule block that overrides every color token under it. Rename the
// class on one side and the app renders permanently light — no error, no failing
// assertion anywhere, because both halves are internally consistent. That is the
// exact failure the enterprise dashboard has today for a different reason, and it
// is not a hypothetical: a reviewer renamed the constant CONSISTENTLY (constant
// plus the init-script literal, so the literal↔constant pin still passed) and
// every suite in the repo stayed green.
//
// The split predates the theme module moving here. What moving it changed is the
// COST: the constant used to sit in web-ui beside its only consumer, and it is now
// a published export of a shared package whose next consumer is a different
// product in a different repository — so a theme.css edit can silently break a
// dashboard nobody working in ui-kit can see.
//
// Resolved through the package's own `./theme.css` export rather than by walking
// `../../ui-kit/src/styles/`, so this also proves the export path consumers
// actually import stays real, and survives the file moving inside ui-kit.
const require = createRequire(import.meta.url);
const THEME_CSS = readFileSync(require.resolve('@akasecurity/ui-kit/theme.css'), 'utf8');

/** Escaped for use in a RegExp — the class is a literal, not a pattern. */
const CLASS = DARK_CLASS.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

describe('DARK_CLASS ↔ ui-kit theme.css', () => {
  it('is the class ui-kit declares its dark variant for', () => {
    // `@custom-variant dark (&:where(.dark, ...))` — what makes `dark:` utilities
    // and the token overrides key off this class at all.
    expect(
      THEME_CSS,
      `@akasecurity/ui-kit's theme.css declares no @custom-variant for "${DARK_CLASS}". ` +
        `applyTheme would write a class nothing styles, and both dashboards would ` +
        `render permanently light with every suite still green.`,
    ).toMatch(new RegExp(`@custom-variant\\s+${CLASS}\\s*\\(`));
  });

  it('is the class ui-kit hangs its dark token block on', () => {
    // The unlayered `.dark, [data-theme='dark'] { --color-…: … }` block. The
    // variant above decides that `dark:` utilities compile; THIS is what actually
    // re-colors bg-surface/text-text-2/border-border, and it is a separate
    // selector list that can drift from the variant independently.
    expect(
      THEME_CSS,
      `@akasecurity/ui-kit's theme.css has no ".${DARK_CLASS}" rule block, so the ` +
        `dark token overrides would never apply.`,
    ).toMatch(new RegExp(`^\\.${CLASS}\\s*,`, 'm'));
  });

  it('the variant and the token block name the SAME class', () => {
    // Belt and braces: both assertions above derive from DARK_CLASS, so a
    // consistent rename across the constant AND both CSS sites would still pass.
    // That is the one mutation this file cannot catch and does not claim to —
    // it is a coordinated three-site edit, which is a diff a reviewer reads.
    // What it does catch is the one-sided rename, in either direction.
    const variant = new RegExp(`@custom-variant\\s+${CLASS}\\s*\\(&:where\\(\\.${CLASS}\\b`);
    expect(
      THEME_CSS,
      `theme.css's @custom-variant for "${DARK_CLASS}" does not select ".${DARK_CLASS}" — ` +
        `the variant name and the selector it expands to have drifted apart.`,
    ).toMatch(variant);
  });
});
