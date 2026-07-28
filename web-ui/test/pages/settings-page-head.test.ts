import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// The Settings page head speaks for the whole page, and the page mixes controls
// that behave differently: `settings.policy` is a stored default that drives no
// runtime enforcement, while historical access is a consent gate read at scan
// time. So ANY live-effect claim in this one line is false for at least one
// control, whatever it says about the others — which is what the shipped
// "applied on the next hook" subtitle got wrong.
//
// This reads the page source rather than the form's copy constants: the subtitle
// is written inline here, the same way the other pages write theirs, so the page
// itself is the only place the claim can appear.
const PAGE = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'app',
  '(app)',
  'settings',
  'page.tsx',
);

// The first four are false of every control on the page, so the form's copy
// guard bans them too (packages/dashboard-ui/test/settings/WorkspaceSettingsFormView.test.ts,
// ALWAYS_FALSE — keep the two in step). The verb class below is banned only
// here: a section describes one control and may legitimately say when that
// control takes effect, but the subtitle speaks for all of them at once.
const LIVE_EFFECT_CLAIMS = [
  /next hook/i,
  /nothing is altered/i,
  /immediately/i,
  /right away/i,
  /takes effect/i,
  /\bapplied\b/i,
  /\benforced\b/i,
];

describe('Settings page head', () => {
  const source = readFileSync(PAGE, 'utf8');
  const head = /<PageHead[\s\S]*?\/>/.exec(source)?.[0];
  const sub = head === undefined ? undefined : /\bsub="([^"]*)"/.exec(head)?.[1];

  it('renders a PageHead with a literal subtitle', () => {
    // Fails loudly if the subtitle stops being a string literal here — moving it
    // behind an expression would take it out of this guard's reach silently.
    expect(head, `no <PageHead .../> found in ${PAGE}`).toBeDefined();
    expect(sub, `no literal sub="..." found in ${head ?? ''}`).toBeDefined();
  });

  it.each(LIVE_EFFECT_CLAIMS)('promises no live effect (%s)', (claim) => {
    expect(sub ?? '').not.toMatch(claim);
  });
});
