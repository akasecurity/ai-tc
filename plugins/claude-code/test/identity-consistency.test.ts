import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { SETUP_DESCRIPTION } from '../src/identity.ts';

const setupMd = readFileSync(new URL('../commands/setup.md', import.meta.url), 'utf8');

// Reads the `description:` value from the leading YAML frontmatter block —
// the string Claude Code registers as the /aka:setup slash-command description.
function frontmatterDescription(source: string): string {
  const frontmatter = /^---\n([\s\S]*?)\n---/.exec(source)?.[1];
  const value = frontmatter ? /^description:[ \t]*(.*)$/m.exec(frontmatter)?.[1] : undefined;
  if (value === undefined) throw new Error('setup.md has no frontmatter description');
  return value.trim();
}

const STALE_SETUP_DESCRIPTION =
  'Set up the AKA Control Plane plugin — evidence-first detection posture and historical access';

describe('SCENARIO-0002 — identity/description consistency guard', () => {
  it('setup.md frontmatter description equals the canonical constant', () => {
    expect(frontmatterDescription(setupMd)).toBe(SETUP_DESCRIPTION);
  });

  it('setup.md carries no stale command description', () => {
    expect(setupMd).not.toContain(STALE_SETUP_DESCRIPTION);
  });
});
