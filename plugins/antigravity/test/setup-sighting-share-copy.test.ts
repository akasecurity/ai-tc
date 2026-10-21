import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { SIGHTING_SHARE_PAYLOAD_NOTE, SIGHTING_SHARE_ROTATION_NOTE } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

const doc = readFileSync(
  fileURLToPath(new URL('../skills/setup/SKILL.md', import.meta.url)),
  'utf8',
);

describe('setup credential-sightings question', () => {
  const start = doc.indexOf(
    '## 1b. Ask about sharing credential sightings — attached machines only',
  );
  const end = doc.indexOf('## 2. Save the answer, then branch');
  const step = doc.slice(start, end);

  it('is its own step, before the answers are saved', () => {
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
  });

  it('checks whether to ask before asking, and skips on standalone or managed machines', () => {
    const check = step.indexOf('onboard.js" --sighting-share-ask');
    const question = step.indexOf('Share credential sightings with your organization?');
    expect(check).toBeGreaterThan(-1);
    expect(question).toBeGreaterThan(check);
    expect(step).toContain('`askSightingShare`');
    expect(step).toMatch(
      /standalone, or its organization's managed settings already\s+decide the answer/,
    );
    expect(step).toContain('skip this step entirely');
  });

  it('states what a sighting carries, scoped to sightings, before the options', () => {
    const note = step.indexOf(SIGHTING_SHARE_PAYLOAD_NOTE);
    expect(note).toBeGreaterThan(-1);
    // Aliases sent during a key rotation stay inside the same grant, and the step says so.
    expect(step.indexOf(SIGHTING_SHARE_ROTATION_NOTE)).toBeGreaterThan(note);
    expect(step.indexOf('Share credential sightings with your organization?')).toBeGreaterThan(
      note,
    );
    expect(step).toMatch(/covers credential sightings only/);
  });

  it("defaults to don't share, and records each answer with the onboarding flag", () => {
    expect(step).toContain("**Don't share** _(default)_");
    expect(step.indexOf("**Don't share**")).toBeLessThan(
      step.indexOf('**Share with my organization**'),
    );
    expect(step).toContain('onboard.js" --sighting-share-consent grant');
    expect(step).toContain('onboard.js" --sighting-share-consent revoke');
  });
});
