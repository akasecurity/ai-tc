import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// The setup skill's consent surface is the disclosure the model-judge grant
// rests on. These assertions pin its SUBSTANCE — a copy edit that drops one of
// these facts changes what the user consented to, and must fail loudly here
// rather than ship silently (mirrors the Claude Code plugin's
// setup-vault-consent-copy.test.ts).
const skillMd = readFileSync(
  fileURLToPath(new URL('../skills/setup/SKILL.md', import.meta.url)),
  'utf8',
);

describe('SKILL.md model-judge egress disclosure', () => {
  it('names exactly what crosses: the raw value plus the re-masked ~120-character window', () => {
    expect(skillMd).toContain('raw value');
    expect(skillMd).toMatch(/120 characters of the\s+surrounding transcript text/);
    expect(skillMd).toMatch(/re-masked first/);
  });

  it('names what is dropped before egress: the file path and the fingerprint', () => {
    expect(skillMd).toMatch(
      /rollout file's\s+path, the value's fingerprint, and the fingerprint key version are \*\*dropped\s+before egress\*\*/,
    );
  });

  it('states the disclosure before the model-judge consent question is asked', () => {
    const disclosure = skillMd.indexOf('dropped\nbefore egress');
    const question = skillMd.indexOf('Send findings to the model to sort real leaks from noise?');
    expect(disclosure).toBeGreaterThan(-1);
    expect(question).toBeGreaterThan(disclosure);
    // The step-3 restatement of the payload also precedes the question.
    const restatement = skillMd.indexOf('restate plainly what leaves the');
    expect(restatement).toBeGreaterThan(-1);
    expect(question).toBeGreaterThan(restatement);
  });

  it('records the grant with exactly the --model-judge-consent flag', () => {
    expect(skillMd).toContain('onboard.js" --model-judge-consent');
    // No variant spelling of the flag anywhere in the skill.
    expect(skillMd).not.toMatch(/--model-judge(?!-consent)/);
    expect(skillMd).not.toContain('--judge-consent');
  });

  it('routes the No-consent option to the severity floor, never the pipe', () => {
    const noConsent = skillMd.indexOf('If the user chose "No, keep it local"');
    expect(noConsent).toBeGreaterThan(-1);
    const branch = skillMd.slice(noConsent, skillMd.indexOf('Pipe the backfill', noConsent));
    expect(branch).toContain('do **not** run the pipe');
    expect(branch).toContain('onboard.js" --floor');
  });
});

describe('SKILL.md known-limitation disclosure', () => {
  it('keeps the section and discloses the vault deferral', () => {
    expect(skillMd).toContain('## Known limitation');
    expect(skillMd).toMatch(/reversible secret vault is\s+not yet wired for Codex/);
  });
});
