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

// The redact-fallback disclosure this plugin adds. Pinned for the reason the
// Antigravity sibling's is: the wording states what a DEFAULT install does with
// a value a policy wanted masked, and nothing else here would go red if it
// drifted.
describe('SKILL.md redact-fallback disclosure', () => {
  const flat = skillMd.replace(/\s+/g, ' ');

  it('names the class, the default and the way back', () => {
    expect(flat).toMatch(/redact policy cannot mask a \*\*shell command\*\*/i);
    expect(flat).toMatch(/redact fallback/i);
    expect(flat).toMatch(/ships as \*\*warn\*\*/i);
    expect(flat).toMatch(/runs with the value unmasked/i);
    expect(flat).toMatch(/Set it to \*\*block\*\*/i);
  });

  it('keeps apply_patch on the masked side, where the field classification puts it', () => {
    // `apply_patch.input` is classified `executable: false`, so the hook
    // captures it rewritable and a redact really is carried out there. This is
    // the half of the disclosure that is a CAPABILITY claim rather than a
    // limitation, so it is the half that must not drift optimistically.
    expect(flat).toMatch(/apply_patch[^.]*masked in place/i);
  });
});
