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
      /transcript\s+file's path, the value's fingerprint, and the fingerprint key version are\s+\*\*dropped before egress\*\*/,
    );
  });

  it('states the disclosure before the model-judge consent question is asked', () => {
    const disclosure = skillMd.indexOf('**dropped before egress**');
    const question = skillMd.indexOf('Send findings to the model to sort real leaks from noise?');
    expect(disclosure).toBeGreaterThan(-1);
    expect(question).toBeGreaterThan(disclosure);
    // The step-3 restatement of the payload also precedes the question.
    const restatement = skillMd.indexOf('restate plainly what leaves the');
    expect(restatement).toBeGreaterThan(-1);
    expect(question).toBeGreaterThan(restatement);
  });

  // This host is weaker than the other two plugins' judges in three specific,
  // user-visible ways, and the consent copy is the only place a user learns it.
  // Each is pinned here so a future edit cannot quietly drop the admission and
  // leave the copy claiming the isolation Codex's --ephemeral actually provides.
  it('admits there is no ephemeral mode and the judge conversation is persisted', () => {
    expect(skillMd).toMatch(/no ephemeral mode/);
    expect(skillMd).toContain('~/.gemini/antigravity-cli/brain/');
  });

  it('admits the cleanup is best effort and can leave the conversation behind', () => {
    expect(skillMd).toMatch(/best\s+effort/);
    expect(skillMd).toMatch(/killed|kills/);
  });

  it('admits the raw values ride the command line and are visible to ps', () => {
    expect(skillMd).toMatch(/command line/);
    expect(skillMd).toContain('ps');
  });

  it('never claims the deletion is network isolation', () => {
    // The Codex copy's honesty rule, restated for the mechanism this host uses:
    // deleting a local file cannot unsend a request.
    expect(skillMd).toMatch(/not network isolation/);
    expect(skillMd).toMatch(/cannot recall what was already sent/);
  });

  it('states the disclosure of this host’s limits before the consent question', () => {
    const limits = skillMd.indexOf('no ephemeral mode');
    const question = skillMd.indexOf('Send findings to the model to sort real leaks from noise?');
    expect(limits).toBeGreaterThan(-1);
    expect(question).toBeGreaterThan(limits);
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
    expect(skillMd).toContain('## Known limitations');
    expect(skillMd).toMatch(/reversible secret vault is not wired for Antigravity/);
  });

  // Each of these is a capability the Claude Code plugin HAS and this one does
  // not. The wizard's whole job is setting the user's expectation of what is
  // being watched, so silently dropping one of these disclosures would leave
  // the wizard claiming coverage the host cannot provide. Pinned individually
  // so a rewrite that drops just one still fails.
  it('discloses that the IDE does not run plugin hooks', () => {
    expect(skillMd).toMatch(/IDE does not run plugin hooks/i);
    expect(skillMd).toMatch(/only apply to CLI sessions/i);
  });

  it('discloses that prompts can be neither blocked nor redacted', () => {
    expect(skillMd).toMatch(/Prompts cannot be blocked or redacted/i);
    expect(skillMd).toMatch(/carries no prompt text/i);
  });

  it('discloses that a redact policy blocks instead of masking', () => {
    expect(skillMd).toMatch(/redact policy blocks instead of masking/i);
  });

  it('discloses that tool results are not scanned live', () => {
    expect(skillMd).toMatch(/Tool results are not scanned live/i);
  });

  it('discloses that transcript-derived capture records nothing yet', () => {
    // The strongest claim to keep honest: the reconcile worker is wired and
    // triggered, so a reader could reasonably assume prompts are being
    // recorded. They are not, until the transcript record shapes are verified.
    expect(skillMd).toMatch(/Transcript-derived capture is not yet active/i);
    expect(skillMd).toMatch(/Do not tell the user their prompts are being recorded/i);
  });
});
