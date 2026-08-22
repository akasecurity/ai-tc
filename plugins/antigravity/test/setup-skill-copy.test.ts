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

  // This host is weaker than the other two plugins' judges in two specific,
  // user-visible ways, and the consent copy is the only place a user learns it.
  // Each is pinned here so a future edit cannot quietly drop the admission and
  // leave the copy claiming the isolation Codex's --ephemeral actually provides.
  //
  // It was THREE until the judge prompt moved off argv onto stdin. The third
  // admission — that the raw values ride the command line and are visible to
  // `ps` — was removed with the behaviour it described, and its guard is now the
  // case below, which holds the copy to the new truth instead.
  it('admits there is no ephemeral mode and the judge conversation is persisted', () => {
    expect(skillMd).toMatch(/no ephemeral mode/);
    expect(skillMd).toContain('~/.gemini/antigravity/brain/');
  });

  it('admits the cleanup is best effort and can leave the conversation behind', () => {
    expect(skillMd).toMatch(/best\s+effort/);
    expect(skillMd).toMatch(/killed|kills/);
  });

  it('no longer claims the prompt rides the command line — it rides stdin', () => {
    // The admission this replaced was correct until the prompt moved to stdin,
    // and a consent surface that overstates the exposure is as wrong as one that
    // understates it: a user would decline a `ps`-visible egress that no longer
    // happens.
    //
    // Scoped to the limits section rather than the whole document, twice over.
    // `toContain('ps')` over the whole of SKILL.md is satisfied by "steps" and
    // was already vacuous, and `/command line/` legitimately appears elsewhere
    // describing a scanned `run_command` — so an unbounded absence check here
    // would fail for a reason that has nothing to do with consent copy.
    const start = skillMd.indexOf('limits of this host are worth knowing');
    const end = skillMd.indexOf('Reading history is granted in step 1');
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const limits = skillMd.slice(start, end);

    // Positive control on the SAME bytes: the section is really the limits
    // section and really still discloses something, so the absences below are
    // read off live copy rather than an empty or mis-located slice.
    expect(limits).toMatch(/no ephemeral mode/);
    expect(limits).toMatch(/not network isolation/);

    expect(limits).not.toMatch(/command line/);
    expect(limits).not.toMatch(/\bps\b/);
    expect(limits).not.toMatch(/list processes/);
  });

  it('states a limit count that matches the bullets it introduces', () => {
    // The count is user-facing prose, and prose beside a set is unguarded: this
    // sentence said "Three limits" until the judge prompt moved off argv, and
    // nothing but a human reading it would have caught the stale number. Derive
    // the set instead, so adding or removing a bullet forces the word with it.
    const start = skillMd.indexOf('limits of this host are worth knowing');
    const end = skillMd.indexOf('Reading history is granted in step 1');
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);

    // The stated count, read from the sentence's own leading word.
    const sentenceStart = skillMd.lastIndexOf('\n\n', start) + 2;
    const stated = /^(One|Two|Three|Four|Five)\b/.exec(skillMd.slice(sentenceStart, start));
    expect(stated?.[1], 'the limits sentence no longer opens with a count word').toBeDefined();
    const WORDS: Record<string, number> = { One: 1, Two: 2, Three: 3, Four: 4, Five: 5 };

    // The actual set: top-level `- **…` bullets in the section it introduces.
    const bullets = skillMd.slice(start, end).match(/^- \*\*/gm) ?? [];
    // Non-vacuous by construction — a section that stopped using bullets would
    // otherwise report zero and match no count word anyone would write.
    expect(bullets.length).toBeGreaterThan(0);
    expect(WORDS[stated?.[1] ?? '']).toBe(bullets.length);
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

  it('discloses that history is scanned but token usage still is not', () => {
    // This disclosure moved rather than went away. The historical scan reads
    // Antigravity's real record shape now, so the old blanket "records nothing"
    // would UNDER-state what runs — but usage reporting genuinely still
    // produces nothing, and that is the half a reader would otherwise assume
    // works because the reconcile worker is wired and triggered.
    expect(skillMd).toMatch(/History is scanned; token usage is not/i);
    expect(skillMd).toMatch(/Do not tell the user\s+their token spend is being tracked/i);
  });

  it('discloses that the historical scan does not read tool-call arguments', () => {
    expect(skillMd).toMatch(/Tool-call arguments are not scan input/i);
    // …and says which side of the live/historical line the gap falls on, so the
    // reader does not conclude that PreToolUse misses them too.
    expect(skillMd).toMatch(/live PreToolUse hook does scan those/i);
  });

  it('discloses that a blocked hook surfaces as a deny the user cannot attribute', () => {
    // The fail-CLOSED consequence. A user seeing "Tool call denied by <hook>"
    // with no reason attached has no way to tell an AKA policy decision from a
    // hook that never got to print, so the copy has to name the second case.
    expect(skillMd).toMatch(/A hook that gets stuck denies the tool call/i);
    expect(skillMd).toMatch(/cannot interrupt work that blocks the\s+thread/i);
    // And must not sell the guarantee as absolute — the exact overstatement the
    // wrapper's own docs were corrected for.
    expect(skillMd).toMatch(/Do not\s+describe AKA's fail-open guarantee to a user as absolute/i);
  });
});
