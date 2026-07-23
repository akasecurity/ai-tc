import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const setupMd = readFileSync(new URL('../commands/setup.md', import.meta.url), 'utf8');

// The 0.4b adjust fork's own section — from its heading up to (not including) the
// next '## 5' heading. Slicing here (rather than to EOF) keeps the fork-scoped
// guards off the identical step-5 confirm spine, which exists independently of
// this branch; a full-file slice would fold step 5 in and let a fork guard pass
// on step 5 alone.
const forkHeading = '## 4b. Adjust a category';
const forkStart = setupMd.indexOf(forkHeading);
const forkEnd = setupMd.indexOf('\n## 5', forkStart);
const forkSection = setupMd.slice(forkStart, forkEnd === -1 ? undefined : forkEnd);

// The prompt-authored 0.3 scan-offer copy lives in commands/setup.md, so a
// regression is otherwise only visible in the manual walkthrough. These guards
// pin the verbatim strings the wizard shows at the scan offer — including the
// privacy-critical disclosure that the scan sends raw, unmasked values to the
// model API via the `claude` CLI, which must be stated before consent.
describe('setup.md 0.3 scan-offer copy', () => {
  it('carries the scan-offer question verbatim', () => {
    expect(setupMd).toContain(
      "I'll scan Claude's recent work — transcripts, temp files, agent memory — and send what I find to the model to rate it, so I can tune what I bring you next.",
    );
  });

  it('carries the Yes-option subtitle verbatim', () => {
    expect(setupMd).toContain(
      'scan my real work here; raw findings go to the model to be rated, then tune what you bring me',
    );
  });

  it('carries the Not-now-option subtitle verbatim', () => {
    expect(setupMd).toContain("start light and I'll learn as we go");
  });

  it('discloses the model-API egress plainly before the consent picker', () => {
    // Whitespace-normalized so the assertion is not coupled to prose line wrapping.
    const flat = setupMd.replace(/\s+/g, ' ');
    expect(flat).toContain(
      'sends the raw, unmasked values — including any secrets — to the model API through the `claude` CLI',
    );
    expect(flat).toContain('they are **not** kept on the machine');
    expect(flat).toContain('Do not present the picker until you have said this');
  });
});

// The 0.3b Not-now branch is prompt-authored orchestration in commands/setup.md:
// on 'Not now' the wizard runs start-light.js, adjusts via AskUserQuestion, writes
// the chosen posture, and rejoins the spine at the applying frame. These guards pin
// the routing so the interim graceful-termination scaffolding can't silently return.
describe('setup.md 0.3b Not-now start-light branch', () => {
  it('routes to the start-light script rather than terminating', () => {
    expect(setupMd).toContain('scripts/start-light.js');
    expect(setupMd).not.toContain('is not built yet');
  });

  it('names the start-light card heading the wizard reproduces verbatim', () => {
    expect(setupMd).toContain('● Starting light — your detection categories');
  });

  it('writes the chosen posture via --floor for defaults or --posture for adjustments', () => {
    expect(setupMd).toContain('scripts/onboard.js" --floor');
    expect(setupMd).toContain('scripts/onboard.js" --posture');
  });

  it('takes zero historical access on the Not-now path', () => {
    expect(setupMd).toContain('zero historical access');
  });
});

// The 0.4b Yes-path adjust reroute is prompt-authored orchestration in
// commands/setup.md: from the calibrated-result confirm the user can fork into
// the adjust table and rejoin the applying-frame spine carrying the adjusted
// posture. These guards pin the fork so it can't silently regress to a
// 'Yes, apply'-only confirm.
describe('setup.md 0.4b adjust reroute branch', () => {
  it('adds the adjust option to the confirm instead of deferring it', () => {
    // The load-bearing new option — the confirm now offers both.
    expect(setupMd).toContain('Yes, apply');
    expect(setupMd).toContain('Adjust a category');
    expect(setupMd).not.toContain('arrives in a follow-up');
  });

  it('renders the 0.4b adjust-confirm table via the start-light --adjust-confirm emission, keyed on the calibrated recommended base', () => {
    // The recommended column is the calibrated recommended posture, not the floor —
    // pin --recommended to the start-light emission (--posture also appears on the
    // onboard overlay below, so it is asserted on this exact command line).
    expect(forkSection).toContain(
      "scripts/start-light.js\" --adjust-confirm --recommended '<recommended-json>' --posture",
    );
  });

  it('carries the save options verbatim', () => {
    expect(forkSection).toContain('Save adjusted — N changed, M as recommended');
    expect(forkSection).toContain('Back to recommended');
  });

  it('rejoins the unchanged confirm spine within the fork, then overlays the changed packs after it', () => {
    const spineIdx = forkSection.indexOf('apply-suppressions.js" --confirmed --plan');
    const overlayIdx = forkSection.indexOf('onboard.js" --posture');
    expect(spineIdx).toBeGreaterThanOrEqual(0);
    expect(overlayIdx).toBeGreaterThanOrEqual(0);
    // Ordering matters: the confirm spine must dismiss/fill-gap and write the
    // recommended base before the changed-packs overlay runs, or evidence-backed
    // packs regress. The overlay must come after the spine, never before.
    expect(overlayIdx).toBeGreaterThan(spineIdx);
  });
});

// The 0.4b adjust fork rejoins the spine at the applying frame (0.5) with its own
// full-8-pack confirmation prose in commands/setup.md — distinct from the step-5
// spine's generic '✓ Set all K detection categories'. Freeze that fork-specific
// rejoin copy so a voice regression fails CI, not only the manual walkthrough.
// Scope is the branch frames only; frame 0.6 and the Yes-take-a-look spine copy
// (frames 0.1–0.6) are baselined elsewhere and are not re-frozen here.
//
// The rest of the branch-frame voice baseline is already covered and is not
// duplicated here: the 0.3b start-light heading ('● Starting light — your
// detection categories'), the 0.4b 'Adjust a category' option, and the
// save-option copy are frozen verbatim by the 0.3b/0.4b branch blocks above.
// Strings that live in a rendered card rather than setup.md prose — the
// start-light heading, the 'Re-tune anytime with /aka:setup or the dashboard'
// re-tune hint, and the confirm table's 'CATEGORY │ RECOMMENDED │ YOURS' header
// (rendered uppercase, space-aligned; the lowercase '│'-framed phrase is only
// prose narration of it) — are guarded against real stdout by
// start-light.test.ts, so this guard stays on the setup.md-prose surface.
describe('setup.md branch-frame voice baseline (0.4b → 0.5 rejoin)', () => {
  it('rejoins the applying frame (0.5) with the full-8-pack tuned/dismissed prose', () => {
    // Command-line templating carve-out: assert only the stable applying-frame
    // prose, never the 'Ready: …' command names the registry templates over the
    // actually-registered command set. Asserted within the fork section so it is
    // the fork's own '✓ Set all 8 detection categories' applying frame, not the
    // step-5 spine's generic '✓ Set all K detection categories'.
    expect(forkSection).toContain('✓ Set all 8 detection categories · set aside N routine results');
  });
});

// Frame 0.6's "Review leaked keys" branch is prompt-authored orchestration.
// The offer itself was already wired, but choosing it must actually run the
// secret-leak remediation chain rather than dead-ending. These guards pin the
// routing so it can't silently regress back to an unwired option.
describe('setup.md frame-0.6 "Review leaked keys" branch', () => {
  it("routes to the remediation entry's present and route modes rather than leaving the option unwired", () => {
    expect(setupMd).toContain('scripts/remediate.js');
    expect(setupMd).toContain('scripts/remediate.js" --option');
  });

  it('feeds the entry the calibration frame block captured in step 3, not a fresh scan', () => {
    expect(setupMd).toContain("Also **retain the block's full text verbatim**");
    expect(setupMd).toContain('captured in step 3, verbatim');
  });

  it('offers exactly the four remediation-decision options in stable order, each mapped to its --option id', () => {
    const idx = setupMd.indexOf('If they choose "Review leaked keys"');
    expect(idx).toBeGreaterThanOrEqual(0);
    const section = setupMd.slice(idx, setupMd.indexOf('\n## 7', idx));
    expect(section).toContain('**Redact + rotation checklist** (`redact-rotation-checklist`)');
    expect(section).toContain('**Redact only** (`redact-only`)');
    expect(section).toContain("**Set 'secret' to redact** (`set-secret-redact`)");
    expect(section).toContain('**Leave** (`leave`)');
  });

  it('instructs showing the FULL remediation-decision layout — count line, table, recommendation and chaining lines — not just the table', () => {
    const idx = setupMd.indexOf('If they choose "Review leaked keys"');
    expect(idx).toBeGreaterThanOrEqual(0);
    const section = setupMd.slice(idx, setupMd.indexOf('\n## 7', idx));
    // The count line, table, and the recommendation + chaining lines are all
    // named as parts the agent must reproduce to the user verbatim — so the
    // rendered decision is shown whole, never narrowed to the finding table.
    expect(section).toContain('the templated count line');
    expect(section).toContain('recommendation line');
    expect(section).toContain('chaining line');
    expect(section.replace(/\s+/g, ' ')).toContain(
      'do not drop the recommendation or chaining lines',
    );
  });

  it('composes with, and never replaces, the Open dashboard / Not now handoff', () => {
    expect(setupMd).toContain(
      'This composes with —\n  never replaces — the dashboard handoff below, so both stay reachable.',
    );
  });

  it('follows a redact choice with the standing-posture question, offering exactly the four palette options mapped to --posture levels', () => {
    const idx = setupMd.indexOf('If they choose "Review leaked keys"');
    expect(idx).toBeGreaterThanOrEqual(0);
    const section = setupMd.slice(idx, setupMd.indexOf('\n## 7', idx));
    expect(section).toContain('If they chose "Redact + rotation checklist" or "Redact only"');
    expect(section).toContain("Set the 'secret' detection level");
    const redact = section.indexOf('**Redact** (`redact`)');
    const warn = section.indexOf('**Warn** (`warn`)');
    const block = section.indexOf('**Block** (`block`)');
    const monitor = section.indexOf('**Monitor** (`monitor`)');
    // The palette appears in the standing order Redact -> Warn -> Block -> Monitor.
    expect(redact).toBeGreaterThanOrEqual(0);
    expect(warn).toBeGreaterThan(redact);
    expect(block).toBeGreaterThan(warn);
    expect(monitor).toBeGreaterThan(block);
  });

  it('runs the route ONCE for a redact choice, carrying both --option and --posture, never re-running the redact route', () => {
    const idx = setupMd.indexOf('If they choose "Review leaked keys"');
    const section = setupMd.slice(idx, setupMd.indexOf('\n## 7', idx));
    expect(section).toContain('scripts/remediate.js" --option <id> --posture <level>');
    expect(section).toContain('Never run the route a second time for this choice');
    // The redact route is invoked exactly once — a second invocation would strike
    // already-redacted keys and corrupt the count.
    const invocations = section.split('--option <id> --posture <level>').length - 1;
    expect(invocations).toBe(1);
  });

  it("routes 'Set 'secret' to redact' and 'Leave' unchanged — no standing-posture follow-up, no --posture", () => {
    const idx = setupMd.indexOf('If they choose "Review leaked keys"');
    const section = setupMd.slice(idx, setupMd.indexOf('\n## 7', idx));
    expect(section).toContain('If they chose "Set \'secret\' to redact" or "Leave"');
    expect(section).toContain("scripts/remediate.js\" --option <id> <<'AKA_FRAME'");
  });
});

// Task 9: the prompt states the relay contract once, up front, rather than
// leaving a skimming model to infer AKA_SHOW handling per step. These guards
// pin the contract's verbatim invariant strings and the step-7 double-ask trim.
describe('setup.md execution contract', () => {
  it('states the one-sentence relay rule for AKA_SHOW regions', () => {
    expect(setupMd).toContain('relay every AKA_SHOW region verbatim');
  });
  it('forbids ad-libbed confirmations', () => {
    expect(setupMd).toContain('write a confirmation or acknowledgement the wizard did not emit');
  });
  it('requires each step’s SHOW regions before advancing', () => {
    expect(setupMd).toContain('must be relayed before you advance');
  });
  it('states one picker per decision', () => {
    expect(setupMd).toContain('picker per decision');
  });
  it('step 7 has a single install gate (no second permission picker)', () => {
    // The old double-ask phrasing must be gone.
    expect(setupMd).not.toContain('Ask permission before running it, warmly');
  });
});
