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
// pin the verbatim strings the wizard shows at the scan offer.
describe('setup.md 0.3 scan-offer copy', () => {
  it('carries the scope disclosure verbatim', () => {
    expect(setupMd).toContain(
      "A retroactive scan of recent activity — transcripts, temp files, agent memory — tunes the notifications we'll review next.",
    );
  });

  it('carries the Yes-option subtitle verbatim', () => {
    expect(setupMd).toContain('calibrate my notifications to your real activity');
  });

  it('carries the Not-now-option subtitle verbatim', () => {
    expect(setupMd).toContain('start light and learn as we go');
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
    expect(setupMd).toContain('Start light — set your packs');
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
// spine's generic '✓ K categories tuned'. Freeze that fork-specific rejoin copy so
// a voice regression fails CI, not only the manual walkthrough. Scope is the branch
// frames only; frame 0.6 and the Yes-scan spine copy (frames 0.1–0.6) are baselined
// elsewhere and are not re-frozen here.
//
// The rest of the branch-frame voice baseline is already covered and is not
// duplicated here: the 0.3b start-light heading ('Start light — set your packs'),
// the 0.4b 'Adjust a category' option, and the save-option copy are frozen verbatim
// by the 0.3b/0.4b branch blocks above. Strings that live in a rendered card rather
// than setup.md prose — the start-light heading, the 'Re-tune anytime with /aka:setup
// or the dashboard' re-tune hint, and the confirm table's 'CATEGORY │ RECOMMENDED │
// YOURS' header (rendered uppercase, space-aligned; the lowercase '│'-framed phrase
// is only prose narration of it) — are guarded against real stdout by
// start-light.test.ts, so this guard stays on the setup.md-prose surface.
describe('setup.md branch-frame voice baseline (0.4b → 0.5 rejoin)', () => {
  it('rejoins the applying frame (0.5) with the full-8-pack tuned/dismissed prose', () => {
    // Command-line templating carve-out: assert only the stable applying-frame
    // prose, never the 'Ready: …' command names the registry templates over the
    // actually-registered command set. Asserted within the fork section so it is
    // the fork's own '✓ 8 categories tuned' applying frame, not the step-5 spine's
    // generic '✓ K categories tuned'.
    expect(forkSection).toContain('✓ 8 categories tuned · ✓ N routine dismissed');
  });
});
