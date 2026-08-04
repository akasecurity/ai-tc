/**
 * The Antigravity CLI presentation wiring for the shared apply-suppressions
 * orchestrator (@akasecurity/setup-wizard's runApply). Every member either
 * carries Antigravity-branded copy, names a host skill, or reads the installed
 * skill registry — the host-bound surface the shared core injects rather
 * than owns. The Claude Code plugin wires its own equivalent of this file.
 */
import type { AdapterPresenter } from '@akasecurity/setup-wizard';

import { frameCalibration, frameEmptyState, zeroCountFrame } from '../calibration.ts';
import { fenced, show } from '../present.ts';
import { renderApplied, renderRecommendedPosture, STORE_UNAVAILABLE_NOTE } from '../render.ts';
import { frameJsonBlock } from '../setup-frame-json.ts';
import { readRegisteredSkills } from '../skills-registry.ts';

export const adapterPresenter: AdapterPresenter = {
  show,
  fenced,
  frameJsonBlock,
  frameEmptyState,
  frameCalibration,
  zeroCountFrame,
  renderRecommendedPosture,
  // How this host restarts the wizard. Antigravity exposes the flow as a skill
  // (`skills/setup/SKILL.md`, `name: aka-setup`) rather than a slash command,
  // so the stale-plan refusal names the skill the way Codex's does — there is
  // no `/aka:setup` to type here.
  rerunHint: 'the aka-setup skill',
  // The applied card's Ready line resolves against the installed skill
  // registry — closed over here so the shared core never reads it.
  renderApplied: (categoriesTuned, dismissed) =>
    renderApplied(categoriesTuned, dismissed, readRegisteredSkills()),
  storeUnavailableNote: STORE_UNAVAILABLE_NOTE,
};
