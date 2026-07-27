/**
 * The Codex CLI presentation wiring for the shared apply-suppressions
 * orchestrator (@akasecurity/setup-wizard's runApply). Every member either
 * carries Codex-branded copy, names a host skill, or reads the installed
 * skill registry — the host-bound surface the shared core injects rather
 * than owns. The Claude Code plugin wires its own equivalent of this file.
 */
import type { AdapterPresenter } from '@akasecurity/setup-wizard';

import { frameCalibration, frameEmptyState } from '../calibration.ts';
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
  renderRecommendedPosture,
  // The applied card's Ready line resolves against the installed skill
  // registry — closed over here so the shared core never reads it.
  renderApplied: (categoriesTuned, dismissed) =>
    renderApplied(categoriesTuned, dismissed, readRegisteredSkills()),
  storeUnavailableNote: STORE_UNAVAILABLE_NOTE,
};
