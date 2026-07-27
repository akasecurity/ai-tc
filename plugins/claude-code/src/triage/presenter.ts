/**
 * The Claude Code presentation wiring for the shared apply-suppressions
 * orchestrator (@akasecurity/setup-wizard's runApply). Every member either
 * carries Claude-Code-branded copy, names a host command, or reads the
 * installed command registry — the host-bound surface the shared core injects
 * rather than owns. Every other harness plugin wires its own equivalent.
 */
import type { AdapterPresenter } from '@akasecurity/setup-wizard';

import { frameCalibration, frameEmptyState, zeroCountFrame } from '../calibration.ts';
import { readRegisteredCommands } from '../command-registry.ts';
import { fenced, show } from '../present.ts';
import { renderApplied, renderRecommendedPosture, STORE_UNAVAILABLE_NOTE } from '../render.ts';
import { frameJsonBlock } from '../setup-frame-json.ts';

export const adapterPresenter: AdapterPresenter = {
  show,
  fenced,
  frameJsonBlock,
  frameEmptyState,
  frameCalibration,
  zeroCountFrame,
  renderRecommendedPosture,
  // The applied card's Ready line resolves against the installed command
  // registry — closed over here so the shared core never reads it.
  renderApplied: (categoriesTuned, dismissed) =>
    renderApplied(categoriesTuned, dismissed, readRegisteredCommands()),
  storeUnavailableNote: STORE_UNAVAILABLE_NOTE,
};
