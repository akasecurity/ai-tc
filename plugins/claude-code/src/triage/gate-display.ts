import type { SuppressionEntry } from '@akasecurity/plugin-sdk';
import type { ActionTaken, BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { builtinPolicyToAction } from '@akasecurity/schema';

import type { JoinEntry } from './join-file.ts';
import type { ShowcaseCategory } from './writeback.ts';

// Human gate for setup-triage FP suppressions. Before the wizard
// writes any exception, it shows the operator this confirm screen: one block per
// to-be-suppressed detection with the masked value, the rule, and the masked
// context window. This is the checkpoint that stops the model silently
// suppressing a genuine secret — a human reads the evidence and approves.
//
// RAW SAFETY: every field rendered here is ALREADY raw-free. `maskedValue`
// (from SuppressionEntry) and `maskedContext` (from JoinEntry) were produced
// through the raw-egress gate in join-file.ts; we never touch a raw value and
// deliberately render only masked fields plus non-secret metadata (ruleId,
// category, fingerprint hash). There is no raw here to assertRawFree against,
// which is correct — the masking already happened upstream.

// Locate the JoinEntry that supplies the masked context for a suppression.
// Primary key: valueFingerprint (both carry it; a fingerprint is a stable,
// collision-resistant hash of the raw value). Fallback: ruleId + masked value,
// so a context still renders if a fingerprint is missing on either side.
function findContext(entry: SuppressionEntry, join: readonly JoinEntry[]): string | undefined {
  const byFingerprint = join.find(
    (j) => j.valueFingerprint !== undefined && j.valueFingerprint === entry.valueFingerprint,
  );
  if (byFingerprint) return byFingerprint.maskedContext;
  const byRuleAndMask = join.find(
    (j) => j.ruleId === entry.ruleId && j.maskedMatch === entry.maskedValue,
  );
  return byRuleAndMask?.maskedContext;
}

// Enforcement strength, least -> most restrictive, over the stored ActionTaken
// palette. `allow` (an active exception override) sits below `log`/monitor. A
// DOWNGRADE is a planned action that ranks strictly below the category's stored
// one — the case I-1 requires the human to see and confirm before it is written.
const ACTION_RANK: Record<ActionTaken, number> = {
  allow: 0,
  log: 1,
  warn: 2,
  redact: 3,
  block: 4,
};

// Palette label for a stored ActionTaken, for display parity with the posture the
// wizard writes (monitor/warn/redact/block). `log` is the stored form of
// `monitor`; `allow` has no palette peer (it is an exception override, not a
// category posture) so it renders as-is.
const ACTION_LABEL: Record<ActionTaken, BuiltinPolicyId | 'allow'> = {
  log: 'monitor',
  warn: 'warn',
  redact: 'redact',
  block: 'block',
  allow: 'allow',
};

// Shared with the adjust fork's confirm card (render.ts), so both gates decide
// "is this a downgrade?" from one comparison rather than two that can drift.
export function isDowngrade(planned: BuiltinPolicyId, current: ActionTaken | undefined): boolean {
  if (current === undefined) return false;
  return ACTION_RANK[builtinPolicyToAction(planned)] < ACTION_RANK[current];
}

// The FULL per-category posture the writeback would overwrite.
// Rendered in the PREVIEW so the wizard shows the user every category's target
// action AND explicitly flags any category whose enforcement would be LOWERED from
// a stronger existing setting — an enforcement downgrade must never happen silently.
// `current` is the store's existing action per category (undefined = no row yet).
// This iterates the resolved plan's posture, so a category that had its suppression
// skipped but still has a posture change (M-1) is surfaced here too.
export function renderPosturePlan(
  posture: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
  current: Partial<Record<DetectionCategory, ActionTaken>>,
): string {
  const categories = Object.keys(posture) as DetectionCategory[];
  const lines: string[] = [];
  const downgrades: DetectionCategory[] = [];
  for (const category of categories) {
    const planned = posture[category];
    if (planned === undefined) continue;
    const existing = current[category];
    if (existing === undefined) {
      lines.push(`  ${category}: ${planned} (new)`);
    } else if (isDowngrade(planned, existing)) {
      downgrades.push(category);
      lines.push(
        `  ${category}: ${planned}  <<< LOWERED from ${ACTION_LABEL[existing]} — enforcement will be WEAKENED`,
      );
    } else if (ACTION_LABEL[existing] === planned) {
      lines.push(`  ${category}: ${planned} (unchanged)`);
    } else {
      lines.push(`  ${category}: ${planned} (was ${ACTION_LABEL[existing]})`);
    }
  }
  if (lines.length === 0) {
    return 'No per-category detection posture will be written.';
  }
  return `Per-category detection posture to be applied:\n${lines.join('\n')}${downgradeWarning(downgrades)}`;
}

// The downgrade WARNING footer, single-sourced so every gate that can weaken
// enforcement (the confirm preview and the adjust fork's confirm card) states it
// identically. Empty string when nothing would be lowered.
export function downgradeWarning(downgrades: readonly DetectionCategory[]): string {
  if (downgrades.length === 0) return '';
  return `\n\nWARNING: ${String(downgrades.length)} categor${downgrades.length === 1 ? 'y' : 'ies'} (${downgrades.join(', ')}) would be LOWERED from a stronger existing setting. Confirm you intend to weaken enforcement there before applying.`;
}

// The intelligence showcase. One compact block per
// surviving category: the posture it recommends and the evidence behind it —
// how many hits it judged genuine vs. false-positive, and its reasoning. Rendered
// in the PREVIEW so the operator sees the judgment for EVERY category present in
// the evidence, including a genuine-hit category that produced no suppressions
// (that row still appears, with fp 0). RAW SAFETY: every field is raw-free by
// construction (reasoning was assertRawFree'd in planTriageWriteback; counts and
// enums carry no free text), so there is nothing to mask here.
export function renderShowcase(showcase: readonly ShowcaseCategory[]): string {
  if (showcase.length === 0) {
    return 'No per-category judgment to show.';
  }
  const blocks = showcase.map((s) => {
    const total = s.genuineCount + s.fpCount;
    return [
      `${s.category}: ${String(total)} hit${total === 1 ? '' : 's'} ` +
        `(${String(s.genuineCount)} genuine, ${String(s.fpCount)} false-positive) -> ${s.action}`,
      `   ${s.reasoning}`,
    ].join('\n');
  });
  return `What the judgment found, per category:\n\n${blocks.join('\n\n')}`;
}

export function renderSuppressionGate(
  entries: readonly SuppressionEntry[],
  join: readonly JoinEntry[],
): string {
  if (entries.length === 0) {
    return 'No false-positive suppressions to confirm — nothing will be written.';
  }

  const header =
    entries.length === 1
      ? 'The following detection will be suppressed as a false positive:'
      : `The following ${String(entries.length)} detections will be suppressed as false positives:`;

  const blocks = entries.map((entry, i) => {
    const context = findContext(entry, join);
    const lines = [
      `${String(i + 1)}. ${entry.ruleId} [${entry.category}]`,
      `   value:   ${entry.maskedValue}`,
      `   context: ${context ?? '(context unavailable)'}`,
      `   reason:  ${entry.justification}`,
    ];
    return lines.join('\n');
  });

  return `${header}\n\n${blocks.join('\n\n')}`;
}
