// Shared presentational atoms for the vault views: the sighting-kind and
// de-reference vocabularies as display labels, plus the reveal-grant badge.
import type { VaultDerefReason, VaultSightingKind } from '@akasecurity/schema';
import { Badge } from '@akasecurity/ui-kit';

// Surface-class labels for sighting chips.
export const SIGHTING_KIND_LABEL: Record<VaultSightingKind, string> = {
  prompt: 'Prompt',
  'tool-input': 'Tool input',
  'tool-output': 'Tool output',
  file: 'File',
  transcript: 'Transcript',
};

// De-reference reason labels for the audit trail.
export const DEREF_REASON_LABEL: Record<VaultDerefReason, string> = {
  display: 'Display render',
  'explicit-reveal': 'Explicit reveal',
  'view-render': 'View render',
  'model-input': 'Model input',
  remediation: 'Remediation',
  purge: 'Purge',
};

/**
 * Reveal-grant chip. Rendered ONLY while an active reveal-to-model grant
 * covers the value — the model can receive its raw form at tool boundaries,
 * so every vault surface flags it. Values without a grant stay unlabelled.
 */
export function RevealToModelBadge() {
  return <Badge variant="critical">Reveal to model</Badge>;
}

/** Surface-class chip for one sighting. */
export function SightingKindChip({ kind }: { kind: VaultSightingKind }) {
  return <Badge variant="outline">{SIGHTING_KIND_LABEL[kind]}</Badge>;
}
