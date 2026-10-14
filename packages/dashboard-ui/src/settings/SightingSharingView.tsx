'use client';

import type { SightingSharing } from '@akasecurity/schema';
import {
  managedByLabel,
  SIGHTING_SHARE_PAYLOAD_NOTE,
  sightingShareModeLabel,
  sightingShareReasonText,
} from '@akasecurity/schema';

import type { Choice } from '../shared/ChoiceGroup.tsx';
import { ChoiceGroup } from '../shared/ChoiceGroup.tsx';
import { HISTORY_SYNC_SECTION_LABEL } from './WorkspaceSettingsFormView.tsx';

export type SightingShareChoice = 'granted' | 'revoked';

export const SIGHTING_SHARE_SECTION_LABEL = 'Credential sightings';

export const SIGHTING_SHARE_SECTION_DESCRIPTION =
  'Whether this machine shares credential sightings with the organization it is attached to.';

export const SIGHTING_SHARE_CHOICES: Choice<SightingShareChoice>[] = [
  {
    value: 'granted',
    label: 'Share with my organization',
    description:
      'Report the credentials scans find on this machine to the organization it is attached to, as hashes or ciphertext.',
  },
  {
    value: 'revoked',
    label: 'Do not share',
    description: 'Credential sightings stay on this machine.',
  },
];

export const SIGHTING_SHARE_STANDALONE_NOTE =
  'Nothing is shared while this machine is standalone. Attach it to an organization to answer; the answer applies to that organization only.';

export const SIGHTING_SHARE_SCOPE_NOTE = `This setting covers credential sightings only. What else an attached machine sends is set out under ${HISTORY_SYNC_SECTION_LABEL} above.`;

export interface SightingSharingViewProps {
  state: SightingSharing;
  onChange: (choice: SightingShareChoice) => void;
  busy?: boolean | undefined;
  error?: string | null | undefined;
}

function sentence(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/**
 * The credential-sightings sharing state: the connection mode, whether sharing
 * is on and why, what a sighting carries, and the user's answer — editable
 * only while attached, and only where the organization's managed settings do
 * not decide it.
 */
export function SightingSharingView({ state, onChange, busy, error }: SightingSharingViewProps) {
  const lockedBy = state.locked
    ? managedByLabel({
        present: true,
        lockedFields: [],
        ...(state.organization === undefined ? {} : { organization: state.organization }),
      })
    : undefined;
  const value: SightingShareChoice = (state.locked ? state.sharing : state.optedIn)
    ? 'granted'
    : 'revoked';
  const headingId = 'sighting-share-label';
  const standalone = state.mode === 'standalone';
  const disabled = lockedBy !== undefined || standalone || busy === true;
  return (
    <section data-slot="sighting-sharing">
      <h2 className="mb-2 text-label font-semibold uppercase tracking-wider text-text-3">
        Sharing
      </h2>
      <div className="overflow-hidden rounded-xl border border-border bg-surface px-4 py-3">
        <div className="flex items-start gap-3">
          <span className="flex-1">
            <span id={headingId} className="block text-sm font-medium text-text">
              {SIGHTING_SHARE_SECTION_LABEL}
            </span>
            <span className="mt-0.5 block text-xs text-text-3">
              {SIGHTING_SHARE_SECTION_DESCRIPTION}
            </span>
          </span>
          <span
            className="shrink-0 rounded-full bg-surface-2 px-2 py-0.5 text-xs font-medium text-text-2"
            data-slot="sighting-share-state"
          >
            {state.sharing ? 'On' : 'Off'} · {sightingShareModeLabel(state.mode)}
          </span>
        </div>
        <p className="mt-3 text-xs text-text-2" data-slot="sighting-share-reason">
          {sentence(sightingShareReasonText(state))}
        </p>
        <p className="mt-1 text-xs text-text-3" data-slot="sighting-share-payload">
          {SIGHTING_SHARE_PAYLOAD_NOTE}
        </p>
        {standalone ? (
          <p className="mt-1 text-xs text-text-3" data-slot="sighting-share-standalone">
            {SIGHTING_SHARE_STANDALONE_NOTE}
          </p>
        ) : (
          <p className="mt-1 text-xs text-text-3" data-slot="sighting-share-scope">
            {SIGHTING_SHARE_SCOPE_NOTE}
          </p>
        )}
        {lockedBy !== undefined && (
          <p className="mt-3 text-xs text-text-3" data-slot="managed-notice">
            {lockedBy}. This setting cannot be changed here.
          </p>
        )}
        <fieldset disabled={disabled} className="contents">
          <div className="mt-3">
            <ChoiceGroup
              name="sightingShareConsent"
              labelledBy={headingId}
              choices={SIGHTING_SHARE_CHOICES}
              value={value}
              onChange={onChange}
              disabled={disabled}
            />
          </div>
        </fieldset>
        {error !== undefined && error !== null && (
          <p className="mt-3 text-xs text-sev-high-ink" role="alert">
            {error}
          </p>
        )}
      </div>
    </section>
  );
}
