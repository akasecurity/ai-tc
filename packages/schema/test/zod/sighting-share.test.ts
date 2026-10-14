import { describe, expect, it } from 'vitest';

import type { AttachmentMode } from '../../src/zod/control-plane.ts';
import { defaultWorkspaceSettings, WorkspaceSettings } from '../../src/zod/local.ts';
import { ManagedSettings } from '../../src/zod/managed.ts';
import {
  isSightingShareConsentValid,
  resolveSightingSharing,
  shouldAskSightingShare,
  SIGHTING_SHARE_CONSENT_VERSION,
  SIGHTING_SHARE_PAYLOAD_NOTE,
  type SightingSharing,
  sightingSharingLine,
} from '../../src/zod/sighting-share.ts';

const ENDPOINT = 'https://cp.example';

const GRANT = {
  acknowledgedAt: '2026-10-01T00:00:00.000Z',
  version: SIGHTING_SHARE_CONSENT_VERSION,
  endpoint: ENDPOINT,
};

function settings(granted: boolean): WorkspaceSettings {
  return granted
    ? WorkspaceSettings.parse({ sightingShareConsent: GRANT })
    : defaultWorkspaceSettings();
}

function managed(pin: boolean | undefined, locked = false): ManagedSettings {
  return ManagedSettings.parse({
    organization: 'Acme',
    values: pin === undefined ? {} : { sightingShareConsent: pin },
    lockedFields: locked ? ['sightingShareConsent'] : [],
  });
}

type Row = [
  label: string,
  mode: AttachmentMode | undefined,
  pin: boolean | undefined,
  granted: boolean,
  expected: Pick<SightingSharing, 'mode' | 'sharing' | 'managed' | 'locked' | 'reason'>,
];

// prettier-ignore
const rows: Row[] = [
  ['standalone, nothing set', undefined, undefined, false, { mode: 'standalone', sharing: false, managed: false, locked: false, reason: 'standalone' }],
  ['standalone, user granted', undefined, undefined, true, { mode: 'standalone', sharing: false, managed: false, locked: false, reason: 'standalone' }],
  ['standalone, pinned on', undefined, true, true, { mode: 'standalone', sharing: false, managed: false, locked: false, reason: 'standalone' }],
  ['standalone, pinned off', undefined, false, true, { mode: 'standalone', sharing: false, managed: false, locked: true, reason: 'standalone' }],
  ['machine, pinned on, no grant', 'machine', true, false, { mode: 'machine', sharing: true, managed: true, locked: true, reason: 'managed-required' }],
  ['machine, pinned on, granted', 'machine', true, true, { mode: 'machine', sharing: true, managed: true, locked: true, reason: 'managed-required' }],
  ['machine, pinned off, granted', 'machine', false, true, { mode: 'machine', sharing: false, managed: false, locked: true, reason: 'managed-denied' }],
  ['machine, pinned off, no grant', 'machine', false, false, { mode: 'machine', sharing: false, managed: false, locked: true, reason: 'managed-denied' }],
  ['machine, no pin, granted', 'machine', undefined, true, { mode: 'machine', sharing: true, managed: false, locked: false, reason: 'opted-in' }],
  ['machine, no pin, no grant', 'machine', undefined, false, { mode: 'machine', sharing: false, managed: false, locked: false, reason: 'not-opted-in' }],
  ['scoped, pinned on, no grant', 'scoped', true, false, { mode: 'scoped', sharing: false, managed: false, locked: false, reason: 'not-opted-in' }],
  ['scoped, pinned on, granted', 'scoped', true, true, { mode: 'scoped', sharing: true, managed: false, locked: false, reason: 'opted-in' }],
  ['scoped, pinned off, granted', 'scoped', false, true, { mode: 'scoped', sharing: false, managed: false, locked: true, reason: 'managed-denied' }],
  ['scoped, no pin, granted', 'scoped', undefined, true, { mode: 'scoped', sharing: true, managed: false, locked: false, reason: 'opted-in' }],
  ['scoped, no pin, no grant', 'scoped', undefined, false, { mode: 'scoped', sharing: false, managed: false, locked: false, reason: 'not-opted-in' }],
];

describe('resolveSightingSharing', () => {
  it.each(rows)('%s', (_label, attachmentMode, pin, granted, expected) => {
    const state = resolveSightingSharing({
      settings: settings(granted),
      managed: managed(pin),
      attachmentMode,
      endpoint: ENDPOINT,
    });
    expect(state).toMatchObject(expected);
  });

  it('never shares with no administrator and no grant, in any mode', () => {
    for (const attachmentMode of [undefined, 'machine', 'scoped'] as const) {
      const state = resolveSightingSharing({
        settings: settings(false),
        managed: null,
        attachmentMode,
        endpoint: ENDPOINT,
      });
      expect(state.sharing).toBe(false);
      expect(state.locked).toBe(false);
    }
  });

  it('shares on a user grant when no managed file exists', () => {
    const state = resolveSightingSharing({
      settings: settings(true),
      managed: null,
      attachmentMode: 'scoped',
      endpoint: ENDPOINT,
    });
    expect(state).toMatchObject({ sharing: true, reason: 'opted-in', locked: false });
  });

  it('locks a locked-but-unpinned key while still honouring the user answer', () => {
    const state = resolveSightingSharing({
      settings: settings(true),
      managed: managed(undefined, true),
      attachmentMode: 'scoped',
      endpoint: ENDPOINT,
    });
    expect(state).toMatchObject({ sharing: true, reason: 'opted-in', locked: true });
  });

  it('does not count a grant given for another deployment', () => {
    const state = resolveSightingSharing({
      settings: settings(true),
      managed: null,
      attachmentMode: 'scoped',
      endpoint: 'https://other.example',
    });
    expect(state).toMatchObject({ sharing: false, reason: 'not-opted-in', optedIn: false });
  });

  it('does not count a grant while standalone, whatever endpoint is passed', () => {
    const state = resolveSightingSharing({
      settings: settings(true),
      managed: null,
      attachmentMode: undefined,
      endpoint: ENDPOINT,
    });
    expect(state).toMatchObject({ sharing: false, optedIn: false });
    expect(state.endpoint).toBeUndefined();
  });

  it('does not count a grant recorded against another version', () => {
    const state = resolveSightingSharing({
      settings: WorkspaceSettings.parse({
        sightingShareConsent: { ...GRANT, version: SIGHTING_SHARE_CONSENT_VERSION + 1 },
      }),
      managed: null,
      attachmentMode: 'machine',
      endpoint: ENDPOINT,
    });
    expect(state).toMatchObject({ sharing: false, reason: 'not-opted-in' });
  });

  it('reports the user own grant separately from whether sharing is on', () => {
    const denied = resolveSightingSharing({
      settings: settings(true),
      managed: managed(false),
      attachmentMode: 'scoped',
      endpoint: ENDPOINT,
    });
    expect(denied).toMatchObject({ sharing: false, optedIn: true });
    const scopedPinnedOn = resolveSightingSharing({
      settings: settings(false),
      managed: managed(true),
      attachmentMode: 'scoped',
      endpoint: ENDPOINT,
    });
    expect(scopedPinnedOn).toMatchObject({ sharing: false, optedIn: false });
  });

  it('carries the organization name from the managed file', () => {
    const state = resolveSightingSharing({
      settings: settings(false),
      managed: managed(true),
      attachmentMode: 'machine',
      endpoint: ENDPOINT,
    });
    expect(state.organization).toBe('Acme');
  });

  it('fails closed when the input cannot be read', () => {
    const state = resolveSightingSharing({
      settings: null as unknown as WorkspaceSettings,
      managed: null,
      attachmentMode: 'machine',
      endpoint: ENDPOINT,
    });
    expect(state.sharing).toBe(false);
  });
});

describe('isSightingShareConsentValid', () => {
  it('accepts only the current version, given for this deployment', () => {
    expect(isSightingShareConsentValid(GRANT, ENDPOINT)).toBe(true);
    expect(isSightingShareConsentValid(undefined, ENDPOINT)).toBe(false);
    expect(isSightingShareConsentValid({ ...GRANT, version: 99 }, ENDPOINT)).toBe(false);
    expect(isSightingShareConsentValid(GRANT, 'https://other.example')).toBe(false);
    expect(isSightingShareConsentValid(GRANT, undefined)).toBe(false);
  });
});

describe('the stored grant', () => {
  it('reads a grant that names no deployment as no grant, keeping the rest of the file', () => {
    const parsed = WorkspaceSettings.parse({
      historicalAccess: 'full',
      sightingShareConsent: { acknowledgedAt: GRANT.acknowledgedAt, version: 1 },
    });
    expect(parsed.sightingShareConsent).toBeUndefined();
    expect(parsed.historicalAccess).toBe('full');
  });
});

describe('sightingSharingLine', () => {
  const line = (
    attachmentMode: AttachmentMode | undefined,
    pin: boolean | undefined,
    granted: boolean,
  ): string =>
    sightingSharingLine(
      resolveSightingSharing({
        settings: settings(granted),
        managed: managed(pin),
        attachmentMode,
        endpoint: ENDPOINT,
      }),
    );

  it('states the payload limit on every line', () => {
    for (const [, mode, pin, granted] of rows) {
      expect(line(mode, pin, granted)).toContain(SIGHTING_SHARE_PAYLOAD_NOTE);
    }
    expect(SIGHTING_SHARE_PAYLOAD_NOTE).toBe(
      'A credential sighting carries only a hash or ciphertext of the value, never the value itself.',
    );
  });

  it('words each state with its mode and its reason', () => {
    expect(line(undefined, undefined, false)).toMatch(
      /^Credential sightings: off \(standalone\) — this machine is not attached to an organization\./,
    );
    expect(line('machine', true, false)).toMatch(
      /^Credential sightings: on \(attached, machine-wide\) — required by Acme on this managed machine\./,
    );
    expect(line('scoped', false, true)).toMatch(
      /^Credential sightings: off \(attached, scoped\) — turned off by Acme\./,
    );
    expect(line('scoped', undefined, true)).toMatch(
      /^Credential sightings: on \(attached, scoped\) — you opted in\./,
    );
    expect(line('machine', undefined, false)).toMatch(
      /^Credential sightings: off \(attached, machine-wide\) — you have not opted in\./,
    );
  });

  it('falls back to a generic organization name', () => {
    const state = resolveSightingSharing({
      settings: settings(false),
      managed: ManagedSettings.parse({ values: { sightingShareConsent: true } }),
      attachmentMode: 'machine',
      endpoint: ENDPOINT,
    });
    expect(sightingSharingLine(state)).toContain('required by your organization');
  });
});

describe('shouldAskSightingShare', () => {
  it('asks only on an attached machine the managed settings do not decide for', () => {
    const ask = (attachmentMode: AttachmentMode | undefined, pin?: boolean, locked = false) =>
      shouldAskSightingShare(
        resolveSightingSharing({
          settings: settings(false),
          managed: managed(pin, locked),
          attachmentMode,
          endpoint: ENDPOINT,
        }),
      );
    expect(ask(undefined)).toBe(false);
    expect(ask('scoped')).toBe(true);
    expect(ask('machine')).toBe(true);
    expect(ask('scoped', true)).toBe(true);
    expect(ask('machine', true)).toBe(false);
    expect(ask('scoped', false)).toBe(false);
    expect(ask('scoped', undefined, true)).toBe(false);
  });
});
