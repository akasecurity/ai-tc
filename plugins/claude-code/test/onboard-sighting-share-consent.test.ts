/**
 * The credential-sightings grant/revoke flag on the onboarding writer, driven
 * through the real shipped script in a throwaway home.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  applyOnboarding,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import {
  isSightingShareConsentValid,
  SIGHTING_SHARE_CONSENT_VERSION,
  SIGHTING_SHARE_PAYLOAD_NOTE,
  WorkspaceSettings,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { readFrameJsonBlock } from '../src/setup-frame-json.ts';
import { SetupJourney } from './journey/harness.ts';

let journey: SetupJourney;

beforeEach(() => {
  journey = new SetupJourney();
});

afterEach(() => {
  journey.cleanup();
});

const ENDPOINT = 'https://cp.example';

function attach(): void {
  const base = join(journey.home, '.aka');
  const attachedAt = '2026-10-01T00:00:00.000Z';
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt } },
    base,
    null,
  );
  writeControlPlaneCredential(settingsDir(base), {
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: ['test', 'only'].join('-'),
    mintedAt: attachedAt,
  });
}

function persisted(): Record<string, unknown> {
  return JSON.parse(readFileSync(journey.settingsPath, 'utf8')) as Record<string, unknown>;
}

describe('--sighting-share-consent', () => {
  it('grant records a writer-stamped grant for the attached deployment', () => {
    attach();
    const result = journey.onboardSightingShareConsent('grant');
    expect(result.status).toBe(0);
    const settings = WorkspaceSettings.parse(persisted());
    expect(settings.sightingShareConsent?.version).toBe(SIGHTING_SHARE_CONSENT_VERSION);
    expect(isSightingShareConsentValid(settings.sightingShareConsent, ENDPOINT)).toBe(true);
    expect(result.stdout).toContain('Credential sightings: on (attached, scoped)');
    expect(result.stdout).toContain(SIGHTING_SHARE_PAYLOAD_NOTE);
  });

  it('refuses a grant while standalone and writes nothing', () => {
    const result = journey.onboardSightingShareConsent('grant');
    expect(result.status).not.toBe(0);
    expect(result.stdout).toContain('not attached to an organization');
    expect(() => readFileSync(journey.settingsPath, 'utf8')).toThrow();
  });

  it('revoke removes the grant from the file', () => {
    attach();
    journey.onboardSightingShareConsent('grant');
    const result = journey.onboardSightingShareConsent('revoke');
    expect(result.status).toBe(0);
    expect('sightingShareConsent' in persisted()).toBe(false);
  });

  it('refuses any other value and writes nothing', () => {
    const result = journey.onboardSightingShareConsent('maybe');
    expect(result.status).not.toBe(0);
    expect(result.stdout).toContain('invalid --sighting-share-consent "maybe"');
  });
});

describe('--sighting-share-ask', () => {
  it('says not to ask on a standalone machine, and writes nothing', () => {
    const result = journey.sightingShareAsk();
    expect(result.status).toBe(0);
    expect(readFrameJsonBlock(result.stdout)).toEqual({ askSightingShare: false });
    expect(() => readFileSync(journey.settingsPath, 'utf8')).toThrow();
  });

  it('says to ask on an attached machine the organization does not decide for', () => {
    attach();
    const result = journey.sightingShareAsk();
    expect(result.status).toBe(0);
    expect(readFrameJsonBlock(result.stdout)).toEqual({ askSightingShare: true });
  });
});
