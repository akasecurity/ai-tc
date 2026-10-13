/**
 * The credential-sightings grant/revoke flag on the onboarding writer, driven
 * through the real shipped script in a throwaway home.
 */
import { readFileSync } from 'node:fs';

import {
  isSightingShareConsentValid,
  SIGHTING_SHARE_CONSENT_VERSION,
  WorkspaceSettings,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { SetupJourney } from './journey/harness.ts';

let journey: SetupJourney;

beforeEach(() => {
  journey = new SetupJourney();
});

afterEach(() => {
  journey.cleanup();
});

function persisted(): Record<string, unknown> {
  return JSON.parse(readFileSync(journey.settingsPath, 'utf8')) as Record<string, unknown>;
}

describe('--sighting-share-consent', () => {
  it('grant records a writer-stamped grant at the current version', () => {
    const result = journey.onboardSightingShareConsent('grant');
    expect(result.status).toBe(0);
    const settings = WorkspaceSettings.parse(persisted());
    expect(settings.sightingShareConsent?.version).toBe(SIGHTING_SHARE_CONSENT_VERSION);
    expect(isSightingShareConsentValid(settings.sightingShareConsent)).toBe(true);
    expect(result.stdout).toContain('Credential sightings:');
    expect(result.stdout).toContain('never plaintext');
  });

  it('revoke removes the grant from the file', () => {
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
