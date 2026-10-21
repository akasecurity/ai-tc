import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  CREDENTIAL_SIGHTINGS_BATCH_MAX,
  CredentialSighting,
  CredentialSightingsAck,
  CredentialSightingsRequest,
  SightingProject,
} from '../../src/zod/control-plane.ts';

describe('registry ids', () => {
  it('names the request body and its components, and not the response parser', () => {
    expect(z.globalRegistry.get(CredentialSightingsRequest)?.id).toBe('CredentialSightingsRequest');
    expect(z.globalRegistry.get(CredentialSighting)?.id).toBe('CredentialSighting');
    expect(z.globalRegistry.get(SightingProject)?.id).toBe('SightingProject');
    expect(z.globalRegistry.get(CredentialSightingsAck)).toBeUndefined();
  });
});

function token(fill = 'A', version = 3): string {
  return `[[aka:fp:v${String(version)}.${fill.repeat(43)}]]`;
}

const sighting = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  token: token(),
  ruleId: 'aws-access-key',
  category: 'secret',
  variableName: 'AWS_ACCESS_KEY_ID',
  locationClass: 'project-file',
  project: { projectKey: 'a'.repeat(64), name: 'acme/widgets' },
  gitTracked: true,
  seenAt: '2026-10-14T09:00:00.000Z',
  ...overrides,
});

const without = (key: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(sighting()).filter(([name]) => name !== key));

describe('CredentialSighting', () => {
  it('parses a sighting with every field', () => {
    expect(CredentialSighting.parse(sighting())).toEqual(sighting());
  });

  it('accepts a sighting without a variable name', () => {
    expect(CredentialSighting.safeParse(without('variableName')).success).toBe(true);
  });

  it('accepts each location class and refuses any other', () => {
    for (const locationClass of ['project-file', 'project-dot-directory', 'home-dotfile']) {
      expect(CredentialSighting.safeParse(sighting({ locationClass })).success).toBe(true);
    }
    expect(CredentialSighting.safeParse(sighting({ locationClass: 'elsewhere' })).success).toBe(
      false,
    );
  });

  it('refuses a token that is not a sighting token', () => {
    for (const bad of ['', 'plain', token('A').replace('fp', 'secret'), `${token()} `]) {
      expect(CredentialSighting.safeParse(sighting({ token: bad })).success).toBe(false);
    }
  });

  it('carries only the secret category', () => {
    expect(CredentialSighting.safeParse(sighting({ category: 'pii' })).success).toBe(false);
  });

  it('refuses a project key that is not a digest', () => {
    for (const projectKey of ['path:/Users/someone/widgets', 'A'.repeat(64), 'a'.repeat(63)]) {
      expect(
        CredentialSighting.safeParse(sighting({ project: { projectKey, name: 'widgets' } }))
          .success,
      ).toBe(false);
    }
  });

  it('refuses a project name carrying a control character', () => {
    expect(
      CredentialSighting.safeParse(
        sighting({ project: { projectKey: 'a'.repeat(64), name: 'wid\u001bgets' } }),
      ).success,
    ).toBe(false);
  });

  it('refuses any field the contract does not name, so no path or excerpt can ride along', () => {
    for (const extra of [
      { filePath: 'src/config.ts' },
      { excerpt: 'AWS_ACCESS_KEY_ID = ...' },
      { maskedMatch: 'AK**' },
    ]) {
      expect(CredentialSighting.safeParse(sighting(extra)).success).toBe(false);
    }
    expect(
      CredentialSighting.safeParse(
        sighting({ project: { projectKey: 'a'.repeat(64), name: 'w', root: '/Users/x/w' } }),
      ).success,
    ).toBe(false);
  });

  it('requires gitTracked and seenAt', () => {
    expect(CredentialSighting.safeParse(without('gitTracked')).success).toBe(false);
    expect(CredentialSighting.safeParse(without('seenAt')).success).toBe(false);
  });
});

describe('CredentialSightingsRequest', () => {
  it('parses a batch with and without a scan id', () => {
    const scanId = '6f2d64f0-b6a4-4bb1-9a3c-6a4c26f5c9d1';
    expect(CredentialSightingsRequest.parse({ sightings: [sighting()], scanId }).scanId).toBe(
      scanId,
    );
    expect(CredentialSightingsRequest.safeParse({ sightings: [sighting()] }).success).toBe(true);
  });

  it('bounds the batch at both ends', () => {
    expect(CredentialSightingsRequest.safeParse({ sightings: [] }).success).toBe(false);
    const full = Array.from({ length: CREDENTIAL_SIGHTINGS_BATCH_MAX }, () => sighting());
    expect(CredentialSightingsRequest.safeParse({ sightings: full }).success).toBe(true);
    expect(CredentialSightingsRequest.safeParse({ sightings: [...full, sighting()] }).success).toBe(
      false,
    );
  });

  it('refuses an unknown top-level field', () => {
    expect(
      CredentialSightingsRequest.safeParse({ sightings: [sighting()], files: ['a'] }).success,
    ).toBe(false);
  });
});

describe('CredentialSightingsAck', () => {
  it('reads the accepted count and strips anything else', () => {
    expect(CredentialSightingsAck.parse({ accepted: 2, extra: true })).toEqual({ accepted: 2 });
    expect(CredentialSightingsAck.safeParse({ accepted: -1 }).success).toBe(false);
  });
});

describe('CredentialSighting aliases', () => {
  it('carries the same value under each previous key version, up to the cap', () => {
    const aliases = [token('B', 2), token('C', 1)];
    expect(CredentialSighting.parse(sighting({ aliases }))).toEqual(sighting({ aliases }));
    const many = Array.from({ length: 5 }, (_, i) => token('D', i + 1));
    expect(CredentialSighting.safeParse(sighting({ aliases: many })).success).toBe(false);
    expect(CredentialSighting.safeParse(sighting({ aliases: [] })).success).toBe(false);
    expect(CredentialSighting.safeParse(sighting({ aliases: ['raw-value'] })).success).toBe(false);
  });
});
