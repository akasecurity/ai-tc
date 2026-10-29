import { createHash } from 'node:crypto';

import type { RecordProjectEgressInput } from '@akasecurity/schema';
import { EgressIngestRequest, SUPERSEDED_PROJECT_KEYS_MAX } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  hashProjectKey,
  supersededProjectKeys,
  toEgressIngestRequest,
} from '../src/egress-wire.ts';
import { resolvedHit as hit } from './helpers/egress-hits.ts';

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest('hex');

// Digests the 0.9.20 build (`v2`) sent for these keys, spelled out so a change
// to the earlier canonical form fails here rather than silently re-keying.
const V2 = {
  githubLower: 'f21b86b8847ce05dc76cd91b932035b87427d7fa0934a654a0048368c3c3674b',
  githubMixed: 'fcc0820bb481ff2e53e5e2bce95193a0a5dde4a620c17403bc1fb26f7b893ecf',
  selfHosted: 'fb2bd17c8487b3a77653a8818b1d8ca16a1413839b132792b65df089a2af4c8b',
};

// Digests 0.9.10 and 0.9.11 sent: SHA-256 of the key as written, unversioned.
const UNVERSIONED = {
  githubHttps: 'fb2e86c96941e5f7c67280f0cf839f34ff4889015cc198d1b0393c3c253ac103',
  githubMixedScp: 'ff54745c63a763f9d95a4ff17e6df9401328bf81521442f342df7e63301ea9a6',
};

describe('supersededProjectKeys', () => {
  it('names the v2 digest, then the unversioned one, of a key whose canonical form is unchanged', () => {
    const key = 'git:https://github.com/acme/payments.git';
    expect(hashProjectKey(key)).toBe(
      '97ed46e8a9b000a920fb18990171f59d06495a22e403264f4e302264965001c5',
    );
    expect(supersededProjectKeys(key)).toEqual([V2.githubLower, UNVERSIONED.githubHttps]);
  });

  it('keeps the path case a forge folds now, as the v2 form did', () => {
    const mixed = 'git:git@github.com:Acme/Payments.git';
    expect(hashProjectKey(mixed)).toBe(hashProjectKey('git:https://github.com/acme/payments'));
    expect(supersededProjectKeys(mixed)).toEqual([V2.githubMixed, UNVERSIONED.githubMixedScp]);
  });

  it('gives each clone spelling of one repository the v2 digest that spelling had', () => {
    const spellings = [
      'git:https://github.com/acme/payments',
      'git:git@github.com:acme/payments.git',
      'git:ssh://git@GitHub.com:22/acme/payments/',
    ];
    for (const key of spellings) {
      expect(supersededProjectKeys(key)).toEqual([V2.githubLower, sha256(key)]);
    }
  });

  it('keeps the case on a host that is not a known forge', () => {
    const lower = 'git:https://git.internal.example/team/svc.git';
    const mixed = 'git:https://git.internal.example/Team/Svc.git';
    expect(supersededProjectKeys(lower)).toEqual([V2.selfHosted, sha256(lower)]);
    expect(supersededProjectKeys(mixed)).toEqual([
      sha256('v2:git:git.internal.example/Team/Svc'),
      sha256(mixed),
    ]);
  });

  it('names both earlier digests of a path: key, which is hashed as written', () => {
    expect(supersededProjectKeys('path:/work/Demo')).toEqual([
      sha256('v2:path:/work/Demo'),
      sha256('path:/work/Demo'),
    ]);
  });

  it('never names the current digest and stays within the wire cap', () => {
    for (const key of ['git:https://github.com/acme/payments', 'path:/work/demo']) {
      const superseded = supersededProjectKeys(key);
      expect(superseded).not.toContain(hashProjectKey(key));
      expect(superseded.length).toBeLessThanOrEqual(SUPERSEDED_PROJECT_KEYS_MAX);
    }
  });
});

describe('toEgressIngestRequest — superseded project keys', () => {
  const input: RecordProjectEgressInput = {
    projectKey: 'git:git@github.com:Acme/Payments.git',
    projectId: null,
    project: 'payments',
    reconcile: { mode: 'walk', walkedPrefix: '' },
    hits: [hit()],
  };

  it('carries the earlier digests beside the current one, and parses', () => {
    const request = toEgressIngestRequest(input);
    expect(request.projectKey).toBe(hashProjectKey(input.projectKey));
    expect(request.supersededProjectKeys).toEqual([V2.githubMixed, UNVERSIONED.githubMixedScp]);
    expect(EgressIngestRequest.parse(request)).toEqual(request);
  });

  it('carries no plaintext key in the superseded list', () => {
    const body = JSON.stringify(toEgressIngestRequest(input));
    expect(body).not.toContain('Acme/Payments');
  });
});
