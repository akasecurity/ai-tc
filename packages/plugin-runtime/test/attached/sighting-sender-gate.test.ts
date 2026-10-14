import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  readSources,
  ungatedSightingSenders,
  unlistedSightingSenders,
} from '../../../../test/helpers/sighting-sender-guard.ts';

// The modules under src/attached/ that send credential sightings, as paths relative to
// it. Empty: nothing here sends sightings yet. A sender is added to this list in
// the change that adds it, and must import and call readSightingSharing or
// resolveSightingSharing.
const SIGHTING_SENDERS: readonly string[] = [];

const sources = readSources(fileURLToPath(new URL('../../src/attached/', import.meta.url)));

describe('credential-sighting senders under src/attached/', () => {
  it('reads the directory it guards', () => {
    expect(sources.length).toBeGreaterThan(0);
  });

  it('lists every module that mentions sightings', () => {
    expect(unlistedSightingSenders(sources, SIGHTING_SENDERS)).toEqual([]);
  });

  it('has every listed sender consult the sharing gate', () => {
    expect(ungatedSightingSenders(sources, SIGHTING_SENDERS)).toEqual([]);
  });
});
