import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  keyReadersThatSend,
  readSources,
  ungatedSightingSenders,
  unlistedSightingSenders,
} from '../../../../test/helpers/sighting-sender-guard.ts';

// The modules under src/attached/ that send credential sightings, as paths relative to
// it. A sender is added to this list in the change that adds it, and must import
// and call readSightingSharing or resolveSightingSharing.
const SIGHTING_SENDERS: readonly string[] = [
  'gateway.ts',
  'history-sync.ts',
  'outbound-encoder.ts',
];

// Modules that fetch or hold the sighting key and send no sightings. A module on
// this list that starts referencing a sighting send fails below and must move to
// SIGHTING_SENDERS.
const SIGHTING_KEY_READERS: readonly string[] = ['sighting-key-sync.ts', 'sync-entry.ts'];

const sources = readSources(fileURLToPath(new URL('../../src/attached/', import.meta.url)));

describe('credential-sighting senders under src/attached/', () => {
  it('reads the directory it guards', () => {
    expect(sources.length).toBeGreaterThan(0);
  });

  it('lists every module that mentions sightings', () => {
    expect(unlistedSightingSenders(sources, SIGHTING_SENDERS, SIGHTING_KEY_READERS)).toEqual([]);
  });

  it('has every listed key reader send no sightings', () => {
    expect(keyReadersThatSend(sources, SIGHTING_KEY_READERS)).toEqual([]);
  });

  it('has every listed sender consult the sharing gate', () => {
    expect(ungatedSightingSenders(sources, SIGHTING_SENDERS)).toEqual([]);
  });
});
