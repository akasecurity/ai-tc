import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  keyReadersThatSend,
  readSources,
  ungatedSightingSenders,
  unlistedSightingSenders,
} from '../../../test/helpers/sighting-sender-guard.ts';

// The modules under src/ that decide to send credential sightings, as paths
// relative to it. Empty: nothing here decides. A sender is added to this list in
// the change that adds it, and must import and call readSightingSharing or
// resolveSightingSharing.
const SIGHTING_SENDERS: readonly string[] = [];

// Modules that only carry a sightings request they are handed. This package
// cannot read the sharing settings, so the gate is read by the caller:
// forwardCredentialSightings in @akasecurity/persistence, immediately before it
// calls the sender.
const SIGHTING_TRANSPORTS: readonly string[] = ['client.ts', 'index.ts', 'sightings-sender.ts'];

// Modules that fetch or hold the sighting key and send no sightings. A module on
// this list that starts referencing a sighting send fails below and must move to
// SIGHTING_SENDERS or SIGHTING_TRANSPORTS.
const SIGHTING_KEY_READERS: readonly string[] = [];

const sources = readSources(fileURLToPath(new URL('../src/', import.meta.url)));

describe('credential-sighting senders under src/', () => {
  it('reads the directory it guards', () => {
    expect(sources.length).toBeGreaterThan(0);
  });

  it('lists every module that mentions sightings', () => {
    expect(
      unlistedSightingSenders(sources, SIGHTING_SENDERS, [
        ...SIGHTING_TRANSPORTS,
        ...SIGHTING_KEY_READERS,
      ]),
    ).toEqual([]);
  });

  it('has every listed key reader send no sightings', () => {
    expect(keyReadersThatSend(sources, SIGHTING_KEY_READERS)).toEqual([]);
  });

  it('has every listed sender consult the sharing gate', () => {
    expect(ungatedSightingSenders(sources, SIGHTING_SENDERS)).toEqual([]);
  });
});
