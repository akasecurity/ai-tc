import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  keyReadersThatSend,
  readSources,
  transportsWithoutGatedCaller,
  ungatedSightingSenders,
  unlistedSightingSenders,
} from '../../../test/helpers/sighting-sender-guard.ts';

// The modules under src/ that send credential sightings, as paths relative to
// it. Empty: nothing here sends sightings yet. A sender is added to this list in
// the change that adds it, and must import and call readSightingSharing or
// resolveSightingSharing.
const SIGHTING_SENDERS: readonly string[] = [];

// Modules that fetch or hold the sighting key and send no sightings. A module on
// this list that starts referencing a sighting send fails below and must move to
// SIGHTING_SENDERS.
const SIGHTING_KEY_READERS: readonly string[] = [];

// Modules that carry a credential-sightings request they are handed, each with the
// callers that build that request and consult the sharing gate at send time.
// `client.ts` also fetches the sighting key. Every send through either reaches the
// network only from `forwardCredentialSightings`.
const gatedForward = {
  path: 'credential-sightings.ts',
  text: readFileSync(
    fileURLToPath(new URL('../../persistence/src/credential-sightings.ts', import.meta.url)),
    'utf8',
  ),
};
const SIGHTING_TRANSPORTS = {
  'client.ts': [gatedForward],
  'sightings-sender.ts': [gatedForward],
};

// Modules that only re-export the ones above.
const SIGHTING_RE_EXPORTS: readonly string[] = ['index.ts'];

const sources = readSources(fileURLToPath(new URL('../src/', import.meta.url)));

describe('credential-sighting senders under src/', () => {
  it('reads the directory it guards', () => {
    expect(sources.length).toBeGreaterThan(0);
  });

  it('lists every module that mentions sightings', () => {
    expect(
      unlistedSightingSenders(sources, SIGHTING_SENDERS, [
        ...SIGHTING_KEY_READERS,
        ...Object.keys(SIGHTING_TRANSPORTS),
        ...SIGHTING_RE_EXPORTS,
      ]),
    ).toEqual([]);
  });

  it('has every listed key reader send no sightings', () => {
    expect(keyReadersThatSend(sources, SIGHTING_KEY_READERS)).toEqual([]);
  });

  it('has every re-export send nothing itself', () => {
    expect(keyReadersThatSend(sources, SIGHTING_RE_EXPORTS)).toEqual([]);
  });

  it('has every transport carry only requests a gated caller builds', () => {
    expect(transportsWithoutGatedCaller(sources, SIGHTING_TRANSPORTS)).toEqual([]);
  });

  it('has every listed sender consult the sharing gate', () => {
    expect(ungatedSightingSenders(sources, SIGHTING_SENDERS)).toEqual([]);
  });
});
