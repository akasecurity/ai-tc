import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  readSources,
  ungatedSightingSenders,
} from '../../../test/helpers/sighting-sender-guard.ts';

// The workspace-wide half of this check, that every caller hands the sightings
// transport to a gated forwarder, is eslint-config's sighting-send-path suite.
describe('the credential-sightings send path', () => {
  it('has the forwarder every send goes through consult the sharing gate', () => {
    const sources = readSources(fileURLToPath(new URL('../src/', import.meta.url)));
    expect(ungatedSightingSenders(sources, ['credential-sightings.ts'])).toEqual([]);
  });
});
