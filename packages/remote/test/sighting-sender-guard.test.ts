import { describe, expect, it } from 'vitest';

import {
  ungatedSightingSenders,
  unlistedSightingSenders,
} from '../../../test/helpers/sighting-sender-guard.ts';

const GATED = [
  "import { readSightingSharing } from '@akasecurity/persistence';",
  'export function send(): void {',
  '  if (!readSightingSharing().sharing) return;',
  "  post('/v1/sightings');",
  '}',
].join('\n');

const UNGATED = "export function send(): void { post('/v1/sightings'); }";

const IMPORT_ONLY = [
  "import { resolveSightingSharing } from '@akasecurity/schema';",
  "export function send(): void { post('/v1/sightings'); }",
].join('\n');

describe('the sighting-sender guard', () => {
  it('flags a module that mentions sightings and is not listed', () => {
    const sources = [
      { path: 'a.ts', text: UNGATED },
      { path: 'b.ts', text: 'export const x = 1;' },
    ];
    expect(unlistedSightingSenders(sources, [])).toEqual(['a.ts']);
    expect(unlistedSightingSenders(sources, ['a.ts'])).toEqual([]);
  });

  it('flags a listed sender that skips the gate, only imports it, or does not exist', () => {
    const sources = [
      { path: 'gated.ts', text: GATED },
      { path: 'ungated.ts', text: UNGATED },
      { path: 'import-only.ts', text: IMPORT_ONLY },
    ];
    expect(
      ungatedSightingSenders(sources, ['gated.ts', 'ungated.ts', 'import-only.ts', 'gone.ts']),
    ).toEqual(['ungated.ts', 'import-only.ts', 'gone.ts']);
  });
});
