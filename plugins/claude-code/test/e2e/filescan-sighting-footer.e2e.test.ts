/**
 * `/aka:scan` ends with the credential-sightings line. Drives the BUILT
 * `scripts/filescan.js` against a throwaway home and an empty directory.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SIGHTING_SHARE_PAYLOAD_NOTE } from '@akasecurity/schema';
import { afterAll, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { hostEnv, tempHomeEnv } from '../helpers/run-hook.ts';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'filescan.js');

const temps: string[] = [];

afterAll(() => {
  removeTrees(temps);
});

describe('/aka:scan footer', () => {
  it('closes the report with whether credential sightings are shared', () => {
    const home = mkdtempSync(join(tmpdir(), 'aka-filescan-home-'));
    const target = mkdtempSync(join(tmpdir(), 'aka-filescan-target-'));
    temps.push(home, target);

    const result = spawnSync(process.execPath, [SCRIPT, '--dir', target], {
      encoding: 'utf8',
      env: { ...hostEnv(), ...tempHomeEnv(home) },
      timeout: 60_000,
    });

    expect(result.status).toBe(0);
    const lines = result.stdout.trimEnd().split('\n');
    // The closing fence, then the footer as the last line inside it.
    expect(lines.at(-1)).toBe('```');
    expect(lines.at(-2)).toBe(
      '  Credential sightings: off (standalone) — this machine is not attached to an ' +
        `organization. ${SIGHTING_SHARE_PAYLOAD_NOTE}`,
    );
  });
});
