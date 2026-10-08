import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import { controlPlaneCredentialPath, settingsDir } from '@akasecurity/persistence';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { attachToControlPlane } from '../../app/(app)/settings/actions.ts';
import { ATTACH_ROLLBACK_FAILED, SETTINGS_WRITE_ERROR } from '../../app/lib/action-refusals.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { tempHomes } from '../helpers/temp-home.ts';

// The dashboard attach's rollback when putting the earlier credential file back
// itself fails. Only the settings write is faked, and it always fails: the
// credential write before it is real, and the fake runs one step inside the
// failing write, the moment between this attach's credential write and its
// rollback.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// The transport, stubbed: the key is accepted and nothing reaches a socket.
vi.mock('@akasecurity/remote', () => ({
  createRemoteClient: () => ({
    whoami: () => Promise.resolve({ tenantName: 'Example Org', userEmail: 'operator' }),
  }),
}));

const writeFailure = vi.hoisted(() => ({ onCall: null as (() => void) | null }));
vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    applyOnboarding: () => {
      writeFailure.onCall?.();
      throw new Error('disk full');
    },
  };
});

// Homes are removed when this FILE finishes, not after each test. See the helper.
const newHome = tempHomes('aka-web-attach-rollback-');

/** A high-entropy key made at run time, so no key-shaped literal sits in the tree. */
const KEY = randomBytes(24).toString('base64url');
const ENDPOINT = 'https://aka.acme.internal';

let home: string;
const akaHome = (): string => join(home, '.aka');

beforeEach(() => {
  home = newHome();
  osHome.dir = home;
  writeFailure.onCall = null;
});

describe('a rollback that cannot put the earlier credential file back', () => {
  it('says the file may differ, rather than only that settings.json could not be written', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('A file where the settings directory belongs reads as ENOTDIR on POSIX only');
      return;
    }
    const dir = settingsDir(akaHome());
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    // A file this build cannot read, which the named mode lets the attach replace.
    writeFileSync(
      controlPlaneCredentialPath(dir),
      JSON.stringify({ specVersion: 3, endpoint: ENDPOINT }),
      { mode: 0o600 },
    );
    // Inside the failing settings write, the settings directory is moved aside
    // and a file takes its place, so every read and write the rollback makes fails.
    writeFailure.onCall = () => {
      renameSync(dir, `${dir}.moved`);
      writeFileSync(dir, 'not a directory');
    };

    const res = await attachToControlPlane({ endpoint: ENDPOINT, accessKey: KEY, mode: 'machine' });

    expect(res).toEqual({
      ok: false,
      error: `${SETTINGS_WRITE_ERROR} ${ATTACH_ROLLBACK_FAILED}`,
    });
    expectNoEchoOf(res.error, KEY);
    // What was moved aside holds this attach's key, which is why "may differ" is
    // the true thing to say.
    expect(readFileSync(controlPlaneCredentialPath(`${dir}.moved`), 'utf8')).toContain(KEY);
  });
});
