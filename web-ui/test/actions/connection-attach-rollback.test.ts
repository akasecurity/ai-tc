import { randomBytes } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import { controlPlaneCredentialPath, settingsDir } from '@akasecurity/persistence';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { attachToControlPlane } from '../../app/(app)/settings/actions.ts';
import {
  ATTACH_ROLLBACK_FAILED,
  ATTACH_ROLLBACK_LOST,
  SETTINGS_WRITE_ERROR,
} from '../../app/lib/action-refusals.ts';
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
/** The key an earlier credential file on the machine holds. */
const OTHER_KEY = randomBytes(24).toString('base64url');
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

    // Scoped, with nothing stored beside the file, so the credential still goes
    // first (a machine-wide attach over this file would write the settings first).
    const res = await attachToControlPlane({ endpoint: ENDPOINT, accessKey: KEY, mode: 'scoped' });

    expect(res).toEqual({
      ok: false,
      error: `${SETTINGS_WRITE_ERROR} ${ATTACH_ROLLBACK_FAILED}`,
    });
    expectNoEchoOf(res.error, KEY);
    // What was moved aside holds this attach's key, which is why "may differ" is
    // the true thing to say.
    expect(readFileSync(controlPlaneCredentialPath(`${dir}.moved`), 'utf8')).toContain(KEY);
  });

  it('says the same when the machine held no credential file before', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('A file where the settings directory belongs reads as ENOTDIR on POSIX only');
      return;
    }
    // Nothing was planted, so the attach's own write creates the directory and
    // the file, and the rollback has nothing earlier to restore: it is trying to
    // remove the key this attach saved, and it cannot reach it.
    const dir = settingsDir(akaHome());
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
    expect(readFileSync(controlPlaneCredentialPath(`${dir}.moved`), 'utf8')).toContain(KEY);
  });
});

// Scoped, with nothing stored beside the file: an attach over a credential file
// this build cannot read that writes the credential before the settings, so a
// failed settings write rolls it back.
describe('a rollback that puts the earlier credential file back, or says it is gone', () => {
  function credentialFile(): string {
    return controlPlaneCredentialPath(settingsDir(akaHome()));
  }

  function plantSettingsDirectory(): void {
    mkdirSync(settingsDir(akaHome()), { recursive: true, mode: 0o700 });
  }

  it('puts back the bytes of a file this build cannot parse', async () => {
    plantSettingsDirectory();
    const content = JSON.stringify({
      specVersion: 3,
      mode: 'scoped',
      endpoint: ENDPOINT,
      apiKey: OTHER_KEY,
    });
    writeFileSync(credentialFile(), content, { mode: 0o600 });

    const res = await attachToControlPlane({ endpoint: ENDPOINT, accessKey: KEY, mode: 'scoped' });

    expect(res).toEqual({ ok: false, error: SETTINGS_WRITE_ERROR });
    expectNoEchoOf(res.error, KEY);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(content);
  });

  it('puts back a credential that names an endpoint no key may be sent to', async () => {
    plantSettingsDirectory();
    const content = `${JSON.stringify(
      {
        specVersion: 1,
        endpoint: 'http://aka.acme.test',
        apiKey: OTHER_KEY,
        mintedAt: '2026-10-07T00:00:00.000Z',
      },
      null,
      2,
    )}\n`;
    writeFileSync(credentialFile(), content, { mode: 0o600 });

    const res = await attachToControlPlane({ endpoint: ENDPOINT, accessKey: KEY, mode: 'scoped' });

    expect(res).toEqual({ ok: false, error: SETTINGS_WRITE_ERROR });
    expectNoEchoOf(res.error, KEY);
    expect(readFileSync(credentialFile(), 'utf8')).toBe(content);
  });

  it('says the earlier file is gone when it could not be read at all', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('Creating a symbolic link needs a privilege Windows runners do not grant');
      return;
    }
    plantSettingsDirectory();
    const target = join(home, 'elsewhere-credential.json');
    const content = JSON.stringify({ specVersion: 3, endpoint: ENDPOINT, apiKey: OTHER_KEY });
    writeFileSync(target, content, { mode: 0o600 });
    symlinkSync(target, credentialFile());

    const res = await attachToControlPlane({ endpoint: ENDPOINT, accessKey: KEY, mode: 'scoped' });

    // A link is never followed, so there were no bytes to put back. The attach's
    // own file had replaced the link and is removed as well, and the refusal says
    // the earlier file is gone rather than implying nothing changed.
    expect(res).toEqual({
      ok: false,
      error: `${SETTINGS_WRITE_ERROR} ${ATTACH_ROLLBACK_LOST}`,
    });
    expectNoEchoOf(res.error, KEY);
    expect(existsSync(credentialFile())).toBe(false);
    // What the link pointed at was never written through.
    expect(readFileSync(target, 'utf8')).toBe(content);
  });
});
