import {
  chmodSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

import type { AttachedCredential, ControlPlaneConnection } from '@akasecurity/schema';
import { ATTACHED_CREDENTIAL_FILENAME } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  controlPlaneCredentialPath,
  isSafeEndpoint,
  readControlPlaneCredential,
  readControlPlaneCredentialFile,
  readControlPlaneCredentialState,
  removeControlPlaneCredential,
  writeControlPlaneCredential,
} from '../src/control-plane-credential.ts';
import { DATA_FILE_MODE } from '../src/paths.ts';
import { applyOnboarding } from '../src/settings.ts';
import { expectNoEchoOf } from './helpers/no-echo.ts';
import { useTempStore } from './helpers/temp-store.ts';

const ENDPOINT = 'https://aka.example-org.internal';
const API_KEY = 'not-a-real-key-4f2a9c8e1b6d';

const credential: AttachedCredential = {
  specVersion: 1,
  endpoint: ENDPOINT,
  apiKey: API_KEY,
  keyPrefix: 'not-a-re',
  mintedAt: '2026-08-24T10:00:00.000Z',
};

const connection: ControlPlaneConnection = {
  endpoint: ENDPOINT,
  attachedAt: '2026-08-24T10:00:00.000Z',
};

// The credential is the one file in `settings/` that holds a bearer token, so
// every case here is about a way it could be read when it should not be, or
// dropped when it should not be.

describe('isSafeEndpoint', () => {
  it('accepts https anywhere', () => {
    expect(isSafeEndpoint('https://aka.example-org.internal')).toBe(true);
    expect(isSafeEndpoint('https://localhost:8443')).toBe(true);
  });

  it('accepts http only on loopback, including the bracketed IPv6 form', () => {
    expect(isSafeEndpoint('http://localhost:3000')).toBe(true);
    expect(isSafeEndpoint('http://127.0.0.1:3000')).toBe(true);
    expect(isSafeEndpoint('http://[::1]:3000')).toBe(true);
  });

  it('refuses plaintext to a real network, and anything that is not a URL', () => {
    expect(isSafeEndpoint('http://aka.example-org.internal')).toBe(false);
    // A host merely SPELLED like loopback is a different host.
    expect(isSafeEndpoint('http://localhost.example.com')).toBe(false);
    expect(isSafeEndpoint('ftp://example.com')).toBe(false);
    expect(isSafeEndpoint('not a url')).toBe(false);
  });
});

describe('write then read', () => {
  const store = useTempStore('cpc-write');

  it('round-trips the credential and stores it owner-only', () => {
    writeControlPlaneCredential(store.settingsDir, credential);

    const read = readControlPlaneCredentialFile(store.settingsDir, connection);
    expect(read).toEqual({ usable: true, credential });

    // Owner-only is the whole at-rest control for this file. Windows has no
    // POSIX modes, so the assertion is scoped to where the mode is real.
    if (process.platform !== 'win32') {
      const mode = statSync(controlPlaneCredentialPath(store.settingsDir)).mode & 0o777;
      expect(mode).toBe(DATA_FILE_MODE);
    }
  });

  // THE PROJECTION, ASSERTED AT ITS SOURCE.
  //
  // The two readers answer the same question and only one of them may carry the
  // key. This is the property the whole split exists for: `CredentialState` is
  // what surfaces take, and one of those surfaces hands its value across a
  // `'use client'` boundary, where every prop is serialised into the payload the
  // browser receives.
  //
  // Asserted over the SERIALISED state, not by naming the absent field, so it
  // stays red for any future shape that reintroduces the value under another
  // name or nested one level down — and paired with the wide read above, which
  // proves the same bytes ARE reachable when a server-side caller asks for them
  // by name. A test that only checked the narrow one would pass just as well
  // against a reader that had stopped working.
  it('keeps the key out of the state, while the file read still carries it', () => {
    writeControlPlaneCredential(store.settingsDir, credential);

    const state = readControlPlaneCredentialState(store.settingsDir, connection);
    expect(state).toEqual({ usable: true });

    const serialised = JSON.stringify(state);
    expect(serialised).toContain('"usable":true');
    expectNoEchoOf(serialised, credential.apiKey);

    // The other half: this is not the key becoming unreachable.
    expect(readControlPlaneCredential(store.settingsDir, connection)?.apiKey).toBe(
      credential.apiKey,
    );
  });

  it('overwrites silently, because re-attaching is how a credential rotates', () => {
    writeControlPlaneCredential(store.settingsDir, credential);
    const rotated = { ...credential, apiKey: 'rotated-8c1d5e7a2f9b' };
    writeControlPlaneCredential(store.settingsDir, rotated);

    // Through the FULL read, because the rotated key is the thing being
    // asserted. `readControlPlaneCredentialState` deliberately cannot answer
    // this — its usable branch carries no credential.
    const read = readControlPlaneCredentialFile(store.settingsDir, connection);
    expect(read.usable && read.credential.apiKey).toBe('rotated-8c1d5e7a2f9b');
  });

  it('refuses to store a credential for an endpoint it would never present to', () => {
    const unsafe = { ...credential, endpoint: 'http://aka.example-org.internal' };
    expect(() => {
      writeControlPlaneCredential(store.settingsDir, unsafe);
    }).toThrow();
    // A refused write leaves nothing behind for a later read to find.
    expect(readControlPlaneCredentialState(store.settingsDir).usable).toBe(false);
  });
});

describe('reading a file that should not be trusted', () => {
  const store = useTempStore('cpc-read');

  it('reports absent when there is no file', () => {
    expect(readControlPlaneCredentialState(store.settingsDir)).toEqual({
      usable: false,
      reason: 'absent',
    });
  });

  it('reports malformed for JSON that is not a credential, and for non-JSON', () => {
    const file = controlPlaneCredentialPath(store.settingsDir);
    mkdirSync(store.settingsDir, { recursive: true });

    writeFileSync(file, 'not json at all', { mode: DATA_FILE_MODE });
    expect(readControlPlaneCredentialState(store.settingsDir)).toEqual({
      usable: false,
      reason: 'malformed',
    });

    writeFileSync(file, JSON.stringify({ endpoint: ENDPOINT }), { mode: DATA_FILE_MODE });
    expect(readControlPlaneCredentialState(store.settingsDir)).toEqual({
      usable: false,
      reason: 'malformed',
    });
  });

  it('reports malformed for a specVersion this build does not know', () => {
    // `specVersion` is a z.literal, so a future format is refused rather than
    // half-read — the machine stays standalone until something understands it.
    mkdirSync(store.settingsDir, { recursive: true });
    writeFileSync(
      controlPlaneCredentialPath(store.settingsDir),
      JSON.stringify({ ...credential, specVersion: 2 }),
      { mode: DATA_FILE_MODE },
    );
    expect(readControlPlaneCredentialState(store.settingsDir)).toEqual({
      usable: false,
      reason: 'malformed',
    });
  });

  it('reports unsafe-endpoint for a credential minted against a plaintext host', () => {
    // Reachable by a hand edit, so the read side refuses it too rather than
    // trusting that every writer went through writeControlPlaneCredential.
    mkdirSync(store.settingsDir, { recursive: true });
    writeFileSync(
      controlPlaneCredentialPath(store.settingsDir),
      JSON.stringify({ ...credential, endpoint: 'http://aka.example-org.internal' }),
      { mode: DATA_FILE_MODE },
    );
    expect(readControlPlaneCredentialState(store.settingsDir)).toEqual({
      usable: false,
      reason: 'unsafe-endpoint',
    });
  });

  it('refuses a symlink rather than reading whatever it points at', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('symlink creation needs a privilege that is not granted by default on Windows');
      return;
    }
    mkdirSync(store.settingsDir, { recursive: true });
    const elsewhere = join(store.home, 'planted.json');
    writeFileSync(elsewhere, JSON.stringify(credential), { mode: DATA_FILE_MODE });
    symlinkSync(elsewhere, controlPlaneCredentialPath(store.settingsDir));

    expect(readControlPlaneCredentialState(store.settingsDir)).toEqual({
      usable: false,
      reason: 'untrusted-file',
    });
  });

  it('tightens a too-permissive file and keeps reading it', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes are a no-op on Windows, so there is nothing to tighten');
      return;
    }
    // A group-readable credential is usually an editor or a `cp`. Refusing
    // would strand a machine that is legitimately attached, so the file is
    // repaired instead — and the repair is the assertion.
    mkdirSync(store.settingsDir, { recursive: true });
    const file = controlPlaneCredentialPath(store.settingsDir);
    writeFileSync(file, JSON.stringify(credential), { mode: DATA_FILE_MODE });
    chmodSync(file, 0o644);

    const state = readControlPlaneCredentialState(store.settingsDir, connection);
    expect(state.usable).toBe(true);
    expect(statSync(file).mode & 0o777).toBe(DATA_FILE_MODE);
  });
});

describe('the endpoint binding', () => {
  const store = useTempStore('cpc-binding');

  it('names both endpoints when the credential belongs to another deployment', () => {
    // The migration case: an administrator repoints `controlPlane` across a
    // fleet and cannot write this file. Every affected machine has to be able
    // to say WHICH deployment it holds a credential for, not merely that it is
    // no longer attached.
    writeControlPlaneCredential(store.settingsDir, credential);

    const moved: ControlPlaneConnection = {
      endpoint: 'https://aka.new-deployment.internal',
      attachedAt: '2026-08-24T12:00:00.000Z',
    };
    expect(readControlPlaneCredentialState(store.settingsDir, moved)).toEqual({
      usable: false,
      reason: 'endpoint-mismatch',
      credentialEndpoint: ENDPOINT,
      settingsEndpoint: 'https://aka.new-deployment.internal',
    });
  });

  it('withholds the credential from an endpoint it was not minted for', () => {
    writeControlPlaneCredential(store.settingsDir, credential);

    expect(readControlPlaneCredential(store.settingsDir, connection)).toEqual(credential);
    expect(
      readControlPlaneCredential(store.settingsDir, {
        endpoint: 'https://aka.attacker.example',
        attachedAt: connection.attachedAt,
      }),
    ).toBeNull();
  });

  it('describes the credential without a connection, and still refuses unsafe ones', () => {
    // A status surface may have no descriptor to compare against — a settings
    // file that was cleared while the credential survived. That is describable
    // without weakening the endpoint check itself.
    writeControlPlaneCredential(store.settingsDir, credential);
    expect(readControlPlaneCredentialState(store.settingsDir).usable).toBe(true);
  });
});

describe('removal', () => {
  const store = useTempStore('cpc-removal');

  it('removes the credential and reports whether there was one', () => {
    expect(removeControlPlaneCredential(store.settingsDir)).toBe(false);

    writeControlPlaneCredential(store.settingsDir, credential);
    expect(removeControlPlaneCredential(store.settingsDir)).toBe(true);
    expect(readControlPlaneCredentialState(store.settingsDir)).toEqual({
      usable: false,
      reason: 'absent',
    });
    expect(removeControlPlaneCredential(store.settingsDir)).toBe(false);
  });
});

describe('the file on disk', () => {
  const store = useTempStore('cpc-ondisk');

  it('is named where every surface expects it, and holds the key nowhere else', () => {
    writeControlPlaneCredential(store.settingsDir, credential);

    expect(controlPlaneCredentialPath(store.settingsDir)).toBe(
      join(store.settingsDir, ATTACHED_CREDENTIAL_FILENAME),
    );

    // A positive control before the absence check below: the key IS in this
    // file, on purpose, so an empty read cannot pass the next assertion
    // vacuously.
    const raw = readFileSync(controlPlaneCredentialPath(store.settingsDir), 'utf8');
    expect(raw).toContain(API_KEY);

    // …and in no OTHER file the settings dir holds.
    //
    // Every sibling is read rather than one named file. The named-file form is
    // what stood here and it measured nothing: no test in this suite writes
    // settings.json, so the read fell to its `''` fallback and `not.toContain`
    // passed against an empty string — green whatever the writer did. Reading
    // the directory also covers a file a future writer adds without anyone
    // remembering to name it here.
    // The positive control: settings.json really is there to be scanned, so an
    // empty directory cannot satisfy the loop below vacuously.
    applyOnboarding({ policy: 'warn' }, store.home);
    const after = readdirSync(store.settingsDir).filter(
      (name) => name !== ATTACHED_CREDENTIAL_FILENAME,
    );
    expect(after).toContain('settings.json');

    for (const name of after) {
      const file = join(store.settingsDir, name);
      if (!statSync(file).isFile()) continue;
      expect(readFileSync(file, 'utf8'), `${name} must not hold the credential`).not.toContain(
        API_KEY,
      );
    }
  });
});
