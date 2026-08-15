import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { KeychainKeyProvider } from '../../src/vault/key-provider.ts';
import { errorFrom, rejectionFrom } from '../helpers/errors.ts';
import { createDisposableKeychain, type DisposableKeychain } from '../helpers/keychain.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

/**
 * The keychain backend driven against the REAL `/usr/bin/security`, not an
 * injected fake. Every other keychain test in this package supplies its own
 * `exec`, so nothing on the far side of that seam — the argv spelling, the exit
 * codes, the OS's own behaviour — has ever been executed.
 *
 * Everything here runs against a throwaway keychain and never the login one.
 */

// The product's own item identity, restated here on purpose rather than
// exported from the module: an independent statement of what must be written
// means a change to the constants shows up as a failure here instead of
// silently moving where the vault key lives.
const SERVICE = 'aka-vault';
const ACCOUNT = 'keyring';

/** The provider's own source, for the two properties no behavioural test can reach. */
const providerSource = (): string =>
  readFileSync(fileURLToPath(new URL('../../src/vault/key-provider.ts', import.meta.url)), 'utf8');

describe('KeychainKeyProvider against the real security binary', () => {
  let keysDir: string;
  let kc: DisposableKeychain;

  beforeEach(() => {
    keysDir = mkdtempSync(join(tmpdir(), 'aka-vault-real-'));
    kc = createDisposableKeychain();
  });

  afterEach(() => {
    kc.cleanup();
    rmSync(keysDir, { recursive: true, force: true });
  });

  // AC1: a full custody lifecycle through the real binary — mint, read back,
  // rotate, and still serve the epoch that was rotated away from.
  it('mints, reads back, rotates, and still serves the earlier epoch', async (ctx) => {
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');
    const provider = new KeychainKeyProvider(keysDir, undefined, kc.path);

    const first = await provider.loadOrCreate();
    expect(first.version).toBe(1);
    expect(first.material.length).toBeGreaterThan(0);

    // A second load must READ the stored keyring, not mint a fresh one — a
    // re-mint here would orphan every ciphertext written under the first.
    const again = await provider.loadOrCreate();
    expect(again.version).toBe(1);
    expect(again.material.equals(first.material)).toBe(true);

    const rotated = await provider.rotate();
    expect(rotated.version).toBe(2);
    expect(rotated.material.equals(first.material)).toBe(false);

    // The whole point of retaining epochs: anything sealed under version 1 is
    // still openable after the rotation.
    const earlier = await provider.materialFor(1);
    expect(earlier.material.equals(first.material)).toBe(true);
  });

  // Without this the test above is vacuous about isolation: if the seam did
  // nothing, the write would land in the DEFAULT keychain and every read would
  // find it there, so the round-trip would pass while the developer's login
  // keychain quietly accumulated vault keys. Asserting the item is in the
  // throwaway keychain fails in exactly that case — and touches no other one.
  it('routes the write to the keychain it was given', async (ctx) => {
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');
    const provider = new KeychainKeyProvider(keysDir, undefined, kc.path);

    await provider.loadOrCreate();

    const stored = kc.exec(['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w']);
    expect(stored.trim()).toMatch(/^\{"current":\s*1\b/);
  });

  // AC2: the read path branches on exit 44 to tell "nothing stored yet" from
  // "the read failed". That number is the OS's, not ours, so it is MEASURED
  // here — if a future macOS moved it, every read would start being taken for
  // absence and mint over a live keyring. This turns that into a red test.
  it('measures the item-not-found status the read path branches on', async (ctx) => {
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');

    const err = errorFrom(() =>
      kc.exec(['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w']),
    );

    expect(err).toBeDefined();
    expect((err as { status?: number } | undefined)?.status).toBe(44);

    // …and the provider really does read that status as absence, so the number
    // above is pinned to the behaviour rather than sitting beside it.
    const provider = new KeychainKeyProvider(keysDir, undefined, kc.path);
    expect((await provider.loadOrCreate()).version).toBe(1);
  });

  // AC3's boundary, measured rather than assumed — and it is narrower than it
  // looks. A keychain that is GONE answers 44, exactly as an empty one does, so
  // at the exit-code level "no such keychain" and "no such item" are the same
  // answer and the read path mints. That is what the 44 branch really covers.
  //
  // The dangerous case — a LOCKED keychain — is not reachable this way at all:
  // measured, `security` does not fail on one, it blocks on a GUI unlock dialog
  // with no exit status and no stderr. Nothing on the calling thread can
  // interrupt that, so no exit-code branch can catch it and the call TIMEOUT is
  // the only thing that converts it into a failure. Driving it from a suite
  // would raise that dialog on every run, which CI has nobody to answer.
  //
  // The refusal branch itself — any non-44 status must throw rather than read as
  // absence — is exercised against an injected status in key-provider.test.ts.
  it('cannot tell a missing keychain from an empty one, and mints', async (ctx) => {
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');
    const provider = new KeychainKeyProvider(keysDir, undefined, kc.path);
    const minted = await provider.loadOrCreate();
    expect(minted.version).toBe(1);

    kc.cleanup();

    const err = errorFrom(() =>
      kc.exec(['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w']),
    );
    expect(err).toBeDefined();
    expect((err as { status?: number } | undefined)?.status).toBe(44);
  });

  // AC5 at the real-binary level: a failed write must describe itself with exit
  // metadata and nothing else. The keyring rode stdin, and neither the message
  // nor the stack may carry it back out.
  it('describes a failed write without echoing the keyring', async (ctx) => {
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');
    const minted = await new KeychainKeyProvider(keysDir, undefined, kc.path).loadOrCreate();
    // BOTH encodings. The keyring stores base64 but the write path sends hex,
    // so checking one form only would sail straight past a leak of the other —
    // and the hex is the form that actually crosses to the child.
    const key = minted.material.toString('base64');
    const keyHex = minted.material.toString('hex');

    // Reads still go to the real binary; only the WRITE is refused. Rotation
    // retains earlier epochs, so the payload this write carries contains the
    // key minted above — the assertion below therefore names the value the
    // failing call actually handled, rather than one it never saw. Deleting the
    // keychain instead would send rotate() down the MINT path, where the
    // payload is a fresh key and every absence assertion holds vacuously.
    const refuseWrites = (args: string[], stdin?: string): string => {
      if (stdin !== undefined) throw Object.assign(new Error('write refused'), { status: 45 });
      return kc.exec(args);
    };
    const provider = new KeychainKeyProvider(keysDir, refuseWrites);

    const err = await rejectionFrom(provider.rotate());

    expect(err).toBeDefined();
    expect(err?.message).toMatch(/keychain write failed/);
    for (const form of [key, keyHex]) {
      expectNoEchoOf(err?.message, form);
      expectNoEchoOf(err?.stack, form);
    }
    // The third shape, and the one the two above cannot see: the payload
    // crosses to the child HEX-ENCODED, so a leak of the write line carries the
    // key as hex-of-base64 — matching neither the base64 nor the raw-bytes-hex
    // form. Hex is trivially decodable, so that is a disclosure like any other.
    // Any long hex run in a message whose legitimate content is `exit 45` is
    // the payload.
    expect(err?.message).not.toMatch(/[0-9a-f]{64}/);
  });

  // AC4: a keychain item that is not a keyring must throw, not be re-minted
  // over. Driven through the KEYCHAIN path deliberately — the corrupt-item case
  // was only ever covered for file custody, where a different parse reaches it.
  it('throws on a corrupt item rather than re-minting over it', async (ctx) => {
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');
    // Valid JSON, invalid keyring — so the refusal comes from the keyring parse
    // itself and its wording is stable, rather than from JSON.parse.
    const junk = '{"current":"not-a-number","keys":{}}';
    kc.exec(['add-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w', junk]);
    const provider = new KeychainKeyProvider(keysDir, undefined, kc.path);

    const err = await rejectionFrom(provider.loadOrCreate());

    expect(err).toBeDefined();
    // The positive control, and the half that carries the property: assert WHY
    // it refused. Without it a provider that swallowed the parse error still
    // passes — it throws anyway, because the plain `add` then collides with the
    // existing item, and the assertion below still holds because that add
    // failed. Both halves stay green while the guard is gone.
    expect(err?.message).toMatch(/not a usable keyring/);

    // …and the corrupt item is untouched: nothing was minted over it.
    expect(kc.exec(['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w']).trim()).toBe(
      junk,
    );
  });

  // A keyring TRUNCATED mid-value is what a partial write leaves behind, and it
  // reaches the refusal through JSON.parse rather than the keyring checks.
  //
  // The absence half here is a REGRESSION guard, not a demonstrated fix: V8's
  // parse errors were measured and carry a position, not a snippet, so nothing
  // echoes today. What it forbids is the realistic next edit — interpolating
  // the body itself "so the user can see what was stored" — which would put the
  // whole keyring in the message. That mutation reddens this; passing V8's own
  // message through does not, because there is nothing in it to catch.
  it('refuses a truncated keyring without quoting it back', async (ctx) => {
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');
    const secret = randomBytes(32).toString('base64');
    // A real keyring, cut off mid-value — exactly what a partial write leaves.
    const truncated = `{"current":1,"keys":{"1":"${secret}`;
    kc.exec(['add-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w', truncated]);
    const provider = new KeychainKeyProvider(keysDir, undefined, kc.path);

    const err = await rejectionFrom(provider.loadOrCreate());

    expect(err).toBeDefined();
    expect(err?.message).toMatch(/not a usable keyring/);
    expectNoEchoOf(err?.message, secret);
    expectNoEchoOf(err?.stack, secret);
  });
});

// These need no keychain: the exec is injected, or the subject is the source
// itself. Kept out of the suite above so they mint no throwaway keychain.
describe('KeychainKeyProvider when security cannot be run', () => {
  let keysDir: string;

  beforeEach(() => {
    keysDir = mkdtempSync(join(tmpdir(), 'aka-vault-nosec-'));
  });

  afterEach(() => {
    rmSync(keysDir, { recursive: true, force: true });
  });

  // AC7: an absent binary must say which backend failed. A bare ENOENT reads as
  // a missing FILE and sends the reader looking for the wrong thing.
  it('names the backend rather than surfacing a bare ENOENT', async () => {
    const absent = (): never => {
      throw Object.assign(new Error('spawn /usr/bin/security ENOENT'), { code: 'ENOENT' });
    };
    const provider = new KeychainKeyProvider(keysDir, absent);

    const err = await rejectionFrom(provider.loadOrCreate());

    expect(err).toBeDefined();
    expect(err?.message).toMatch(/keychain read failed/);
    expect(err?.message).toContain('ENOENT');
  });

  // AC7, second half: the binary is spawned by ABSOLUTE path. A bare name is
  // resolved through PATH, where anything earlier on it wins — and this call
  // hands over the vault key, so the program on the other end is not a detail.
  it('spawns an absolute path, never a bare name resolved from PATH', () => {
    expect(providerSource()).toContain("execFileSync('/usr/bin/security'");
    expect(providerSource()).not.toMatch(/execFileSync\(\s*['"`]security['"`]/);
  });

  // The bound on a LOCKED keychain, and the only one there is. `security` does
  // not fail on one — measured, it blocks on a GUI unlock dialog with no exit
  // status and no stderr — so no exit-code branch can catch it and nothing on
  // the calling thread can interrupt it. Without this timeout loadOrCreate()
  // blocks for ever: the hook blows its harness budget and fails open, letting
  // the tool call through unscanned, and the CLI and dashboard action wedge.
  //
  // Asserted against the source because the failure cannot be provoked from a
  // suite: driving a real locked keychain raises that dialog on every run, and
  // an injected exec bypasses runSecurity, which is where the bound lives. A
  // behavioural test is what this would rather be; there is no safe one.
  it('bounds every security call, well inside the plugin harness budget', () => {
    const source = providerSource();

    const declared = /const SECURITY_TIMEOUT_MS = ([\d_]+);/.exec(source);
    expect(declared).not.toBeNull();
    const ms = Number(declared?.[1]?.replaceAll('_', ''));
    expect(Number.isFinite(ms)).toBe(true);
    expect(ms).toBeGreaterThan(0);
    // Under the 10s a Claude Code hook gets, so the read fails and is handled
    // rather than the whole hook being killed mid-call.
    expect(ms).toBeLessThan(10_000);

    // …and it is actually applied, not merely declared.
    expect(source).toMatch(/timeout: SECURITY_TIMEOUT_MS/);
  });

  // The interactive line is whitespace-separated, so a keychain path carrying a
  // quote or a line break would re-tokenize it and could write the keyring
  // somewhere unintended. Refused rather than escaped, and the refusal must
  // reach the caller intact rather than being reported as a write failure.
  it('refuses a keychain path that would break the interactive command line', async () => {
    const notFound = (): never => {
      throw Object.assign(new Error('no such item'), { status: 44 });
    };
    const provider = new KeychainKeyProvider(keysDir, notFound, "/tmp/quote'in-path.keychain");

    const err = await rejectionFrom(provider.loadOrCreate());

    expect(err).toBeDefined();
    expect(err?.message).toMatch(/quote or line break/);
  });
});
