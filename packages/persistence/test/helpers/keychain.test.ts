import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

import { afterEach, describe, expect, it } from 'vitest';

import { errorFrom } from './errors.ts';
import { createDisposableKeychain, type DisposableKeychain } from './keychain.ts';

const SECURITY_BIN = '/usr/bin/security';
const SERVICE = `aka-harness-${randomBytes(6).toString('hex')}`;
const ACCOUNT = 'keyring';

/** A distinct high-entropy sentinel per call, so no assertion can pass on a stale item. */
const sentinel = (): string => randomBytes(24).toString('base64url');

const live: DisposableKeychain[] = [];

/** Creates a keychain and registers its teardown, or hands back the reason it could not. */
function open(): DisposableKeychain {
  const kc = createDisposableKeychain();
  if (kc.usable) live.push(kc);
  return kc;
}

// Drains the list, so a test that tore its own keychain down early is not
// cleaned up twice — and a test that opened two gets both removed regardless.
afterEach(() => {
  for (const kc of live.splice(0)) kc.cleanup();
});

describe('createDisposableKeychain', () => {
  // Driven with an explicit platform so this branch runs on macOS too. A test
  // that only ever runs on the platform it is describing proves nothing about
  // the other one, and this is the branch every non-darwin runner takes.
  it('reports a reason rather than throwing where there is no keychain', () => {
    const kc = createDisposableKeychain('linux');

    expect(kc.usable).toBe(false);
    expect(kc.reason).toMatch(/macOS-only/);
    expect(kc.reason).toContain('linux');
  });

  // `exec` on an unusable keychain must throw rather than silently no-op: a
  // no-op would let every absence assertion below pass without a keychain
  // existing at all.
  it('refuses to exec when it is unusable', () => {
    const kc = createDisposableKeychain('win32');

    const err = errorFrom(() => kc.exec(['find-generic-password']));

    expect(err).toBeDefined();
    expect(err?.message).toMatch(/unusable/);
  });

  it('creates a usable keychain on macOS', (ctx) => {
    const kc = open();
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');

    expect(kc.path).not.toBe('');
    expect(kc.path).toMatch(/\.keychain$/);
  });

  // The empirical question the whole approach rests on: an item added the way
  // the PRODUCT adds one — no `-A`, so the item's ACL carries only the default
  // trust in its creating application — must read back without a dialog.
  // `security` is both creator and reader, so the default trust should cover
  // it. If it does not, this times out and reports as a skip with a reason
  // rather than hanging, and keychain custody cannot be tested against the real
  // binary without loosening the item's ACL.
  it('round-trips an item added the way the product adds one', (ctx) => {
    const kc = open();
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');
    const value = sentinel();

    kc.exec(['add-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w', value]);
    const read = kc.exec(['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w']);

    expect(read.trim()).toBe(value);
  });

  // The property that makes this harness safe to run on a developer's machine.
  // The positive control is not decoration: without it, an `exec` that wrote
  // nothing at all would satisfy the absence assertion below.
  it('keeps the item out of the default login keychain', (ctx) => {
    const kc = open();
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');
    const value = sentinel();

    kc.exec(['add-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w', value]);

    // positive control — it really is in the throwaway keychain
    expect(kc.exec(['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w']).trim()).toBe(
      value,
    );

    // …and nowhere in the default search list. No trailing keychain here, so
    // `security` searches the user's own. errSecItemNotFound is exit 44.
    const err = errorFrom(() =>
      execFileSync(SECURITY_BIN, ['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 3_000,
      }),
    );

    expect(err).toBeDefined();
    expect((err as { status?: number } | undefined)?.status).toBe(44);
  });

  // What makes the assertion above non-vacuous. It reads exit 44 as "absent
  // from the keychain searched", which is worth nothing unless the SAME call
  // returns 0 when the item is present — a lookup that always failed would
  // satisfy it just as well. Proven between two disposable keychains rather
  // than by planting an item in the login keychain, which is the one place
  // this harness must never write.
  it('reads exit 44 only when the item is genuinely absent', (ctx) => {
    const withItem = open();
    const without = open();
    if (!withItem.usable || !without.usable) {
      ctx.skip(withItem.reason ?? without.reason ?? 'no disposable keychain');
    }
    const value = sentinel();

    withItem.exec(['add-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w', value]);

    // Present → exit 0 and the value back, so the lookup can succeed.
    expect(
      withItem.exec(['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w']).trim(),
    ).toBe(value);

    // Absent → the identical call shape against a keychain that never received
    // it. Only the target differs, so 44 can only be reporting absence.
    const err = errorFrom(() =>
      without.exec(['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w']),
    );

    expect(err).toBeDefined();
    expect((err as { status?: number } | undefined)?.status).toBe(44);
  });

  it('deletes the keychain on cleanup', (ctx) => {
    const kc = open();
    if (!kc.usable) ctx.skip(kc.reason ?? 'no disposable keychain');
    kc.exec(['add-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w', sentinel()]);

    kc.cleanup();

    // The keychain is gone, so the same lookup that just succeeded now fails.
    const err = errorFrom(() => kc.exec(['find-generic-password', '-s', SERVICE, '-a', ACCOUNT]));
    expect(err).toBeDefined();
  });
});
