/**
 * `~/.aka` itself being unusable — not the store inside it.
 *
 * These faults land before SQLite is ever reached, so they arrive as Node
 * filesystem errors rather than result codes, and none of the package's
 * SQLite-shaped fail-open branches see them. `openLocalDatabase` throws, and
 * failing open is then entirely the caller's job — which is worth pinning,
 * because a caller that does not is a session running with detection off and
 * nothing said about it.
 */
import {
  accessSync,
  chmodSync,
  constants,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { dataDir } from '../../src/local-layout.ts';
import { ensureDataDirSync } from '../../src/paths.ts';
import { errorFrom } from '../helpers/errors.ts';

let parent: string;
let home: string;

beforeEach(() => {
  parent = mkdtempSync(join(tmpdir(), 'aka-fault-home-'));
  home = join(parent, '.aka');
});

afterEach(() => {
  // Widen before removing, innermost first: a directory without write
  // permission cannot have its entries unlinked, and `force` only forgives
  // ENOENT, not EACCES — so a tightened directory left behind by a failed case
  // strands the whole temp tree rather than reporting the failure. Both levels
  // are restored because cases here tighten either one.
  for (const dir of [dataDir(home), home]) {
    try {
      chmodSync(dir, 0o700);
    } catch {
      // Absent, a regular file, or a platform that never applied the mode.
    }
  }
  rmSync(parent, { recursive: true, force: true });
});

/**
 * True when this process is actually denied write access to `dir` by its mode.
 *
 * `accessSync` asks the question directly and changes nothing. Probing with a
 * `mkdir` would answer a wider one — it fails for a path that is a regular
 * file (ENOTDIR) just as readily as for one this process may not write, and
 * a case gated on that would skip on a fault it had successfully injected,
 * reporting an unexercised test as a pass. It also leaves a directory behind
 * on the success path, which is a mutation inside a predicate.
 */
function deniesWrite(dir: string): boolean {
  try {
    accessSync(dir, constants.W_OK);
    return false;
  } catch {
    return true;
  }
}

describe('a permission-denied ~/.aka', () => {
  it('refuses the open, naming the path it could not create', (ctx) => {
    mkdirSync(home, { recursive: true });
    chmodSync(home, 0o000);
    if (!deniesWrite(home)) {
      ctx.skip('the mode change does not deny access here (Windows, or running as root)');
      return;
    }

    const err = errorFrom(() => openLocalDatabase(dataDir(home)));

    expect(err).toBeDefined();
    expect((err as { code?: string }).code).toBe('EACCES');
    // The path is the whole diagnosis: the user has to be able to tell which
    // directory to fix from the message alone.
    expect(err?.message).toContain(dataDir(home));
  });

  it('stays refusing across repeated attempts', (ctx) => {
    mkdirSync(home, { recursive: true });
    chmodSync(home, 0o000);
    if (!deniesWrite(home)) {
      ctx.skip('the mode change does not deny access here (Windows, or running as root)');
      return;
    }

    // A hook fires per tool call and a dashboard request comes back on every
    // reload, so the retry is the normal case, not the exception. Nothing here
    // may be left half-created for the next attempt to trip over.
    for (let i = 0; i < 3; i += 1) {
      expect(
        (errorFrom(() => openLocalDatabase(dataDir(home))) as { code?: string } | undefined)?.code,
      ).toBe('EACCES');
    }
  });

  it('opens once the directory is readable again', (ctx) => {
    // The positive control, and the reason the refusal above is safe to fix by
    // hand: nothing about the store was damaged, only walled off.
    mkdirSync(home, { recursive: true });
    chmodSync(home, 0o000);
    if (!deniesWrite(home)) {
      ctx.skip('the mode change does not deny access here (Windows, or running as root)');
      return;
    }
    // Refused FIRST, then widened. Without this the case only shows that
    // openLocalDatabase works on a 0700 directory — which every other test
    // here already shows — and it would pass unchanged with the 0000 line
    // deleted.
    expect(errorFrom(() => openLocalDatabase(dataDir(home)))).toBeDefined();
    chmodSync(home, 0o700);

    const db = openLocalDatabase(dataDir(home));
    expect(db).toBeDefined();
    db.close();
  });

  it('is undone by ensureDataDirSync where the directory is ours to widen', (ctx) => {
    // Worth writing down because it is why the fault above needs `~/.aka`
    // itself to be denied. An owner can always chmod their own directory back,
    // and `ensureDataDirSync` does exactly that — so a merely tightened
    // *data* dir never reaches SQLite as a fault at all.
    mkdirSync(dataDir(home), { recursive: true });
    chmodSync(dataDir(home), 0o500);
    if (!deniesWrite(dataDir(home))) {
      ctx.skip('the mode change does not deny access here (Windows, or running as root)');
      return;
    }

    ensureDataDirSync(dataDir(home));

    expect(deniesWrite(dataDir(home))).toBe(false);
  });
});

describe('a ~/.aka that is a regular file', () => {
  it('refuses the open, naming the path', () => {
    writeFileSync(home, 'not a directory\n');

    const err = errorFrom(() => openLocalDatabase(dataDir(home)));

    expect(err).toBeDefined();
    // ENOTDIR is the honest report: a path component that has to be a
    // directory is not one. It is also all the caller gets — nothing in the
    // package looks at this to say WHICH component, so a reader has to work
    // that out from the path in the message.
    expect((err as { code?: string }).code).toBe('ENOTDIR');
    expect(err?.message).toContain(dataDir(home));
  });

  it('leaves the file exactly as it found it', () => {
    // The store never overwrites what it found: whatever the user actually put
    // at `~/.aka` is still theirs after a failed open, which is what makes
    // "move it aside" a safe instruction to give them.
    const original = 'not a directory — someone else owns this path\n';
    writeFileSync(home, original);

    expect(errorFrom(() => openLocalDatabase(dataDir(home)))).toBeDefined();

    expect(readFileSync(home, 'utf8')).toBe(original);
    expect(statSync(home).isFile()).toBe(true);
  });

  it('opens once the file is moved aside', () => {
    // The positive control, and the recovery a user is told to perform.
    writeFileSync(home, 'not a directory\n');
    expect(errorFrom(() => openLocalDatabase(dataDir(home)))).toBeDefined();

    rmSync(home, { force: true });

    const db = openLocalDatabase(dataDir(home));
    expect(db).toBeDefined();
    db.close();
  });
});
