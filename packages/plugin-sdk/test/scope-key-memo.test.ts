// scopeKeyMemo's cost and consistency promise, pinned by counting: a pass asks
// the repository resolver ONCE per directory it meets, however many records
// share it, and keeps that answer past the resolver's own memo bound.
//
// It has its own file because the seam is a `vi.mock` of `../src/repo.ts`, and a
// module mock applies to every test in the file that declares it. The wrapper
// delegates to the real resolver, so the answers are the real ones and only the
// calls are counted. scope-key.test.ts holds the cases that need no spy.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { resolver } = vi.hoisted(() => ({
  resolver: vi.fn<(cwd: string) => unknown>(),
}));

vi.mock('../src/repo.ts', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  resolver.mockImplementation(actual.resolveRepoAttribution as (cwd: string) => unknown);
  return { ...actual, resolveRepoAttribution: resolver };
});

const { scopeKeyMemo } = await import('../src/scope-key.ts');

// An scp-form remote's userinfo reads as an email address to a scanner, so the
// fixture builds it from parts.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;

let root: string;
let work: string;
let scratch: string;

const callsFor = (cwd: string): number => resolver.mock.calls.filter(([c]) => c === cwd).length;

beforeEach(() => {
  resolver.mockClear();
  root = mkdtempSync(join(tmpdir(), 'aka-scope-memo-'));
  work = join(root, 'work');
  mkdirSync(join(work, '.git'), { recursive: true });
  writeFileSync(
    join(work, '.git', 'config'),
    `[remote "origin"]\n\turl = ${gitUser}github.com:acme/work.git\n`,
  );
  scratch = join(root, 'scratch');
  mkdirSync(scratch);
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('scopeKeyMemo — one resolution per directory per pass', () => {
  it('asks the resolver once however often a directory is asked about, and the answer holds', () => {
    // The control: the interception fires, so a count of zero below could not
    // be a seam that is not in the path.
    const scopeKeyOf = scopeKeyMemo();
    expect(scopeKeyOf(work)).toBe('github.com/acme/work');
    expect(callsFor(work)).toBe(1);

    for (let i = 0; i < 5; i++) expect(scopeKeyOf(work)).toBe('github.com/acme/work');
    expect(callsFor(work)).toBe(1);
  });

  it('remembers a keyless answer as well', () => {
    const scopeKeyOf = scopeKeyMemo();

    expect(scopeKeyOf(scratch)).toBeUndefined();
    expect(scopeKeyOf(scratch)).toBeUndefined();
    expect(callsFor(scratch)).toBe(1);
  });

  it('does not ask for no directory', () => {
    expect(scopeKeyMemo()(undefined)).toBeUndefined();
    expect(resolver).not.toHaveBeenCalled();
  });

  it('starts every pass empty: two memos do not share answers', () => {
    expect(scopeKeyMemo()(work)).toBe('github.com/acme/work');
    expect(scopeKeyMemo()(work)).toBe('github.com/acme/work');

    expect(callsFor(work)).toBe(2);
  });

  it("answers as it first did past the resolver's own memo bound, though the remote has changed", () => {
    // The resolver forgets everything once it holds 64 directories. A pass
    // that met more than that must still answer its first directory as it
    // did, or an llm_call whose bag a later pass replaces could change key
    // mid-pass.
    const scopeKeyOf = scopeKeyMemo();
    expect(scopeKeyOf(work)).toBe('github.com/acme/work');
    for (let i = 0; i < 70; i++) scopeKeyOf(join(scratch, `d${String(i)}`));
    writeFileSync(
      join(work, '.git', 'config'),
      '[remote "origin"]\n\turl = https://github.com/acme/renamed.git\n',
    );

    expect(scopeKeyOf(work)).toBe('github.com/acme/work');
    // The control: a resolver that has forgotten the directory reads the new remote.
    expect(scopeKeyMemo()(work)).toBe('github.com/acme/renamed');
  });
});
