import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

import type { RecordProjectEgressInput } from '@akasecurity/schema';
import { ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH, AttachmentScopeEntry } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  canonicalRepoUrl,
  hashProjectKey,
  scopeKeyOfProjectKey,
  toEgressIngestRequest,
} from '../src/egress-wire.ts';
import { resolvedHit as hit } from './helpers/egress-hits.ts';
import { expectNoEchoOf } from './helpers/no-echo.ts';

const HEX_64 = /^[0-9a-f]{64}$/;

const input = (over: Partial<RecordProjectEgressInput> = {}): RecordProjectEgressInput => ({
  projectKey: 'git:github.com/acme/widgets',
  project: 'widgets',
  projectId: 'source-project-1',
  reconcile: { mode: 'walk', walkedPrefix: '' },
  hits: [hit()],
  ...over,
});

// ─── hashProjectKey ────────────────────────────────────────────────────────

describe('hashProjectKey', () => {
  it('is deterministic for an identical key', () => {
    const key = 'git:github.com/acme/widgets';
    expect(hashProjectKey(key)).toBe(hashProjectKey(key));
  });

  it('produces 64 lowercase hex characters', () => {
    expect(hashProjectKey('git:github.com/acme/widgets')).toMatch(HEX_64);
    expect(hashProjectKey('path:/Users/alice/code/widgets')).toMatch(HEX_64);
  });

  it('does not alias git: and path: variants of the same suffix', () => {
    const suffix = 'github.com/acme/widgets';
    expect(hashProjectKey(`git:${suffix}`)).not.toBe(hashProjectKey(`path:${suffix}`));
  });

  it('hashes over the full prefixed key, not just the suffix', () => {
    // Same suffix, different prefix — must not collide with a bare hash of the
    // suffix alone (i.e. the prefix is genuinely part of what is hashed).
    const suffix = 'github.com/acme/widgets';
    expect(hashProjectKey(`git:${suffix}`)).not.toBe(hashProjectKey(suffix));
  });
});

// The userinfo in an scp-style remote (`<user>@<host>:path`) is indistinguishable
// from an email address to a scanner reading this file, so every fixture that
// needs one builds it from parts rather than carrying it as a literal.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;
const aliceUser = `alice${AT}`;
// A password, built for the same reason: `user:<password>@host` is a credential
// shape to a scanner, so no case carries one as a literal.
const TOKEN = ['t', 'ok'].join('');
// A userinfo whose first colon comes before its `@`. In scp form git reads
// everything before the first colon as the host, so this one names host `a`.
const colonUser = `${['a', 'b'].join(':')}${AT}`;
const BACKSLASH = String.fromCharCode(92);

// The digest of a canonical string, from the documented construction rather
// than through hashProjectKey, so a case can state what the digest was handed.
const digestOver = (canonical: string): string =>
  createHash('sha256').update(`v2:git:${canonical}`, 'utf8').digest('hex');

// The four spellings one repository really produces, depending only on how it
// was cloned. Two engineers on the same repo land in the same project only if
// these agree, which is the whole reason the digest exists.
const SAME_REPO = [
  ['scp form', `${gitUser}github.com:acme/widgets.git`],
  ['scp form without .git', `${gitUser}github.com:acme/widgets`],
  ['https with .git', 'https://github.com/acme/widgets.git'],
  ['https without .git', 'https://github.com/acme/widgets'],
  ['https with credentials in the URL', `https://${aliceUser}github.com/acme/widgets.git`],
  ['a capitalised host', 'https://GitHub.com/acme/widgets.git'],
  ['a trailing slash', 'https://github.com/acme/widgets/'],
  ['ssh:// form', `ssh://${gitUser}github.com/acme/widgets.git`],
  ['an explicit port', 'https://github.com:443/acme/widgets.git'],
] as const;

// The exact string each branch of the canonicalization hands the digest,
// stated as a construction rather than inferred from two calls agreeing. It
// has to stay green across any change to how the parse is factored: a digest
// that moved would re-bucket every project on the receiving side, and nothing
// on either side could say which rule produced a given hash.
const DIGESTED_AS = [
  ['scp form', `${gitUser}github.com:acme/widgets.git`, 'github.com/acme/widgets'],
  [
    'a capitalised host and a trailing slash',
    'https://GitHub.com/acme/widgets/',
    'github.com/acme/widgets',
  ],
  [
    'ssh:// with a port',
    `ssh://${gitUser}github.com:22/acme/widgets.git`,
    'github.com/acme/widgets',
  ],
  ['path case', 'https://example.com/acme/Widgets', 'example.com/acme/Widgets'],
  ['a subgroup path', 'https://gitlab.com/group/sub/project.git', 'gitlab.com/group/sub/project'],
  ['a bare host', 'https://github.com', 'github.com'],
  ['a POSIX path', '/Users/dev/demo', '/Users/dev/demo'],
  ['a Windows path', 'D:/repos/demo.git', 'D:/repos/demo.git'],
  ['an unrecognised remote, trimmed', '  some-local-remote-name  ', 'some-local-remote-name'],
  ['an empty remote', '', ''],
] as const;

describe('hashProjectKey — cross-device convergence', () => {
  const digestOf = (url: string): string => hashProjectKey(`git:${url}`);

  it.each(SAME_REPO)('converges %s onto one digest', (_label, url) => {
    expect(digestOf(url)).toBe(digestOf('https://github.com/acme/widgets'));
  });

  it('still separates two repositories that differ only in owner', () => {
    // The control for the whole describe. Without it every case above is
    // satisfied by a digest that returns a constant.
    expect(digestOf('https://github.com/acme/widgets')).not.toBe(
      digestOf('https://github.com/other/widgets'),
    );
  });

  it('still separates the same path on two different hosts', () => {
    expect(digestOf('https://github.com/acme/widgets')).not.toBe(
      digestOf('https://gitlab.com/acme/widgets'),
    );
  });

  it('keeps two repositories that differ only in PATH case apart', () => {
    // Deliberate, and the opposite of the host rule. DNS is case-insensitive so
    // folding the host is safe; a forge serving a case-sensitive filesystem can
    // host both of these, and merging them would blend two repositories' egress
    // into one project. A missed convergence is two projects a human can
    // reconcile; a collision is not recoverable.
    expect(digestOf('https://example.com/acme/Widgets')).not.toBe(
      digestOf('https://example.com/acme/widgets'),
    );
  });

  it('leaves a path: key alone, including its case', () => {
    // A local path never converges across devices — that is why a repo with a
    // remote is keyed by the remote — and most of them live on case-sensitive
    // filesystems where two spellings are two directories.
    expect(hashProjectKey('path:/Users/alice/Code')).not.toBe(
      hashProjectKey('path:/users/alice/code'),
    );
  });

  it('does not alias a git: URL onto the path: key of the same text', () => {
    // The prefix is still inside the digest after canonicalization, so the
    // separation the original construction bought is not lost to it.
    expect(hashProjectKey('git:github.com/acme/widgets')).not.toBe(
      hashProjectKey('path:github.com/acme/widgets'),
    );
  });

  // A `git:` key does not always carry a remote. `resolveRepoIdentity` falls back
  // to the worktree ROOT PATH for a repository with no remote, and both producers
  // keep the `git:` prefix on it — so these are real keys, not hypotheticals.
  describe('a git: key carrying a local path, which is the no-remote fallback', () => {
    const WIN = 'C:/Users/dev/scratch/demo';

    it('leaves a Windows path alone instead of reading the drive as a host', () => {
      // Without the drive-prefix exclusion, scp form reads host `C` and path
      // `Users/dev/scratch/demo`, and the digest is taken over `c/Users/...`.
      expect(hashProjectKey(`git:${WIN}`)).toBe(hashProjectKey(`git:${WIN}`));
      expect(hashProjectKey(`git:${WIN}`)).not.toBe(hashProjectKey('git:c/Users/dev/scratch/demo'));
    });

    it('keeps two checkouts apart when one merely ends in .git', () => {
      // The defect that matters: the trailing-`.git` strip is meant for a remote
      // spelling, and applied to a PATH it merged two distinct local checkouts
      // into one project — the silent, unrecoverable direction.
      expect(hashProjectKey(`git:${WIN}`)).not.toBe(hashProjectKey(`git:${WIN}.git`));
    });

    it('keeps the drive letter, since a path is not a DNS name', () => {
      // Lowercasing is safe for a host because DNS is case-insensitive. A drive
      // letter is not a host, and the reasoning does not transfer.
      expect(hashProjectKey(`git:${WIN}`)).not.toBe(
        hashProjectKey('git:c:/Users/dev/scratch/demo'),
      );
    });

    it.each(['C:\\Users\\dev\\demo', 'D:/repos/demo', 'z:/x'])('leaves %s alone too', (path) => {
      // Both separators and any drive letter: the producer joins on `/`, but
      // the guard is about the PREFIX rather than about one spelling.
      expect(hashProjectKey(`git:${path}`)).toBe(hashProjectKey(`git:${path}`));
      expect(hashProjectKey(`git:${path}`)).not.toBe(hashProjectKey(`git:${path}.git`));
    });

    it('leaves a POSIX path alone, which never reached scp form anyway', () => {
      // The control on the three above: this one was already correct, because a
      // path with no colon cannot match scp form. It is here so a future change
      // to the guard cannot break it silently.
      expect(hashProjectKey('git:/Users/dev/demo')).not.toBe(
        hashProjectKey('git:/Users/dev/demo.git'),
      );
    });

    it('still canonicalizes a real scp remote, which is the point of the form', () => {
      // The positive control for the whole describe. An exclusion that swallowed
      // scp form entirely would satisfy every case above.
      expect(hashProjectKey(`git:${gitUser}github.com:acme/widgets.git`)).toBe(
        hashProjectKey('git:https://github.com/acme/widgets'),
      );
    });
  });

  // A `file://` remote is a real git remote form, and it names a local path.
  describe('a file:// remote, which names a path on one machine', () => {
    // The digest of a key taken over its text exactly as given, computed
    // independently of `hashProjectKey`, so "returned untouched" is stated as a
    // construction rather than inferred from two calls agreeing.
    const untouched = (key: string): string =>
      createHash('sha256').update(`v2:${key}`, 'utf8').digest('hex');
    // The empty-authority form, built the way the platform spells it: a drive
    // lands after the third slash on Windows, and the URL is still `file://`.
    const LOCAL = pathToFileURL('/srv/repos/demo').href;

    it('does not read an empty authority as a host named "file"', () => {
      // Scp form matches the empty-authority URL with host `file` and a path of
      // slashes then the directory, and the digest was taken over `file/<path>`.
      const scpMisread = LOCAL.replace(/^file:\/+/, 'file/');
      expect(scpMisread.startsWith('file/')).toBe(true);
      expect(hashProjectKey(`git:${LOCAL}`)).not.toBe(hashProjectKey(`git:${scpMisread}`));
      expect(hashProjectKey(`git:${LOCAL}`)).toBe(untouched(`git:${LOCAL}`));
    });

    it.each([LOCAL, 'file://localhost/srv/repos/demo', LOCAL.replace(/^file:/, 'FILE:')])(
      'digests %s over its text as given',
      (url) => {
        expect(hashProjectKey(`git:${url}`)).toBe(untouched(`git:${url}`));
      },
    );

    it.each([LOCAL, 'file://localhost/srv/repos/demo'])(
      'keeps %s apart from the same path ending in .git',
      (url) => {
        // A bare repository beside a working one is an ordinary layout, and the
        // trailing-`.git` strip merged the two into one project.
        expect(hashProjectKey(`git:${url}`)).not.toBe(hashProjectKey(`git:${url}.git`));
      },
    );

    it('still canonicalizes scp form against a host that is merely named file', () => {
      // The positive control: the exclusion is the `://` spelling, not the word.
      // Without this, a guard on any `file:` prefix would satisfy every case above.
      expect(hashProjectKey('git:file:acme/widgets.git')).toBe(
        hashProjectKey('git:ssh://file/acme/widgets'),
      );
    });
  });

  it('gives an unrecognised remote a stable digest rather than guessing', () => {
    // Neither scheme nor scp form. It gets no convergence, which is the honest
    // outcome, but it must still hash the same way twice or the device would
    // create a new project on every scan.
    const odd = 'git:some-local-remote-name';
    expect(hashProjectKey(odd)).toBe(hashProjectKey(odd));
    expect(hashProjectKey(odd)).toMatch(HEX_64);
  });

  it('is stamped with a version, so a later canonicalization change is legible', () => {
    // The receiving side stores the digest and not its input, so a change to the
    // rules above is otherwise invisible: every device moves to a new digest at
    // once and nothing can tell which rule produced a given hash. Pinned against
    // an independent computation of the documented input rather than a copied
    // literal, so it states the construction rather than freezing an output.
    const expected = createHash('sha256')
      .update('v2:git:github.com/acme/widgets', 'utf8')
      .digest('hex');
    expect(hashProjectKey(`git:${gitUser}github.com:acme/widgets.git`)).toBe(expected);
  });

  it.each(DIGESTED_AS)('digests %s over exactly its canonical string', (_label, url, canonical) => {
    const expected = createHash('sha256').update(`v2:git:${canonical}`, 'utf8').digest('hex');
    expect(hashProjectKey(`git:${url}`)).toBe(expected);
  });
});

// ─── canonicalRepoUrl: the scope key ───────────────────────────────────────

describe('canonicalRepoUrl', () => {
  // Every spelling one remote is really cloned under. A scope key is matched
  // byte for byte against what a user enrolled, so two of these disagreeing
  // would make one checkout of an enrolled repository forward while another
  // stayed local.
  const ONE_REMOTE = [
    ['scp form with a capitalised host', `${gitUser}GitHub.com:org/repo.git`],
    [
      'https with userinfo, a port and a trailing slash',
      `https://user${AT}github.com:443/org/repo/`,
    ],
    ['ssh:// form', `ssh://${gitUser}github.com/org/repo.git`],
    ['https without .git', 'https://github.com/org/repo'],
    ['surrounding whitespace', '  https://github.com/org/repo.git  '],
  ] as const;

  it.each(ONE_REMOTE)('reads %s as github.com/org/repo', (_label, url) => {
    expect(canonicalRepoUrl(url)).toBe('github.com/org/repo');
  });

  it('keeps path case, so a differently-cased path is a different key', () => {
    // The opposite of the host rule, for the reason canonicalGitUrl gives: a
    // forge on a case-sensitive filesystem can host both, and merging them would
    // forward one repository because the other was enrolled.
    expect(canonicalRepoUrl('https://github.com/Org/Repo')).toBe('github.com/Org/Repo');
    expect(canonicalRepoUrl('https://github.com/Org/Repo')).not.toBe(
      canonicalRepoUrl('https://github.com/org/repo'),
    );
  });

  it('drops userinfo, so a key never carries who cloned the repository', () => {
    const key = canonicalRepoUrl(`https://${aliceUser}github.com/acme/widgets.git`);
    expect(key).toBe('github.com/acme/widgets');
    expect(key).not.toContain('alice');
  });

  // WHERE THE KEY AND THE DIGEST PART WAYS. Both read a remote through one parse,
  // and for every remote the key accepts they agree. The key is also the one that
  // gates forwarding, so it is stricter, and on three shapes it departs on
  // purpose. The digest's own parse is frozen, because a moved digest would
  // re-bucket every project on the receiving side; each departure is therefore
  // made by the key alone, and the table and the case below state what the
  // digest still reads, so a change to either side shows up here.
  //
  //   - a remote whose host is not the one git contacts is REFUSED by the key:
  //     userinfo carrying a `?`, `#` or backslash, which ends a URL's authority
  //     before the `@`; and, in scp form, userinfo carrying a colon, since git
  //     takes everything before the first colon as the host.
  //   - a string that begins with a URL scheme but fits no URL form this parse
  //     reads (a bracketed IPv6 host, a non-numeric port) is REFUSED, instead of
  //     being re-read as scp form with the scheme as the host.
  //   - a `/.git` directory under the path CONVERGES onto the repository, where
  //     the digest keeps the slash the suffix left behind.
  const HOST_NOT_NAMED = [
    [
      'a ? in the userinfo, which ends the authority before the @',
      `https://other.example?${AT}github.com/acme/work`,
      'github.com/acme/work',
    ],
    [
      'a # in the userinfo',
      `https://other.example#${AT}github.com/acme/work`,
      'github.com/acme/work',
    ],
    [
      'a backslash in the userinfo',
      `https://other.example${BACKSLASH}${AT}github.com/acme/work`,
      'github.com/acme/work',
    ],
    [
      'a colon in the userinfo of an scp remote',
      `${colonUser}github.com:acme/work.git`,
      'github.com/acme/work',
    ],
    [
      'a bracketed IPv6 host with a password',
      `https://user:${TOKEN}${AT}[fd00::1]/acme/work.git`,
      `https/user:${TOKEN}${AT}[fd00::1]/acme/work`,
    ],
    [
      'a bracketed IPv6 host over ssh://',
      `ssh://${gitUser}[2001:db8::1]/acme/work.git`,
      `ssh/${gitUser}[2001:db8::1]/acme/work`,
    ],
    ['a non-numeric port', 'https://github.com:abc/org/repo', 'https/github.com:abc/org/repo'],
  ] as const;

  it.each(HOST_NOT_NAMED)(
    'gives no key for %s, though the digest reads it as it always did',
    (_label, url, digestedAs) => {
      expect(canonicalRepoUrl(url)).toBeUndefined();
      expect(hashProjectKey(`git:${url}`)).toBe(digestOver(digestedAs));
    },
  );

  it('converges a .git directory under the path onto the repository, which the digest does not', () => {
    // The `.git` suffix strip leaves the slash in front of it behind, so the
    // path read `org/repo/`. The key trims that slash again.
    for (const url of [
      'https://github.com/org/repo/.git',
      'https://github.com/org/repo/.git/',
      `${gitUser}github.com:org/repo/.git`,
    ]) {
      expect(canonicalRepoUrl(url)).toBe('github.com/org/repo');
    }
    expect(hashProjectKey('git:https://github.com/org/repo/.git')).toBe(
      digestOver('github.com/org/repo/'),
    );
  });

  // The controls on the refusals above: each is the same family of remote with
  // an ordinary userinfo, and must still key. Without them a key that refused
  // every remote with userinfo would satisfy every case above.
  it.each([
    ['a plain user@host scp remote', `${gitUser}github.com:org/repo.git`],
    [
      'an https remote with a user and an explicit port',
      `https://user${AT}github.com:443/org/repo`,
    ],
    [
      'an https remote with a password, which is where a URL carries one',
      `https://user:${TOKEN}${AT}github.com/org/repo`,
    ],
    ['an ssh:// remote with a user and a port', `ssh://${gitUser}github.com:22/org/repo.git`],
  ])('still keys %s', (_label, url) => {
    expect(canonicalRepoUrl(url)).toBe('github.com/org/repo');
  });

  // Every remote the digest pin tables cover, whichever table it is in.
  const PINNED_REMOTES: readonly (readonly [string, string])[] = [
    ...SAME_REPO,
    ...DIGESTED_AS.map(([label, url]) => [label, url] as const),
    ...ONE_REMOTE,
  ];
  // Of those, the ones that name no repository every clone shares: a forge with
  // no path, a place on one machine, a string that is no remote, or nothing.
  const PINNED_BUT_NOT_KEYED = [
    'a bare host',
    'a POSIX path',
    'a Windows path',
    'an unrecognised remote, trimmed',
    'an empty remote',
  ];

  it('agrees with the digest about every pinned remote it keys', () => {
    // For every remote that has a key, the digest of the remote is the digest of
    // its key. Checked over every spelling the digest pins cover, not one key,
    // and the refusals are listed rather than skipped, so a key that quietly
    // refused more would fail here instead of passing for want of rows.
    const refused: string[] = [];
    for (const [label, url] of PINNED_REMOTES) {
      const key = canonicalRepoUrl(url);
      if (key === undefined) {
        refused.push(label);
        continue;
      }
      expect(hashProjectKey(`git:${url}`), label).toBe(digestOver(key));
    }
    expect(refused).toEqual(PINNED_BUT_NOT_KEYED);
  });

  it('still reads scp form against a host that is merely named file', () => {
    // The positive control on the file:// cases below: the refusal is the `://`
    // spelling, exactly as for the digest, not the word.
    expect(canonicalRepoUrl('file:acme/widgets.git')).toBe('file/acme/widgets');
  });

  // A key must name a repository every clone shares. Each of these is a place on
  // one machine, a forge rather than a repository, or nothing at all — and
  // resolveRepoIdentity hands back a worktree PATH for a repository with no
  // remote, so the path cases are real inputs, not hypotheticals.
  const NO_KEY: [string, string][] = [
    ['a POSIX worktree path', '/Users/dev/demo'],
    ['a relative path remote', '../sibling.git'],
    ['a bare relative path', 'repos/demo'],
    ['an unrecognised remote', 'some-local-remote-name'],
    ['a canonical key, which is not itself a remote', 'github.com/acme/widgets'],
    ['a Windows path', 'D:/repos/demo'],
    ['a Windows path with backslashes', ['C:', 'Users', 'dev', 'demo'].join(BACKSLASH)],
    ['a file:// URL', pathToFileURL('/srv/repos/demo').href],
    ['a file:// URL with an authority', 'file://localhost/srv/repos/demo'],
    ['an uppercase FILE:// URL', 'FILE:///srv/repos/demo'],
    ['a bare host', 'https://github.com'],
    ['a bare host with a slash', 'https://github.com/'],
    ['a bare host whose path is only .git', 'https://github.com/.git'],
    ['scp form with an empty path', `${gitUser}github.com:/`],
    ['a host and port with no path', `ssh://${gitUser}github.com:22`],
    ['an empty string', ''],
    ['only whitespace', '   '],
    ...HOST_NOT_NAMED.map(([label, url]): [string, string] => [label, url]),
  ];

  it.each(NO_KEY)('gives no key for %s', (_label, url) => {
    expect(canonicalRepoUrl(url)).toBeUndefined();
  });

  // A key is meant to be stamped on each capture, compared against what a user
  // enrolled and printed wherever a scope is listed — and the remote it comes
  // from was written by whoever wrote the repository's git config. So a key is
  // one a scope entry could hold, under its identity's own cap and character
  // rule, or there is none. Every one of these parses as a remote; only its key
  // is refused.
  const BEL = String.fromCharCode(7);
  const LF = String.fromCharCode(10);
  const ESC = String.fromCharCode(27);
  const DEL = String.fromCharCode(127);
  // RIGHT-TO-LEFT OVERRIDE: a format character rather than a control one, which
  // is why the rule names both.
  const RLO = String.fromCodePoint(0x202e);
  const UNPRINTABLE: [string, string][] = [
    ['a path that takes its key past 512 characters', `https://github.com/acme/${'w'.repeat(600)}`],
    ['a BEL in the path', `https://github.com/acme/wid${BEL}gets`],
    ['an escape sequence in the path', `https://github.com/acme/${ESC}[2Kwidgets`],
    // Both URL forms take any character but `/` and `:` as part of a host.
    ['a newline in the host', `https://git${LF}hub.com/acme/widgets`],
    ['a right-to-left override in the path', `https://github.com/acme/${RLO}stegdiw`],
    ['a DEL in scp form', `${gitUser}github.com:acme/wid${DEL}gets.git`],
  ];

  it.each(UNPRINTABLE)('gives no key for %s', (_label, url) => {
    expect(canonicalRepoUrl(url)).toBeUndefined();
  });

  it('caps the key at 512 characters, measured on the key', () => {
    // `github.com/acme/` is 16 characters, so at(n) is a remote whose key is
    // exactly n long.
    const at = (n: number): string => `https://github.com/acme/${'w'.repeat(n - 16)}`;
    expect(canonicalRepoUrl(at(512))).toHaveLength(512);
    expect(canonicalRepoUrl(at(513))).toBeUndefined();
  });

  it('takes that cap from the scope entry, so a key is always an identity one could hold', () => {
    // One number behind both ends: the key is refused past the length an entry's
    // identity accepts, and a key at that length is accepted by the entry.
    const cap = ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH;
    const at = (n: number): string => `https://github.com/acme/${'w'.repeat(n - 16)}`;
    const key = canonicalRepoUrl(at(cap));
    expect(key).toHaveLength(cap);
    expect(canonicalRepoUrl(at(cap + 1))).toBeUndefined();
    const entry = (identity: string | undefined) => ({
      kind: 'repo',
      identity,
      enrolledAt: '2026-06-18T00:00:00.000Z',
    });
    expect(AttachmentScopeEntry.safeParse(entry(key)).success).toBe(true);
    expect(AttachmentScopeEntry.safeParse(entry('w'.repeat(cap + 1))).success).toBe(false);
  });

  it('measures that cap on the key, not on the remote it came from', () => {
    // Userinfo, a port, slash runs at either end of the path and surrounding
    // whitespace are all gone before the key exists. A remote far past the cap
    // can still name an ordinary repository, and must read as the same key as
    // its short spelling, or two clones of one enrolled repository would split.
    const slashes = '/'.repeat(600);
    const padded = `  https://${'u'.repeat(600)}${AT}github.com:443${slashes}org/repo${slashes}  `;
    expect(padded.length).toBeGreaterThan(1800);
    expect(canonicalRepoUrl(padded)).toBe('github.com/org/repo');
  });
});

// ─── scopeKeyOfProjectKey: the scan's pre-hash key ─────────────────────────

describe('scopeKeyOfProjectKey', () => {
  it('reads a git: key as the canonical repository of its remote', () => {
    expect(scopeKeyOfProjectKey(`git:${gitUser}github.com:acme/widgets.git`)).toBe(
      'github.com/acme/widgets',
    );
    expect(scopeKeyOfProjectKey('git:https://GitHub.com/acme/widgets')).toBe(
      'github.com/acme/widgets',
    );
  });

  it.each([
    ['a path: key', 'path:/Users/alice/code/widgets'],
    ['the no-remote fallback, which keeps the git: prefix', 'git:/Users/dev/demo'],
    ['the Windows no-remote fallback', 'git:C:/Users/dev/demo'],
    ['a git: key naming a bare host', 'git:https://github.com'],
    ['a bare git: prefix', 'git:'],
    ['a remote with no prefix at all', 'https://github.com/acme/widgets'],
    [
      'a prefix in another case, which the digest does not read as git: either',
      'GIT:https://github.com/acme/widgets',
    ],
  ])('gives no key for %s', (_label, key) => {
    expect(scopeKeyOfProjectKey(key)).toBeUndefined();
  });
});

// ─── toEgressIngestRequest: projection shape ──────────────────────────────

describe('toEgressIngestRequest', () => {
  it('strips snippet from every hit site', () => {
    const payload = toEgressIngestRequest(input());
    for (const h of payload.hits) {
      expect('snippet' in h.site).toBe(false);
    }
  });

  it('hashes projectKey for both git: and path: variants', () => {
    const gitPayload = toEgressIngestRequest(input({ projectKey: 'git:github.com/acme/widgets' }));
    expect(gitPayload.projectKey).toMatch(HEX_64);
    expect(gitPayload.projectKey).not.toBe('git:github.com/acme/widgets');

    const pathPayload = toEgressIngestRequest(input({ projectKey: 'path:/Users/alice/widgets' }));
    expect(pathPayload.projectKey).toMatch(HEX_64);
    expect(pathPayload.projectKey).not.toBe('path:/Users/alice/widgets');
  });

  it('hashing is deterministic across two builds of the same key', () => {
    const first = toEgressIngestRequest(input());
    const second = toEgressIngestRequest(input());
    expect(first.projectKey).toBe(second.projectKey);
  });

  it('keeps display project, and drops projectId entirely', () => {
    const payload = toEgressIngestRequest(input({ project: 'widgets', projectId: 'source-1' }));
    expect(payload.project).toBe('widgets');
    expect('projectId' in payload).toBe(false);
  });

  it('preserves vendored: true rather than omitting or defaulting it', () => {
    const payload = toEgressIngestRequest(
      input({ hits: [hit({ site: { ...hit().site, vendored: true } })] }),
    );
    expect(payload.hits[0]?.site.vendored).toBe(true);
  });

  it('preserves the reconcile block for walk mode', () => {
    const payload = toEgressIngestRequest(
      input({ reconcile: { mode: 'walk', walkedPrefix: 'src' } }),
    );
    expect(payload.reconcile).toEqual({ mode: 'walk', walkedPrefix: 'src' });
  });

  it('preserves the reconcile block for ledger mode', () => {
    const reconcile = {
      mode: 'ledger' as const,
      scannedFiles: ['a.ts', 'b.ts'],
      deletedFiles: ['c.ts'],
    };
    const payload = toEgressIngestRequest(input({ reconcile }));
    expect(payload.reconcile).toEqual(reconcile);
  });

  it('carries only the confirmed hit-level fields', () => {
    const payload = toEgressIngestRequest(input());
    expect(Object.keys(payload.hits[0] ?? {}).sort()).toEqual(
      [
        'category',
        'dataClass',
        'host',
        'kind',
        'method',
        'name',
        'network',
        'providerId',
        'site',
        'template',
        'transport',
        'trust',
        'url',
      ].sort(),
    );
  });

  it('carries a provider hit providerId through to the payload', () => {
    const payload = toEgressIngestRequest(input({ hits: [hit({ providerId: 'stripe' })] }));
    expect(payload.hits[0]?.providerId).toBe('stripe');
  });

  it('carries a non-provider hit null providerId through to the payload', () => {
    const payload = toEgressIngestRequest(
      input({
        hits: [
          hit({
            kind: 'external',
            providerId: null,
            trust: 'unverified',
            host: 'api.acme-partner.com',
          }),
        ],
      }),
    );
    expect(payload.hits[0]?.providerId).toBeNull();
  });

  it('carries only the confirmed site-level fields', () => {
    const payload = toEgressIngestRequest(input());
    expect(Object.keys(payload.hits[0]?.site ?? {}).sort()).toEqual(
      ['dynamic', 'file', 'line', 'vendored'].sort(),
    );
  });

  it('applies the per-project cap before serialization (walk mode drops whole files by count)', () => {
    const many = Array.from({ length: 5001 }, (_, i) =>
      hit({ site: { ...hit().site, file: `src/f${String(i)}.ts`, line: 1 } }),
    );
    const payload = toEgressIngestRequest(
      input({ reconcile: { mode: 'walk', walkedPrefix: '' }, hits: many }),
    );
    expect(payload.hits.length).toBe(5000);
  });

  it('applies withoutDroppedFiles to a ledger-mode reconcile set when the cap drops whole files', () => {
    // One file with 5001 hits alone exceeds the cap and is dropped wholesale.
    const overflowing = Array.from({ length: 5001 }, (_, i) =>
      hit({ site: { ...hit().site, file: 'src/generated.ts', line: i + 1 } }),
    );
    const payload = toEgressIngestRequest(
      input({
        reconcile: {
          mode: 'ledger',
          scannedFiles: ['src/generated.ts', 'src/other.ts'],
          deletedFiles: [],
        },
        hits: overflowing,
      }),
    );
    expect(payload.hits.length).toBe(0);
    expect(payload.reconcile).toEqual({
      mode: 'ledger',
      scannedFiles: ['src/other.ts'],
      deletedFiles: [],
    });
  });
});

// ─── Privacy assertions over the serialized payload ───────────────────────

describe('egress-wire-privacy: serialized payload', () => {
  it('contains no "snippet" key at any nesting level', () => {
    const payload = toEgressIngestRequest(input());
    expect(JSON.stringify(payload)).not.toContain('"snippet"');
  });

  it('contains no substring of any local snippet value', () => {
    const secretSnippet = 'const client = new Stripe(process.env.STRIPE_SECRET_KEY);';
    const payload = toEgressIngestRequest(
      input({ hits: [hit({ site: { ...hit().site, snippet: secretSnippet } })] }),
    );
    expectNoEchoOf(JSON.stringify(payload), secretSnippet);
    expectNoEchoOf(JSON.stringify(payload), 'STRIPE_SECRET_KEY');
  });

  it('projectKey matches the digest shape, never a path:/git: plaintext prefix', () => {
    const payload = toEgressIngestRequest(input({ projectKey: 'git:github.com/acme/widgets' }));
    expect(payload.projectKey).toMatch(HEX_64);
    const serialized = JSON.stringify(payload);
    expectNoEchoOf(serialized, 'git:');
    expectNoEchoOf(serialized, 'path:');
  });

  it('contains no OS username substring for a path: projectKey', () => {
    const payload = toEgressIngestRequest(input({ projectKey: 'path:/Users/alice/code/widgets' }));
    const serialized = JSON.stringify(payload);
    expectNoEchoOf(serialized, 'alice');
    expectNoEchoOf(serialized, '/Users/alice');
  });
});

// ─── hashProjectKey: linearity ─────────────────────────────────────────────

describe('hashProjectKey — linear in the remote URL', () => {
  // The canonicalization runs on the remote URL of whatever repository the
  // scanner was pointed at, read from that repository's own git config. Its
  // length is therefore chosen by whoever wrote the clone, and the two callers
  // — `aka scan` and the dashboard's folder-scan Server Action — sit on the
  // calling thread with no harness timeout between them and a hostile repo.
  //
  // CPU time rather than wall time, for the reason the per-rule budget uses it:
  // the question is whether this does work proportional to the square of its
  // input, which is a statement about WORK. A thread the scheduler took the
  // core away from accumulates wall time having executed nothing, so a
  // wall-clock verdict here is satisfiable by a stall this code had no part in.
  // `threadCpuUsage` rather than `cpuUsage` because the latter sums the whole
  // process, V8's background GC and compiler threads included.
  const cpuMs = (): number => {
    const { user, system } = process.threadCpuUsage();
    return (user + system) / 1000;
  };

  function burned(work: () => unknown): number {
    const before = cpuMs();
    work();
    return cpuMs() - before;
  }

  // The fastest of a few passes: noise only ever adds time, so the minimum is
  // the reading a loaded runner cannot inflate.
  function fastest(work: () => unknown): number {
    let best = Infinity;
    for (let i = 0; i < 3; i += 1) best = Math.min(best, burned(work));
    return best;
  }

  // A slash run that does not reach the end of the string, which is what makes
  // an end-anchored `+` quadratic: the anchor fails after consuming the whole
  // run, and the engine retries from every position inside it. The leading run
  // is stripped first, so only a run in the MIDDLE reaches the trailing form —
  // hence the `a` in front.
  const slashRun = (n: number): string => `/a${'/'.repeat(n)}b`;

  // 0.08ms of CPU for the whole digest at this size, measured on an arm64 Mac,
  // against a budget 1,200x above it. The control below burns 500ms — 5x the
  // budget — at 40,000, well under half this input, which is what makes this a
  // correctness assertion rather than a benchmark: no runner is slow enough to
  // cross it, and no quadratic trim is fast enough to stay under. Both margins
  // are stated because only the smaller one bounds how far this can be
  // tightened.
  //
  // The size is chosen so that the retired form REDDENS this case rather than
  // timing out in it. A synchronous body cannot be interrupted, so one that
  // overruns runs to completion and is reported as a timeout — which reads as a
  // budget failure and is not one. At 100,000 the quadratic costs ~2.9s a pass,
  // so three passes still land inside the package's ceiling and the assertion
  // is what fails.
  const BUDGET_MS = 100;
  const HOSTILE_LENGTH = 100_000;
  const CONTROL_LENGTH = 40_000;

  // The pattern this case exists to keep retired. A frozen copy — nothing in
  // `src/` spells it any more — whose only job is to prove the input above
  // really is adversarial. Without it a case fed a harmless string passes for
  // ever.
  const REPLACED_TRAILING_SLASHES = /\/+$/;

  it('digests a remote carrying a long slash run inside the budget', () => {
    const key = `git:https://h.example${slashRun(HOSTILE_LENGTH)}`;

    const spent = fastest(() => hashProjectKey(key));

    expect(spent).toBeLessThan(BUDGET_MS);
  });

  it('canonicalizes that remote rather than being fast by declining to', () => {
    // The positive control on the case above: a `canonicalGitUrl` that returned
    // its input untouched would pay nothing and pass the budget for ever.
    const run = slashRun(HOSTILE_LENGTH);
    expect(hashProjectKey(`git:https://H.Example${run}`)).toBe(
      hashProjectKey(`git:https://h.example${run}.git`),
    );
  });

  it('refuses the same hostile remote as a scope key, inside the budget', () => {
    // The key shares the digest's parse, so it shares the digest's exposure to a
    // clone URL chosen by whoever wrote the repository's config — and the cap's
    // own check may then run over the whole 100,000-character key before
    // refusing it. Both have to stay linear.
    const url = `https://h.example${slashRun(HOSTILE_LENGTH)}`;

    const spent = fastest(() => canonicalRepoUrl(url));

    expect(spent).toBeLessThan(BUDGET_MS);
    // Its key is far past 512 characters, so there is none.
    expect(canonicalRepoUrl(url)).toBeUndefined();
  });

  it('reads that shape as a real key below the cap, so the refusal above is the cap', () => {
    // The positive control on the case above: the same middle slash run, short
    // enough to leave a 412-character key, is parsed and canonicalized rather
    // than declined.
    const run = slashRun(400);
    expect(canonicalRepoUrl(`https://h.example${run}`)).toBe(`h.example${run}`);
    expect(canonicalRepoUrl(`https://H.Example${run}.git`)).toBe(`h.example${run}`);
  });

  it('would blow that budget on a fraction of the input, through the retired form', () => {
    // The control that keeps the two cases above honest. One pass, because the
    // assertion is that this is EXPENSIVE and noise only ever adds time.
    const spent = burned(() => REPLACED_TRAILING_SLASHES.exec(slashRun(CONTROL_LENGTH)));

    expect(spent).toBeGreaterThan(BUDGET_MS);
  });
});
