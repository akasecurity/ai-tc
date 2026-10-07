import { pathToFileURL } from 'node:url';

import { AttachmentScopeEntry } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { enrollableRepoKey } from '../src/egress-wire.ts';

// What is stored for a repository a user types in by hand. Keys are compared
// byte for byte against what a checkout stamps on its events, so a key that is
// almost right is worse than none: it is stored, echoed back as enrolled, and
// matches nothing. Every spelling below is one a user can plausibly type.

const ESC = String.fromCharCode(27);
// Built from a char code: a Windows path written as a literal would be read for
// escape sequences by the tooling that writes this file.
const BACKSLASH = String.fromCharCode(92);
const KEY = 'github.com/acme/payments-api';

const ACCEPTED: [string, string, string][] = [
  ['an https clone URL', 'https://github.com/acme/payments-api', KEY],
  ['an https clone URL with .git', 'https://github.com/acme/payments-api.git', KEY],
  ['an https clone URL with a trailing slash', 'https://github.com/acme/payments-api/', KEY],
  ['a clone URL with a capitalised host', 'https://GitHub.com/acme/payments-api.git', KEY],
  ['an scp-style clone URL', 'github.com:acme/payments-api.git', KEY],
  ['an ssh:// clone URL on a port', 'ssh://github.com:2222/acme/payments-api.git', KEY],
  [
    'a self-hosted forge on a port',
    'https://git.example.com:8443/team/payments-api.git',
    'git.example.com/team/payments-api',
  ],
  [
    'an ssh config alias host',
    'github.com-work:acme/payments-api.git',
    'github.com-work/acme/payments-api',
  ],
  ['a typed canonical key', KEY, KEY],
  [
    'a typed key whose path keeps its case',
    'github.com/Acme/Payments-API',
    'github.com/Acme/Payments-API',
  ],
  ['a typed key in surrounding whitespace', `  ${KEY}  `, KEY],
  [
    'a typed key under nested groups',
    'gitlab.com/acme/platform/payments-api',
    'gitlab.com/acme/platform/payments-api',
  ],
  [
    'a typed key on a host given as an address',
    '10.0.0.5/team/payments-api',
    '10.0.0.5/team/payments-api',
  ],
];

const REFUSED: [string, string][] = [
  // Almost canonical, typed: refused rather than repaired, so the user sees the
  // difference instead of a silent rewrite.
  ['a typed key with a capitalised host', 'GitHub.com/Org/Repo'],
  ['a typed key with a trailing slash', `${KEY}/`],
  ['a typed key with a .git suffix', `${KEY}.git`],
  // A host and one segment names an owner, not a repository.
  ['a typed host and one path segment', 'github.com/org'],
  ['a clone URL with one path segment', 'https://github.com/org'],
  ['a host alone', 'github.com'],
  // A trailing-dot host names the same host, so it would be a second key for it.
  ['a typed trailing-dot host', 'github.com./acme/payments-api'],
  ['a clone URL with a trailing-dot host', 'https://github.com./acme/payments-api.git'],
  // A typed relative path reads as a key whose host is `.`, `..` or `-`.
  ['a host of two dots', '../acme/payments-api'],
  ['a host of one dot', './acme/payments-api'],
  ['a relative path', './payments-api'],
  ['a parent-relative path', '../payments-api'],
  ['a host that is a hyphen', '-/acme/payments-api'],
  ['a host label that begins with a hyphen', '-github.com/acme/payments-api'],
  ['an empty path segment', 'github.com/acme//payments-api'],
  ['a dot-dot path segment', 'github.com/acme/../payments-api'],
  // Paths and local URLs: a repository with no shared identity is never enrolled.
  ['an absolute POSIX path', '/home/dev/payments-api'],
  ['a Windows path', ['C:', 'Users', 'dev', 'payments-api'].join(BACKSLASH)],
  ['a file URL', pathToFileURL('/srv/git/payments-api.git').href],
  ['a query in the path', `${KEY}?ref=main`],
  ['an empty string', ''],
  ['only whitespace', '   '],
  ['a control character', `${KEY}${ESC}[2J`],
  ['a key longer than a scope entry may hold', `github.com/acme/${'x'.repeat(600)}`],
];

describe('enrollableRepoKey', () => {
  it.each(ACCEPTED)('accepts %s', (_label, input, key) => {
    expect(enrollableRepoKey(input)).toBe(key);
  });

  it.each(REFUSED)('refuses %s', (_label, input) => {
    expect(enrollableRepoKey(input)).toBeUndefined();
  });

  it.each(ACCEPTED)(
    'gives, for %s, a key that is itself accepted unchanged and can be stored',
    (_l, input) => {
      // Idempotent, and inside the scope entry's own rule, so a key this returns
      // is one a second typing of it would accept again and the settings file
      // can hold.
      const key = enrollableRepoKey(input);
      expect(key).toBeDefined();
      expect(enrollableRepoKey(key ?? '')).toBe(key);
      expect(
        AttachmentScopeEntry.safeParse({
          kind: 'repo',
          identity: key,
          enrolledAt: '2026-10-07T09:00:00.000Z',
        }).success,
      ).toBe(true);
    },
  );
});
