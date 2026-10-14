import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { canonicalRepoUrl } from '@akasecurity/persistence';
import { resolveRepo } from '@akasecurity/plugin-sdk';
import type { IngestEvent } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { withScopedRepo } from '../../src/attached/scoped-repo.ts';

// The userinfo in an scp-style remote (`<user>@<host>:path`) reads as an email
// address to a scanner, so every fixture that needs one builds it from parts,
// as persistence's egress-wire test does.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;

const EVENT: IngestEvent = {
  id: 'e1',
  sourceTool: 'claude-code',
  kind: 'prompt',
  occurredAt: '2026-08-19T10:00:00.000Z',
  contentHash: 'hash-e1',
  content: 'content of e1',
};

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-scoped-repo-'));
});
afterEach(() => {
  removeTree(dir);
});

/** A checkout whose only remote is `url`, laid out the way `resolveRepo` reads one. */
function checkoutWithRemote(url: string): string {
  const root = join(dir, 'checkout');
  mkdirSync(join(root, '.git'), { recursive: true });
  writeFileSync(join(root, '.git', 'config'), `[remote "origin"]\n\turl = ${url}\n`);
  return root;
}

describe('withScopedRepo', () => {
  it.each([
    ['github.com/org/work-repo', 'work-repo'],
    ['gitlab.com/group/sub/project', 'project'],
    ['github.com/Org/Repo', 'Repo'],
  ])('names the key %s by its last path segment, %s', (key, repo) => {
    expect(withScopedRepo(EVENT, key).metadata?.repo).toBe(repo);
  });

  it("replaces the producer's slug where it stands, and leaves every other field alone", () => {
    const event: IngestEvent = {
      ...EVENT,
      metadata: { repo: 'personal-repo', sessionId: 's1', filePath: '/w/src/app.ts' },
    };
    expect(JSON.stringify(withScopedRepo(event, 'github.com/org/work-repo'))).toBe(
      JSON.stringify({
        ...EVENT,
        metadata: { repo: 'work-repo', sessionId: 's1', filePath: '/w/src/app.ts' },
      }),
    );
  });

  it('adds a slug when the producer set none, and metadata when there was none', () => {
    const noSlug: IngestEvent = { ...EVENT, metadata: { sessionId: 's1' } };
    expect(withScopedRepo(noSlug, 'github.com/org/work-repo').metadata).toEqual({
      sessionId: 's1',
      repo: 'work-repo',
    });
    expect(withScopedRepo(EVENT, 'github.com/org/work-repo').metadata).toEqual({
      repo: 'work-repo',
    });
  });

  it('never writes to the event it is given', () => {
    const metadata = Object.freeze({ repo: 'personal-repo', sessionId: 's1' });
    const event = Object.freeze({ ...EVENT, metadata });
    const out = withScopedRepo(event, 'github.com/org/work-repo');
    expect(out).not.toBe(event);
    expect(out.metadata?.repo).toBe('work-repo');
    expect(event.metadata.repo).toBe('personal-repo');
  });

  // Never a key `canonicalRepoUrl` returns, which always carries a non-empty
  // path. Total all the same: such a key sends no slug, never the producer's.
  it("drops the producer's slug for a key with no segment to name", () => {
    const slugged: IngestEvent = { ...EVENT, metadata: { repo: 'personal-repo', sessionId: 's1' } };
    expect(withScopedRepo(slugged, '///').metadata).toEqual({ sessionId: 's1' });
    expect(withScopedRepo(EVENT, '///')).toBe(EVENT);
  });
});

// The claim the rewrite rests on, pinned: on a checkout whose remote IS the
// keyed repository, the slug the producer already sends (`resolveRepo`) and the
// key's last segment are one value, so the rewrite changes nothing there.
describe("the key's last segment is resolveRepo's slug on the keyed checkout", () => {
  it.each([
    `${gitUser}GitHub.com:org/repo.git`,
    `https://user${AT}github.com:443/org/repo/`,
    `ssh://${gitUser}github.com/org/repo.git`,
    'https://github.com/org/repo',
    'https://github.com/Org/Repo',
    'https://gitlab.com/group/sub/project.git',
  ])('%s', (url) => {
    const key = canonicalRepoUrl(url);
    const slug = resolveRepo(checkoutWithRemote(url));
    expect(key).toBeDefined();
    expect(slug).toBeDefined();
    expect(withScopedRepo(EVENT, key ?? '').metadata?.repo).toBe(slug);
  });

  // Where the two derivations part, the key's segment is what is sent: it names
  // the repository that was enrolled. Neither is a remote a forge hands out.
  it.each([
    ['a trailing slash after .git', 'repo', 'repo.git', 'https://github.com/org/repo.git/'],
    ['a colon in the last path segment', 're:po', 'po', 'https://example.test/org/re:po'],
  ])('%s: the key gives %s where resolveRepo gives %s', (_label, fromKey, fromSlug, url) => {
    expect(resolveRepo(checkoutWithRemote(url))).toBe(fromSlug);
    expect(withScopedRepo(EVENT, canonicalRepoUrl(url) ?? '').metadata?.repo).toBe(fromKey);
  });
});

// A web chat account key names no repository. Taken as a key, its last segment
// would be the whole key, and the account's id would leave as the slug.
describe('an account key', () => {
  const ACCOUNT = 'claude:0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b';
  const WEB: IngestEvent = { ...EVENT, sourceTool: 'claude-ai' };

  it('sends no slug and does not echo the key', () => {
    const sent = withScopedRepo(WEB, ACCOUNT);
    expect(sent.metadata?.repo).toBeUndefined();
    expect(JSON.stringify(sent)).not.toContain('0f1e2d3c');
  });

  it("drops a producer's slug rather than sending it under the account", () => {
    const sent = withScopedRepo({ ...WEB, metadata: { repo: 'side-project' } }, ACCOUNT);
    expect(sent.metadata?.repo).toBeUndefined();
  });

  // The control: a repository key still names its repository.
  it('leaves a repository key naming its repository', () => {
    expect(withScopedRepo(EVENT, 'github.com/acme/payments-api').metadata?.repo).toBe(
      'payments-api',
    );
  });
});
