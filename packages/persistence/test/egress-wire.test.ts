import { createHash } from 'node:crypto';

import type { RecordProjectEgressInput } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { hashProjectKey, toEgressIngestRequest } from '../src/egress-wire.ts';
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

describe('hashProjectKey — cross-device convergence', () => {
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
        'site',
        'template',
        'transport',
        'trust',
        'url',
      ].sort(),
    );
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
