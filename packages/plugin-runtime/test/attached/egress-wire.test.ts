import type { RecordProjectEgressInput, ResolvedEgressHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { hashProjectKey, toEgressIngestRequest } from '../../src/attached/egress-wire.ts';

const HEX_64 = /^[0-9a-f]{64}$/;

const hit = (over: Partial<ResolvedEgressHit> = {}): ResolvedEgressHit => ({
  host: 'api.stripe.com',
  kind: 'provider',
  name: 'Stripe',
  category: 'payments',
  trust: 'recognized',
  network: null,
  method: 'POST',
  transport: 'https',
  url: 'https://api.stripe.com/v1/charges',
  template: false,
  dataClass: 'customer',
  site: {
    file: 'src/billing/charge.ts',
    line: 42,
    snippet: 'const client = new Stripe(process.env.STRIPE_SECRET_KEY);',
    dynamic: false,
    vendored: false,
  },
  ...over,
});

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
    expect(JSON.stringify(payload)).not.toContain(secretSnippet);
    expect(JSON.stringify(payload)).not.toContain('STRIPE_SECRET_KEY');
  });

  it('projectKey matches the digest shape, never a path:/git: plaintext prefix', () => {
    const payload = toEgressIngestRequest(input({ projectKey: 'git:github.com/acme/widgets' }));
    expect(payload.projectKey).toMatch(HEX_64);
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain('git:');
    expect(serialized).not.toContain('path:');
  });

  it('contains no OS username substring for a path: projectKey', () => {
    const payload = toEgressIngestRequest(input({ projectKey: 'path:/Users/alice/code/widgets' }));
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain('alice');
    expect(serialized).not.toContain('/Users/alice');
  });
});
