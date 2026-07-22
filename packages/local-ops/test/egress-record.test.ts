import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { DB_FILENAME, type LocalDatabase, openLocalDatabase } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { recordProjectEgress } from '../src/egress-record.ts';
import { scanPathIntoStore } from '../src/fs-scan.ts';

const REMOTE_URL = 'https://github.com/acme/payments-api.git';

// A minimal on-disk git repo: a `.git` DIRECTORY (what the identity resolver
// detects) whose `config` carries the remote the identity is derived from.
// Omitting the remote exercises the path-shaped identity fallback.
function initRepo(root: string, remoteUrl?: string): void {
  mkdirSync(join(root, '.git'));
  writeFileSync(
    join(root, '.git', 'config'),
    remoteUrl ? `[remote "origin"]\n\turl = ${remoteUrl}\n` : '',
  );
}

// One source file whose only egress is a POST to `host`.
function writeCall(file: string, host: string): void {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `fetch('https://${host}/v1/go', { method: 'POST' });\n`);
}

// Settings under a ~/.aka-shaped base, so the toggle is read through the real
// loader rather than a hand-built object.
function writeSettings(base: string, dataSharesInPlace: boolean): void {
  mkdirSync(join(base, 'settings'), { recursive: true });
  writeFileSync(
    join(base, 'settings', 'settings.json'),
    JSON.stringify({ dataSharesInPlace }, null, 2),
  );
}

interface StoredSite {
  projectKey: string;
  project: string;
  projectId: string | null;
  file: string;
  host: string;
  method: string;
  url: string;
  vendored: number;
}

// Raw at-rest rows, straight from the store file — the assertions are on what
// actually hit disk, independent of any read port.
function storedSites(dir: string): StoredSite[] {
  const raw = new DatabaseSync(join(dir, DB_FILENAME), { readOnly: true });
  try {
    return raw
      .prepare(
        `SELECT c.project_key AS projectKey, c.project AS project, c.project_id AS projectId,
                c.file AS file, d.host AS host, e.method AS method, e.url AS url,
                c.vendored AS vendored
           FROM share_call_site c
           JOIN share_endpoint e ON e.id = c.endpoint_id
           JOIN share_destination d ON d.id = e.destination_id
          ORDER BY c.project_key, c.file, e.url`,
      )
      .all() as unknown as StoredSite[];
  } finally {
    raw.close();
  }
}

// Walk `target` and record whatever egress the walk produced — the exact
// two-call sequence the CLI and the web-ui Scan action perform.
function scanAndRecord(db: LocalDatabase, target: string, base: string) {
  const result = scanPathIntoStore(db, target, { rules: [] });
  return recordProjectEgress(db, target, result.egress, base);
}

let root: string;
let store: string;
let base: string;
let db: LocalDatabase;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-egress-'));
  store = mkdtempSync(join(tmpdir(), 'aka-egress-db-'));
  base = mkdtempSync(join(tmpdir(), 'aka-egress-home-'));
  db = openLocalDatabase(store);
});

afterEach(() => {
  db.close();
  rmSync(root, { recursive: true, force: true });
  rmSync(store, { recursive: true, force: true });
  rmSync(base, { recursive: true, force: true });
});

describe('recordProjectEgress — git project', () => {
  it('keys on the remote identity and stores repo-relative posix paths', () => {
    initRepo(root, REMOTE_URL);
    writeCall(join(root, 'src', 'pay.ts'), 'api.stripe.com');
    writeFileSync(
      join(root, 'package.json'),
      `${JSON.stringify({ name: 'demo', dependencies: { stripe: '^14.0.0' } }, null, 2)}\n`,
    );

    const recorded = scanAndRecord(db, root, base);

    // Display name is the remote slug; the reconcile key is the prefixed
    // identity, never the bare one.
    expect(recorded).toEqual({
      project: 'payments-api',
      destinations: 1,
      endpoints: 2,
      callSites: 2,
      truncated: false,
    });

    const sites = storedSites(store);
    expect(sites.map((s) => s.file)).toEqual(['package.json', 'src/pay.ts']);
    expect(new Set(sites.map((s) => s.projectKey))).toEqual(new Set([`git:${REMOTE_URL}`]));
    expect(sites.every((s) => s.project === 'payments-api')).toBe(true);
    // The Inventory deep-link is populated on the git path.
    expect(sites.every((s) => typeof s.projectId === 'string' && s.projectId.length > 0)).toBe(
      true,
    );
    expect(sites.map((s) => s.method).sort()).toEqual(['POST', 'SDK']);
  });

  it('records the same key and paths when a subdirectory is the scan target', () => {
    initRepo(root, REMOTE_URL);
    writeCall(join(root, 'src', 'pay.ts'), 'api.alpha-corp.com');

    scanAndRecord(db, join(root, 'src'), base);

    const sites = storedSites(store);
    // Relativized against the worktree root, not the scan target: a subtree
    // scan and a root scan agree on the stored path.
    expect(sites.map((s) => s.file)).toEqual(['src/pay.ts']);
    expect(sites[0]?.projectKey).toBe(`git:${REMOTE_URL}`);
  });

  it('is idempotent across repeated scans of an unchanged tree', () => {
    initRepo(root, REMOTE_URL);
    writeCall(join(root, 'src', 'pay.ts'), 'api.alpha-corp.com');

    const first = scanAndRecord(db, root, base);
    const second = scanAndRecord(db, root, base);

    expect(second).toEqual(first);
    expect(storedSites(store)).toHaveLength(1);
  });
});

describe('recordProjectEgress — walk-mode reconciliation', () => {
  function twoDirCorpus(): void {
    initRepo(root, REMOTE_URL);
    writeCall(join(root, 'src', 'pay.ts'), 'api.alpha-corp.com');
    writeCall(join(root, 'lib', 'old.ts'), 'api.beta-corp.com');
  }

  it('replaces only the scanned subtree, leaving sibling directories intact', () => {
    twoDirCorpus();
    scanAndRecord(db, root, base);
    expect(storedSites(store)).toHaveLength(2);

    // Re-point src/ at a different host, then scan ONLY src/.
    writeCall(join(root, 'src', 'pay.ts'), 'api.gamma-corp.com');
    scanAndRecord(db, join(root, 'src'), base);

    const sites = storedSites(store);
    // src/ was replaced in place; lib/ was never walked and survives.
    expect(sites.map((s) => `${s.file}:${s.host}`)).toEqual([
      'lib/old.ts:api.beta-corp.com',
      'src/pay.ts:api.gamma-corp.com',
    ]);
  });

  it('replaces exactly one file when the scan target is that file', () => {
    twoDirCorpus();
    writeCall(join(root, 'src', 'other.ts'), 'api.delta-corp.com');
    scanAndRecord(db, root, base);
    expect(storedSites(store)).toHaveLength(3);

    // A single-file target must scope the replacement to that file's own path
    // — never to its directory, and never to the whole project.
    writeCall(join(root, 'src', 'pay.ts'), 'api.gamma-corp.com');
    const recorded = scanAndRecord(db, join(root, 'src', 'pay.ts'), base);

    const sites = storedSites(store);
    expect(sites.map((s) => `${s.file}:${s.host}`)).toEqual([
      'lib/old.ts:api.beta-corp.com',
      'src/other.ts:api.delta-corp.com',
      'src/pay.ts:api.gamma-corp.com',
    ]);
    // The summary reports live per-project totals, not just this walk's rows.
    expect(recorded?.callSites).toBe(3);
  });

  it('does not let a single-file target delete a same-prefixed sibling', () => {
    initRepo(root, REMOTE_URL);
    writeCall(join(root, 'src', 'pay.ts'), 'api.alpha-corp.com');
    // Shares the 'src/pay.ts' string prefix; a prefix-only delete would take it.
    writeCall(join(root, 'src', 'pay.ts.bak.ts'), 'api.beta-corp.com');
    scanAndRecord(db, root, base);
    expect(storedSites(store)).toHaveLength(2);

    writeCall(join(root, 'src', 'pay.ts'), 'api.gamma-corp.com');
    scanAndRecord(db, join(root, 'src', 'pay.ts'), base);

    expect(storedSites(store).map((s) => `${s.file}:${s.host}`)).toEqual([
      'src/pay.ts:api.gamma-corp.com',
      'src/pay.ts.bak.ts:api.beta-corp.com',
    ]);
  });

  it('clears rows for a walked file whose egress is gone', () => {
    initRepo(root, REMOTE_URL);
    writeCall(join(root, 'src', 'pay.ts'), 'api.alpha-corp.com');
    scanAndRecord(db, root, base);
    expect(storedSites(store)).toHaveLength(1);

    writeFileSync(join(root, 'src', 'pay.ts'), 'export const n = 1;\n');
    const recorded = scanAndRecord(db, root, base);

    expect(storedSites(store)).toEqual([]);
    expect(recorded).toMatchObject({ destinations: 0, endpoints: 0, callSites: 0 });
  });

  it('marks vendored call sites from the stored repo-relative path', () => {
    initRepo(root, REMOTE_URL);
    writeCall(join(root, 'vendor', 'lib', 'client.ts'), 'api.alpha-corp.com');

    scanAndRecord(db, root, base);

    const sites = storedSites(store);
    expect(sites[0]?.file).toBe('vendor/lib/client.ts');
    expect(sites[0]?.vendored).toBe(1);
  });
});

describe('recordProjectEgress — non-git target', () => {
  it('keys on the realpath of the walked directory and records no project id', () => {
    writeCall(join(root, 'src', 'pay.ts'), 'api.alpha-corp.com');

    const recorded = scanAndRecord(db, root, base);

    expect(recorded?.project).toBe(basename(root));
    const sites = storedSites(store);
    expect(sites[0]?.projectKey).toBe(`path:${realpathSync(root)}`);
    expect(sites[0]?.projectId).toBeNull();
    expect(sites[0]?.file).toBe('src/pay.ts');
  });

  it('gives two same-basename directories distinct keys', () => {
    const a = join(root, 'a', 'app');
    const b = join(root, 'b', 'app');
    writeCall(join(a, 'pay.ts'), 'api.alpha-corp.com');
    writeCall(join(b, 'pay.ts'), 'api.beta-corp.com');

    scanAndRecord(db, a, base);
    scanAndRecord(db, b, base);

    const sites = storedSites(store);
    expect(sites).toHaveLength(2);
    expect(new Set(sites.map((s) => s.projectKey))).toEqual(
      new Set([`path:${realpathSync(a)}`, `path:${realpathSync(b)}`]),
    );
    // Both are named 'app'; neither walk clobbered the other's rows.
    expect(sites.every((s) => s.project === 'app')).toBe(true);
    expect(new Set(sites.map((s) => s.host))).toEqual(
      new Set(['api.alpha-corp.com', 'api.beta-corp.com']),
    );
  });

  it('keys a single-file target on its containing directory', () => {
    writeCall(join(root, 'pay.ts'), 'api.alpha-corp.com');

    scanAndRecord(db, join(root, 'pay.ts'), base);

    const sites = storedSites(store);
    expect(sites[0]?.projectKey).toBe(`path:${realpathSync(root)}`);
    expect(sites[0]?.file).toBe('pay.ts');
  });
});

describe('recordProjectEgress — key collision safety', () => {
  it('never aliases a remote-less repo onto the non-git key for the same path', () => {
    // A repo with no remote falls back to a PATH-shaped identity, which is
    // exactly the shape the non-git key is built from. The prefixes are what
    // keep the two universes apart.
    const repo = join(root, 'repo');
    mkdirSync(repo);
    initRepo(repo);
    writeCall(join(repo, 'pay.ts'), 'api.alpha-corp.com');

    scanAndRecord(db, repo, base);

    const key = storedSites(store)[0]?.projectKey;
    expect(key?.startsWith('git:')).toBe(true);
    expect(key).not.toBe(`path:${realpathSync(repo)}`);
    // The identity is the worktree root path, so only the prefix distinguishes
    // it from a non-git walk of the same directory.
    expect(key).toBe(`git:${repo}`);
  });
});

describe('recordProjectEgress — fail-open', () => {
  it('returns null and writes nothing when the kill-switch is off', () => {
    writeSettings(base, false);
    initRepo(root, REMOTE_URL);
    writeCall(join(root, 'src', 'pay.ts'), 'api.alpha-corp.com');

    expect(scanAndRecord(db, root, base)).toBeNull();
    expect(storedSites(store)).toEqual([]);
  });

  it('records normally when the kill-switch is explicitly on', () => {
    writeSettings(base, true);
    initRepo(root, REMOTE_URL);
    writeCall(join(root, 'src', 'pay.ts'), 'api.alpha-corp.com');

    expect(scanAndRecord(db, root, base)).toMatchObject({ callSites: 1 });
  });

  it('returns null for a target that does not exist', () => {
    const missing = join(root, 'nope', 'gone');
    expect(recordProjectEgress(db, missing, { files: [] }, base)).toBeNull();
    expect(storedSites(store)).toEqual([]);
  });

  it('returns null instead of throwing when the store is closed', () => {
    initRepo(root, REMOTE_URL);
    writeCall(join(root, 'src', 'pay.ts'), 'api.alpha-corp.com');
    const result = scanPathIntoStore(db, root, { rules: [] });
    db.close();

    expect(() => recordProjectEgress(db, root, result.egress, base)).not.toThrow();
    expect(recordProjectEgress(db, root, result.egress, base)).toBeNull();

    // Reopened for the afterEach close.
    db = openLocalDatabase(store);
  });
});
