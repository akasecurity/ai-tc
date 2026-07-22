import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { DB_FILENAME, openLocalDatabase } from '@akasecurity/persistence';
import type { Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { collectFiles, scanPathIntoStore } from '../src/fs-scan.ts';

// An AWS-key-SHAPED test value, assembled at runtime so no key-shaped literal
// sits in this source file (the AKA plugin itself would flag it). Matched by
// the explicit test rule below, so the test never depends on the SDK's bundled
// packs — the engine's global registry stays untouched, exactly how the web-ui
// invokes the pipeline.
const SECRET = `AKIA${'A'.repeat(16)}`;

const RULES: Rule[] = [
  {
    specVersion: 1,
    id: 'test/aws-key',
    name: 'AWS access key',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: 'AKIA[0-9A-Z]{16}', flags: 'g' },
  },
];

// The raw at-rest event rows, straight from the store file — the tests assert
// on what actually hit disk, independent of any read port.
function storedEvents(dir: string): { content: string; metadata: string | null }[] {
  const raw = new DatabaseSync(join(dir, DB_FILENAME), { readOnly: true });
  try {
    return raw.prepare('SELECT content, metadata FROM events').all() as unknown as {
      content: string;
      metadata: string | null;
    }[];
  } finally {
    raw.close();
  }
}

let root: string;
let store: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-fs-scan-'));
  store = mkdtempSync(join(tmpdir(), 'aka-fs-scan-db-'));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(store, { recursive: true, force: true });
});

describe('collectFiles', () => {
  it('walks a tree skipping vendored dirs, dotdirs, and oversized files', () => {
    writeFileSync(join(root, 'app.ts'), `const key = '${SECRET}';\n`);
    mkdirSync(join(root, 'node_modules'));
    writeFileSync(join(root, 'node_modules', 'dep.js'), SECRET);
    mkdirSync(join(root, '.hidden'));
    writeFileSync(join(root, '.hidden', 'sneaky.txt'), SECRET);
    writeFileSync(join(root, 'huge.bin'), 'x'.repeat(1_000_001));

    const files = [...collectFiles(root)];
    expect(files).toEqual([{ path: join(root, 'app.ts'), gitignored: false }]);
  });

  it('yields a directly-named file and nothing for a missing path', () => {
    const file = join(root, 'one.txt');
    writeFileSync(file, 'hello');
    expect([...collectFiles(file)]).toEqual([{ path: file, gitignored: false }]);
    expect([...collectFiles(join(root, 'nope'))]).toEqual([]);
  });

  it('hard-skips .akaignore matches (files and directories)', () => {
    // The ignore file lists itself too — dotFILES are otherwise scanned
    // (that's where secrets live), unlike dot-directories.
    writeFileSync(join(root, '.akaignore'), '.akaignore\nskipped.ts\nprivate/\n');
    writeFileSync(join(root, 'kept.ts'), 'a');
    writeFileSync(join(root, 'skipped.ts'), 'b');
    mkdirSync(join(root, 'private'));
    writeFileSync(join(root, 'private', 'inner.ts'), 'c');

    const files = [...collectFiles(root)].map((f) => f.path);
    expect(files).toEqual([join(root, 'kept.ts')]);
  });

  it('marks .gitignore matches as gitignored but still yields them', () => {
    writeFileSync(join(root, '.gitignore'), 'scratch.env\nlogs/\n');
    writeFileSync(join(root, 'tracked.ts'), 'a');
    writeFileSync(join(root, 'scratch.env'), 'b');
    mkdirSync(join(root, 'logs'));
    writeFileSync(join(root, 'logs', 'debug.log'), 'c');

    const files = [...collectFiles(root)];
    const byPath = new Map(files.map((f) => [f.path, f.gitignored]));
    expect(byPath.get(join(root, 'tracked.ts'))).toBe(false);
    expect(byPath.get(join(root, 'scratch.env'))).toBe(true);
    expect(byPath.get(join(root, 'logs', 'debug.log'))).toBe(true);
  });

  it('lets an .akaignore negation re-include a default-skipped directory', () => {
    writeFileSync(join(root, '.akaignore'), '!build/\n');
    mkdirSync(join(root, 'build'));
    writeFileSync(join(root, 'build', 'gen.ts'), 'a');

    const files = [...collectFiles(root)].map((f) => f.path);
    expect(files).toContain(join(root, 'build', 'gen.ts'));
  });

  it('applies a deeper .akaignore only beneath its own directory', () => {
    mkdirSync(join(root, 'sub'));
    writeFileSync(join(root, 'sub', '.akaignore'), 'local.ts\n');
    writeFileSync(join(root, 'sub', 'local.ts'), 'a');
    writeFileSync(join(root, 'local.ts'), 'b');

    const files = [...collectFiles(root)].map((f) => f.path);
    expect(files).toContain(join(root, 'local.ts'));
    expect(files).not.toContain(join(root, 'sub', 'local.ts'));
  });
});

describe('scanPathIntoStore', () => {
  it('records a redacted event + masked findings per matching file', async () => {
    writeFileSync(join(root, 'app.ts'), `const key = '${SECRET}';\n`);
    writeFileSync(join(root, 'clean.ts'), `const ok = true;\n`);

    const db = openLocalDatabase(store);
    try {
      const result = scanPathIntoStore(db, root, { rules: RULES, sourceTool: 'cli' });
      expect(result.scanned).toBe(2);
      expect(result.findings).toBe(1);
      // Per-file detail (the --format json surface) carries only store-safe
      // fields: the masked match, never the raw one.
      expect(result.files).toHaveLength(1);
      expect(result.files[0]?.path).toBe(join(root, 'app.ts'));
      expect(result.files[0]?.findings[0]?.maskedMatch).not.toBe(SECRET);

      // The raw secret never lands on disk: the event content is redacted and
      // the finding stores only a masked preview.
      const [event] = storedEvents(store);
      expect(event?.content).not.toContain(SECRET);
      const findings = await db.findings.recentFindings({ limit: 10 });
      const recorded = findings.find((f) => f.ruleId === 'test/aws-key');
      expect(recorded).toBeDefined();
      expect(recorded?.maskedMatch).not.toBe(SECRET);
    } finally {
      db.close();
    }
  });

  it('records nothing when no rules match', () => {
    writeFileSync(join(root, 'clean.ts'), `const ok = true;\n`);
    const db = openLocalDatabase(store);
    try {
      const result = scanPathIntoStore(db, root, { rules: RULES });
      expect(result).toEqual({ scanned: 1, findings: 0, files: [], egress: { files: [] } });
      expect(storedEvents(store)).toEqual([]);
    } finally {
      db.close();
    }
  });

  it('stamps the per-pack action from ruleActions (overriding the category default)', async () => {
    writeFileSync(join(root, 'app.ts'), `const key = '${SECRET}';\n`);
    const db = openLocalDatabase(store);
    try {
      // The secret rule's category default is 'block'; the pack policy is Monitor.
      scanPathIntoStore(db, root, {
        rules: RULES,
        ruleActions: new Map([['test/aws-key', 'log']]),
      });
      const findings = await db.findings.recentFindings({ limit: 10 });
      const recorded = findings.find((f) => f.ruleId === 'test/aws-key');
      expect(recorded?.actionTaken).toBe('log');
    } finally {
      db.close();
    }
  });

  it('falls back to the category default when the rule is absent from ruleActions', async () => {
    writeFileSync(join(root, 'app.ts'), `const key = '${SECRET}';\n`);
    const db = openLocalDatabase(store);
    try {
      scanPathIntoStore(db, root, { rules: RULES, ruleActions: new Map() });
      const findings = await db.findings.recentFindings({ limit: 10 });
      const recorded = findings.find((f) => f.ruleId === 'test/aws-key');
      // DEFAULT_ACTIONS.secret = 'warn'
      expect(recorded?.actionTaken).toBe('warn');
    } finally {
      db.close();
    }
  });

  it('stamps gitignored provenance on the stored event and never ledgers .akaignore skips', () => {
    writeFileSync(join(root, '.gitignore'), 'scratch.env\n');
    writeFileSync(join(root, '.akaignore'), 'excluded.ts\n');
    writeFileSync(join(root, 'scratch.env'), `key=${SECRET}\n`);
    writeFileSync(join(root, 'excluded.ts'), `const key = '${SECRET}';\n`);

    const db = openLocalDatabase(store);
    try {
      const result = scanPathIntoStore(db, root, { rules: RULES });
      expect(result.files).toHaveLength(1);
      expect(result.files[0]?.gitignored).toBe(true);

      const events = storedEvents(store);
      expect(events).toHaveLength(1);
      const metadata: unknown = JSON.parse(events[0]?.metadata ?? '{}');
      expect(metadata).toMatchObject({
        filePath: join(root, 'scratch.env'),
        gitignored: true,
      });
    } finally {
      db.close();
    }
  });
});

// The egress collection pass rides the same walk as detection scanning. What it
// runs on is decided entirely here — the walker has no extension filter — so
// these cases pin the gating: code extensions get URL/IP extraction, manifests
// get SDK extraction, lockfiles and prose files get neither, and a file
// carrying a NUL byte is treated as binary and skipped.
describe('scanPathIntoStore — egress collection', () => {
  // A NUL byte written as an escape so this source file stays plain text.
  const NUL = '\u0000';

  function writeCorpus(): void {
    mkdirSync(join(root, 'src'));
    writeFileSync(
      join(root, 'src', 'pay.ts'),
      `export async function charge() {\n  return fetch('https://api.stripe.com/v1/charges', { method: 'POST' });\n}\n`,
    );
    writeFileSync(
      join(root, 'package.json'),
      `${JSON.stringify({ name: 'demo', dependencies: { stripe: '^14.0.0' } }, null, 2)}\n`,
    );
    // Prose: this URL extracts fine in isolation, so its absence proves the
    // extension gate excludes it rather than the extractor failing to see it.
    writeFileSync(join(root, 'README.md'), 'See https://api.acme-live.com/x for details.\n');
    // Lockfile: manifestKindOf returns null and .json is not a code extension.
    writeFileSync(
      join(root, 'package-lock.json'),
      `${JSON.stringify(
        {
          packages: {
            'node_modules/stripe': {
              resolved: 'https://registry.npmjs.org/stripe/-/stripe-14.0.0.tgz',
            },
          },
        },
        null,
        2,
      )}\n`,
    );
    // Binary guard: an otherwise-extractable URL alongside a NUL byte.
    writeFileSync(join(root, 'blob.ts'), `${NUL}const u = 'https://api.stripe.com/v1/x';\n`);
  }

  it('extracts from code files and manifests, skipping prose, lockfiles, and NUL-bearing files', () => {
    writeCorpus();

    const db = openLocalDatabase(store);
    try {
      // No rules at all, so every file takes the "no matches" path: a pass that
      // only ran after the finding early-out would collect nothing here.
      const result = scanPathIntoStore(db, root, { rules: [] });
      expect(result.findings).toBe(0);

      const byFile = new Map(result.egress.files.map((f) => [f.file, f]));
      expect([...byFile.keys()].sort()).toEqual(
        [join(root, 'package.json'), join(root, 'src', 'pay.ts')].sort(),
      );

      const pay = byFile.get(join(root, 'src', 'pay.ts'));
      expect(pay?.sdkHits).toEqual([]);
      expect(pay?.endpoints).toHaveLength(1);
      expect(pay?.endpoints[0]).toMatchObject({
        host: 'api.stripe.com',
        url: 'https://api.stripe.com/v1/charges',
        method: 'POST',
        transport: 'https',
        line: 2,
      });

      const manifest = byFile.get(join(root, 'package.json'));
      expect(manifest?.endpoints).toEqual([]);
      expect(manifest?.sdkHits).toHaveLength(1);
      expect(manifest?.sdkHits[0]).toMatchObject({ ecosystem: 'npm', pkg: 'stripe' });
    } finally {
      db.close();
    }
  });

  it('collects egress for files that produce findings too', () => {
    writeFileSync(
      join(root, 'app.ts'),
      `const key = '${SECRET}';\nfetch('https://api.stripe.com/v1/charges', { method: 'POST' });\n`,
    );

    const db = openLocalDatabase(store);
    try {
      const result = scanPathIntoStore(db, root, { rules: RULES });
      expect(result.findings).toBe(1);
      expect(result.egress.files).toHaveLength(1);
      expect(result.egress.files[0]?.endpoints[0]?.host).toBe('api.stripe.com');
    } finally {
      db.close();
    }
  });

  it('omits files whose extraction yields nothing', () => {
    writeFileSync(join(root, 'plain.ts'), 'export const n = 1;\n');
    writeFileSync(join(root, 'notes.txt'), 'https://api.stripe.com/v1/charges\n');

    const db = openLocalDatabase(store);
    try {
      const result = scanPathIntoStore(db, root, { rules: [] });
      expect(result.scanned).toBe(2);
      expect(result.egress.files).toEqual([]);
    } finally {
      db.close();
    }
  });

  it('marks vendored call sites from the walked path', () => {
    mkdirSync(join(root, 'vendor', 'lib'), { recursive: true });
    writeFileSync(
      join(root, 'vendor', 'lib', 'client.ts'),
      `fetch('https://api.stripe.com/v1/charges', { method: 'POST' });\n`,
    );

    const db = openLocalDatabase(store);
    try {
      const result = scanPathIntoStore(db, root, { rules: [] });
      expect(result.egress.files).toHaveLength(1);
      expect(result.egress.files[0]?.vendored).toBe(true);
    } finally {
      db.close();
    }
  });
});
