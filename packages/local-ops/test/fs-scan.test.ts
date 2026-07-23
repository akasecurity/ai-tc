import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  DB_FILENAME,
  fingerprintValue,
  loadOrCreateFingerprintKey,
  openLocalDatabase,
} from '@akasecurity/persistence';
import { computeFindingKey } from '@akasecurity/plugin-sdk';
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

// The raw at-rest audit-event rows, straight from the store file — the tests
// assert on what actually hit disk, independent of any read port. Constrained
// to the four capture kinds — audit_events also holds structural rows (session,
// run, tool_call, llm_call, source_lookup, config_scan) that scanPathIntoStore
// never writes, but the predicate keeps intent explicit.
function storedEvents(dir: string): { content: string; attributes: string | null }[] {
  const raw = new DatabaseSync(join(dir, DB_FILENAME), { readOnly: true });
  try {
    return raw
      .prepare(
        `SELECT content, attributes FROM audit_events
         WHERE event_type IN ('prompt','response','code_change','tool_use')`,
      )
      .all() as unknown as {
      content: string;
      attributes: string | null;
    }[];
  } finally {
    raw.close();
  }
}

// The raw at-rest findings rows, straight from the store file — used to assert
// on row COUNT (does a re-scan duplicate?) and on finding_key directly, which
// no read port surfaces today.
function storedFindings(dir: string): { id: string; finding_key: string | null }[] {
  const raw = new DatabaseSync(join(dir, DB_FILENAME), { readOnly: true });
  try {
    return raw.prepare('SELECT id, finding_key FROM findings').all() as unknown as {
      id: string;
      finding_key: string | null;
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
      expect(result).toEqual({ scanned: 1, findings: 0, files: [] });
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
      const attributes: unknown = JSON.parse(events[0]?.attributes ?? '{}');
      expect(attributes).toMatchObject({
        file_path: join(root, 'scratch.env'),
        gitignored: true,
      });
    } finally {
      db.close();
    }
  });
});

describe('scanPathIntoStore — finding_key (re-scan reconciliation)', () => {
  // The regression test for the bug this fix closes: without a finding_key,
  // ON CONFLICT (finding_key) never fires (SQLite never equates two NULLs in a
  // unique index), so every re-scan of an unchanged file minted a fresh row.
  it('reconciles a re-scan of an unchanged file onto the same row instead of duplicating', () => {
    writeFileSync(join(root, 'app.ts'), `const key = '${SECRET}';\n`);
    const db = openLocalDatabase(store);
    try {
      scanPathIntoStore(db, root, { rules: RULES, dataDir: store });
      scanPathIntoStore(db, root, { rules: RULES, dataDir: store });

      const rows = storedFindings(store);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.finding_key).not.toBeNull();
    } finally {
      db.close();
    }
  });

  it('still produces a non-null finding_key with no fingerprint key available (no dataDir)', () => {
    writeFileSync(join(root, 'app.ts'), `const key = '${SECRET}';\n`);
    const db = openLocalDatabase(store);
    try {
      scanPathIntoStore(db, root, { rules: RULES }); // no dataDir option passed
      const rows = storedFindings(store);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.finding_key).toMatch(/^[0-9a-f]{64}$/);
    } finally {
      db.close();
    }
  });

  it('derives finding_key via the shared computeFindingKey/fingerprintValue formula — parity with the plugin', () => {
    writeFileSync(join(root, 'app.ts'), `const key = '${SECRET}';\n`);
    const db = openLocalDatabase(store);
    try {
      scanPathIntoStore(db, root, { rules: RULES, dataDir: store });
      const rows = storedFindings(store);

      // Independently recompute the key from the same on-disk fingerprint key
      // scanPathIntoStore just minted at `store`, using the exact functions the
      // plugin's createPluginRuntime.capture() calls (computeFindingKey +
      // fingerprintValue) — not a copy. A byte-identical match here is the
      // whole point of importing rather than reimplementing.
      const fpKey = loadOrCreateFingerprintKey(store);
      const expected = computeFindingKey({
        ruleId: 'test/aws-key',
        filePath: join(root, 'app.ts'),
        valueFingerprint: fingerprintValue(fpKey, SECRET),
      });
      expect(rows[0]?.finding_key).toBe(expected);
    } finally {
      db.close();
    }
  });
});
