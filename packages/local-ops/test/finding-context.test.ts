import { randomUUID } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { LocalDatabase } from '@akasecurity/persistence';
import { DB_FILENAME, openLocalDatabase } from '@akasecurity/persistence';
import { bundledMaskingRules } from '@akasecurity/plugin-sdk';
import type { DetectedFindingWithKey, IngestEvent, Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { loadFindingContext } from '../src/finding-context.ts';
import { scanPathIntoStore } from '../src/fs-scan.ts';
import { migratedStore } from './helpers/store-templates.ts';

// A finding's masked excerpt as the dashboard drawer gets it: built by the
// folder scan while the file is in memory, or rebuilt for an older finding
// from the event's stored text where that is still safe.

const FILE = [
  'import { render } from "./view";',
  '',
  'export function show(userInput: string) {',
  '  const element = document.getElementById("out");',
  '  element.innerHTML = userInput;',
  '  return element;',
  '}',
  '',
].join('\n');

let store: string;
let root: string;
let db: LocalDatabase;

beforeEach(() => {
  store = mkdtempSync(join(tmpdir(), 'aka-finding-context-store-'));
  root = mkdtempSync(join(tmpdir(), 'aka-finding-context-root-'));
  migratedStore.seed(store);
  db = openLocalDatabase(store);
});

afterEach(() => {
  db.close();
  removeTrees([store, root]);
});

function rules(): Rule[] {
  const loaded = bundledMaskingRules();
  if (loaded === null) throw new Error('bundled packs failed to load');
  return loaded;
}

describe('the folder scan records where each finding sits', () => {
  it('stores the file line, the column and a masked excerpt counted in the file', async () => {
    writeFileSync(join(root, 'show.ts'), FILE);
    await scanPathIntoStore(db, root, { rules: rules() });

    const page = await db.findings.listFindingInstances({ subtype: ['code-flaws/xss-inner-html'] });
    const instance = page.items[0];
    expect(instance?.line).toBe(5);
    expect(instance?.col).toBe('  element.'.length + 1);

    // Read from the stored column, not through the loader: the loader would
    // rebuild an excerpt from this unredacted file if the scan had stored none.
    const stored = db.findings.findingContextSource(instance?.id ?? '')?.context ?? null;
    expect(stored).not.toBeNull();
    const context = loadFindingContext(db.findings, instance?.id ?? '');
    expect(context).toEqual(JSON.parse(stored ?? 'null'));
    expect(context?.basis).toBe('file');
    expect(context?.firstLine).toBe(3);
    expect(context?.lines[2]).toBe('  element.innerHTML = userInput;');
    expect(context?.match?.line).toBe(5);
  });
});

describe('the folder scan never shows what its policy redacted at rest', () => {
  it('redacts the matched code in the excerpt when the rule resolves to redact', async () => {
    writeFileSync(join(root, 'show.ts'), FILE);
    await scanPathIntoStore(db, root, {
      rules: rules(),
      ruleActions: new Map([['code-flaws/xss-inner-html', 'redact']]),
    });
    const page = await db.findings.listFindingInstances({ subtype: ['code-flaws/xss-inner-html'] });
    const shown = loadFindingContext(db.findings, page.items[0]?.id ?? '')?.lines.join('\n') ?? '';
    // Control: the excerpt was built.
    expect(shown).toContain('userInput');
    expect(shown).toContain('[REDACTED:CODE_FLAW]');
    expect(shown).not.toContain('innerHTML =');
  });
});

describe('loadFindingContext — a finding recorded before excerpts existed', () => {
  it('counts a rebuilt excerpt from a scanned file in the file', async () => {
    writeFileSync(join(root, 'show.ts'), FILE);
    await scanPathIntoStore(db, root, { rules: rules() });
    const page = await db.findings.listFindingInstances({ subtype: ['code-flaws/xss-inner-html'] });
    const id = page.items[0]?.id ?? '';
    // Make it an older finding: no stored excerpt, so the loader rebuilds one.
    const raw = new DatabaseSync(join(store, DB_FILENAME));
    try {
      raw.prepare('UPDATE inspection_findings SET context = NULL WHERE id = ?').run(id);
    } finally {
      raw.close();
    }
    expect(db.findings.findingContextSource(id)?.context).toBeNull();
    expect(loadFindingContext(db.findings, id)?.basis).toBe('file');
  });

  function recordLegacy(content: string | null, needle: string, filePath = '/repo/show.ts') {
    const event: IngestEvent = {
      id: randomUUID(),
      sourceTool: 'claude-code',
      kind: 'code_change',
      occurredAt: new Date().toISOString(),
      contentHash: randomUUID(),
      content: content ?? '',
      metadata: { filePath, toolName: 'Edit' },
    };
    const start = (content ?? '').indexOf(needle);
    const finding: DetectedFindingWithKey = {
      id: randomUUID(),
      eventId: event.id,
      ruleId: 'code-flaws/xss-inner-html',
      category: 'code_flaw',
      severity: 'high',
      span: { start, end: start + needle.length },
      maskedMatch: 'i*********=',
      actionTaken: 'log',
      confidence: 0.8,
    };
    db.recordCapture(event, [finding]);
    return finding.id;
  }

  it('rebuilds an excerpt from stored text that nothing was redacted in ahead of the match', () => {
    const id = recordLegacy(FILE, 'innerHTML =');
    const context = loadFindingContext(db.findings, id);
    expect(context?.basis).toBe('excerpt');
    expect(context?.match?.line).toBe(5);
    expect(context?.lines).toContain('  element.innerHTML = userInput;');
  });

  it('refuses when a redaction placeholder sits ahead of the match, since the offsets moved', () => {
    // Stored as the at-rest copy would be: a value rewritten to a placeholder
    // of a different length, so every offset after it is off.
    const stored = `const key = "[REDACTED:SECRET]";\n${FILE}`;
    const id = recordLegacy(stored, 'innerHTML =');
    // Control: the placeholder really is ahead of the match.
    expect(stored.indexOf('[REDACTED:')).toBeLessThan(stored.indexOf('innerHTML ='));
    expect(loadFindingContext(db.findings, id)).toBeNull();
  });

  it('returns the stored excerpt as it was written, never a rebuilt one', async () => {
    writeFileSync(join(root, 'show.ts'), FILE);
    await scanPathIntoStore(db, root, { rules: rules() });
    const page = await db.findings.listFindingInstances({ subtype: ['code-flaws/xss-inner-html'] });
    const id = page.items[0]?.id ?? '';
    // A stored excerpt no rebuild from this file could produce, so only reading
    // the stored column can return it.
    const sentinel = { basis: 'file', firstLine: 9, lines: ['stored excerpt'], match: null };
    const raw = new DatabaseSync(join(store, DB_FILENAME));
    try {
      raw
        .prepare('UPDATE inspection_findings SET context = ? WHERE id = ?')
        .run(JSON.stringify(sentinel), id);
    } finally {
      raw.close();
    }
    expect(loadFindingContext(db.findings, id)).toEqual(sentinel);
  });

  it('returns null for a stored excerpt that is not one', async () => {
    writeFileSync(join(root, 'show.ts'), FILE);
    await scanPathIntoStore(db, root, { rules: rules() });
    const page = await db.findings.listFindingInstances({ subtype: ['code-flaws/xss-inner-html'] });
    const id = page.items[0]?.id ?? '';
    const raw = new DatabaseSync(join(store, DB_FILENAME));
    try {
      raw.prepare('UPDATE inspection_findings SET context = ? WHERE id = ?').run('{not json', id);
    } finally {
      raw.close();
    }
    expect(loadFindingContext(db.findings, id)).toBeNull();
    // JSON that parses but is not an excerpt is refused too.
    const again = new DatabaseSync(join(store, DB_FILENAME));
    try {
      again
        .prepare('UPDATE inspection_findings SET context = ? WHERE id = ?')
        .run(JSON.stringify({ lines: 'stored excerpt' }), id);
    } finally {
      again.close();
    }
    expect(loadFindingContext(db.findings, id)).toBeNull();
  });

  it('returns null for an unknown finding', () => {
    expect(loadFindingContext(db.findings, 'no-such-finding')).toBeNull();
  });
});
