import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import {
  dataDir,
  DB_FILENAME,
  type LocalDatabase,
  openLocalDatabase,
} from '@akasecurity/persistence';
import type { DetectedFindingWithKey, FindingContext, IngestEvent } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { loadFindingContextAction } from '../../app/(app)/findings/actions.ts';
import { emptyStore } from '../helpers/store-templates.ts';
import { tempHomes } from '../helpers/temp-home.ts';

/**
 * The drawer's excerpt read. A READ action the browser can post anything to,
 * so what matters is the boundary: a malformed body resolves to null — the
 * drawer then says the code was not kept — and never rejects, since a rejected
 * Server Action becomes a framework error page.
 *
 * Setup follows the four steps every web-ui Server Action test needs (see
 * findings-load-more.test.ts).
 */
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

function dropMemoisedDb(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

const newHome = tempHomes('aka-findings-context-');

let dir: string;

beforeEach(() => {
  osHome.dir = newHome();
  dir = dataDir();
  emptyStore.seed(dir);
  dropMemoisedDb();
});

afterEach(() => {
  dropMemoisedDb();
});

const EXCERPT: FindingContext = {
  basis: 'file',
  firstLine: 1,
  lines: ['element.innerHTML = userInput;'],
  match: { line: 1, start: 8, end: 19 },
};

/** One finding carrying EXCERPT, seeded through a second handle. */
function seedFinding(): string {
  const db = openLocalDatabase(dir);
  const event: IngestEvent = {
    id: randomUUID(),
    sourceTool: 'claude-code',
    kind: 'code_change',
    occurredAt: new Date().toISOString(),
    contentHash: randomUUID(),
    content: 'element.innerHTML = userInput;',
    metadata: { filePath: '/repo/show.ts', toolName: 'Write' },
  };
  const finding: DetectedFindingWithKey = {
    id: randomUUID(),
    eventId: event.id,
    ruleId: 'code-flaws/xss-inner-html',
    category: 'code_flaw',
    severity: 'high',
    span: { start: 8, end: 19 },
    maskedMatch: 'i*********=',
    actionTaken: 'log',
    confidence: 0.8,
    location: { line: 1, col: 9, context: EXCERPT },
  };
  db.recordCapture(event, [finding]);
  db.close();
  dropMemoisedDb();
  return finding.id;
}

describe('loadFindingContextAction', () => {
  it('returns the excerpt stored for the finding', async () => {
    const id = seedFinding();
    await expect(loadFindingContextAction({ id })).resolves.toEqual(EXCERPT);
  });

  it('resolves to null for a body that is not the query, and never rejects', async () => {
    const id = seedFinding();
    // Positive control: a well-formed body still reads.
    await expect(loadFindingContextAction({ id })).resolves.toEqual(EXCERPT);
    const hostile = {
      toString: () => {
        throw new Error('coerced');
      },
    };
    for (const body of [42, null, 'id', {}, { id: 7 }, { id: '' }, { id: hostile }, [id]]) {
      await expect(loadFindingContextAction(body)).resolves.toBeNull();
    }
  });

  it('resolves to null for an id that names no finding', async () => {
    await expect(loadFindingContextAction({ id: 'no-such-finding' })).resolves.toBeNull();
  });

  it('resolves to null, not a rejection, when the store cannot be read', async () => {
    writeFileSync(join(dir, DB_FILENAME), 'this is not a database');
    await expect(loadFindingContextAction({ id: 'any' })).resolves.toBeNull();
  });
});
