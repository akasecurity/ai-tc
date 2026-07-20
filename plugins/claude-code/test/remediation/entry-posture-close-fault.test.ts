import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { LocalDatabase } from '@akasecurity/persistence';
import { openLocalDatabase } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// A toggle a single test flips to make the store connection's `close()` throw —
// every other case leaves it off, so the real teardown path still runs. The
// underlying store operations stay real (only `close()` is wrapped), so this
// proves the fix against a genuine SQLite connection, not a hand-rolled stub.
// `vi.hoisted` makes it exist before the mock factory below runs.
const { dbCloseShouldThrow } = vi.hoisted(() => ({ dbCloseShouldThrow: { value: false } }));

vi.mock('@akasecurity/persistence', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const realOpenLocalDatabase = actual.openLocalDatabase as (dir: string) => LocalDatabase;
  return {
    ...actual,
    openLocalDatabase: (dir: string): LocalDatabase => {
      const db = realOpenLocalDatabase(dir);
      return {
        ...db,
        close: () => {
          if (dbCloseShouldThrow.value) throw new Error('simulated db close fault');
          db.close();
        },
      };
    },
  };
});

// The production entry's `writeSecretPosture` — guarded at the bottom of
// entry.ts so importing it here never runs the CLI (reads stdin, calls
// process.exit).
import { writeSecretPosture } from '../../src/remediation/entry.ts';

describe("entry.ts writeSecretPosture — a close() fault in the finally never rewrites the write's own result", () => {
  let home: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    // writeSecretPosture calls loadConfig() with no override, resolving ~/.aka
    // from $HOME — point it at a throwaway home so this test never touches the
    // developer's real local store.
    home = mkdtempSync(join(tmpdir(), 'aka-entry-posture-'));
    // eslint-disable-next-line n/no-process-env -- test needs to redirect ~/.aka to a throwaway home
    originalHome = process.env.HOME;
    // eslint-disable-next-line n/no-process-env -- test needs to redirect ~/.aka to a throwaway home
    process.env.HOME = home;
  });

  afterEach(() => {
    dbCloseShouldThrow.value = false;
    // eslint-disable-next-line n/no-process-env -- restore the host HOME after the test
    if (originalHome === undefined) delete process.env.HOME;
    // eslint-disable-next-line n/no-process-env -- restore the host HOME after the test
    else process.env.HOME = originalHome;
    rmSync(home, { recursive: true, force: true });
  });

  it('a db.close() fault after the posture write already succeeded still reports persisted:true — not a false failure', () => {
    dbCloseShouldThrow.value = true;

    const result = writeSecretPosture('redact');

    // The write landed and returned before close() ever ran; a teardown fault
    // must not overwrite that outcome with a false "not persisted".
    expect(result).toEqual({ persisted: true, level: 'redact' });

    // Durable: read back on a fresh connection (close() never swallows a real
    // fault, but the wrapped connection above never got to release its own
    // handle, so a fresh open proves the write is genuinely on disk).
    dbCloseShouldThrow.value = false;
    const verify = openLocalDatabase(join(home, '.aka', 'data'));
    try {
      expect(verify.policies.getCategoryAction('secret')).toBe('redact');
    } finally {
      verify.close();
    }
  });

  it('with no close() fault, the write still reports persisted:true (baseline unaffected by the fix)', () => {
    const result = writeSecretPosture('warn');

    expect(result).toEqual({ persisted: true, level: 'warn' });
  });
});
