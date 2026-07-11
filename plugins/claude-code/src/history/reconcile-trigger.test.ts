import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Mock the detached spawn so the test never launches a real worker — we only assert
// HOW OFTEN it would fire. `vi.hoisted` makes the spy exist before the mock factory.
const { spawnSpy } = vi.hoisted(() => ({ spawnSpy: vi.fn(() => ({ unref: vi.fn() })) }));
vi.mock('node:child_process', () => ({ spawn: spawnSpy }));

// `throttled` (@akasecurity/plugin-sdk) is left REAL: it writes the on-disk
// marker we're testing, against a temp dataDir.
import { triggerReconcile } from './reconcile-trigger.ts';

describe('triggerReconcile — per-session throttle', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-reconcile-'));
    spawnSpy.mockClear();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('throttles per session, not globally — concurrent sessions each get their own spawn', () => {
    // First turn of session A → spawns (no marker yet).
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    // A second turn of session A within the 30s window is batched (throttled).
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(1);

    // A DIFFERENT concurrent session (another tab/project) must NOT be starved by
    // session A's marker — with a global marker it would be throttled and its live
    // capture delayed; with the per-session marker it spawns immediately.
    triggerReconcile(dir, 'sess-B', '/t/b.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(2);
  });
});
