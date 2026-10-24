// The hook server's file locations: one directory under ~/.aka, one socket and start lock per plugin version.
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  logPath,
  RUN_DIR_MODE,
  runDir,
  socketPath,
  startLockPath,
} from '../../../src/hooks/hook-server/paths.ts';

describe('the hook server paths', () => {
  const home = join('/', 'home', 'someone');

  it('keeps every file in one owner-only directory under ~/.aka', () => {
    expect(runDir(home)).toBe(join(home, '.aka', 'run'));
    expect(RUN_DIR_MODE).toBe(0o700);
    expect(logPath(home)).toBe(join(runDir(home), 'hook-server.log'));
  });

  it('gives each plugin version its own socket and start lock', () => {
    expect(socketPath(home, '1.2.3')).toBe(join(runDir(home), 'hook-1.2.3.sock'));
    expect(socketPath(home, '1.2.4')).not.toBe(socketPath(home, '1.2.3'));
    expect(startLockPath(home, '1.2.3')).toBe(join(runDir(home), 'hook-1.2.3.starting'));
  });
});
