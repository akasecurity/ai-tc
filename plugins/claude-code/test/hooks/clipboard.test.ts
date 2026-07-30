// Platform selection + fallback chain for the best-effort clipboard write.
// Every test injects a spawner, so no real clipboard is ever touched.
import { describe, expect, it } from 'vitest';

import { writeClipboard } from '../../src/hooks/clipboard.ts';

const POINTERIZED = 'deploy with [[aka:secret:0123456789abcdef0123456789abcdef]] please';

interface SpawnCall {
  cmd: string;
  args: string[];
  input: string;
}

function recordingSpawner(okFor: (cmd: string) => boolean): {
  calls: SpawnCall[];
  spawn: (cmd: string, args: string[], input: string) => { ok: boolean };
} {
  const calls: SpawnCall[] = [];
  return {
    calls,
    spawn: (cmd, args, input) => {
      calls.push({ cmd, args, input });
      return { ok: okFor(cmd) };
    },
  };
}

describe('writeClipboard', () => {
  it('darwin uses pbcopy', () => {
    const { calls, spawn } = recordingSpawner(() => true);
    expect(writeClipboard(POINTERIZED, { platform: 'darwin', spawn })).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ cmd: 'pbcopy', args: [], input: POINTERIZED });
  });

  it('win32 uses clip', () => {
    const { calls, spawn } = recordingSpawner(() => true);
    expect(writeClipboard(POINTERIZED, { platform: 'win32', spawn })).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.cmd).toBe('clip');
  });

  it('linux walks wl-copy → xclip → xsel, stopping at the first success', () => {
    const { calls, spawn } = recordingSpawner((cmd) => cmd === 'xclip');
    expect(writeClipboard(POINTERIZED, { platform: 'linux', spawn })).toBe(true);
    expect(calls.map((c) => c.cmd)).toEqual(['wl-copy', 'xclip']);
    expect(calls[1]?.args).toEqual(['-selection', 'clipboard']);
  });

  it('linux falls through to xsel with the documented selection args', () => {
    const { calls, spawn } = recordingSpawner((cmd) => cmd === 'xsel');
    expect(writeClipboard(POINTERIZED, { platform: 'linux', spawn })).toBe(true);
    expect(calls.map((c) => c.cmd)).toEqual(['wl-copy', 'xclip', 'xsel']);
    expect(calls[2]?.args).toEqual(['--clipboard', '--input']);
  });

  it('every utility missing → false, never a throw', () => {
    const { calls, spawn } = recordingSpawner(() => false);
    expect(writeClipboard(POINTERIZED, { platform: 'linux', spawn })).toBe(false);
    expect(calls).toHaveLength(3);
  });

  it('a spawner that throws → false, never a throw', () => {
    const spawn = (): { ok: boolean } => {
      throw new Error('spawn exploded');
    };
    expect(writeClipboard(POINTERIZED, { platform: 'darwin', spawn })).toBe(false);
  });

  it('an unrecognized platform → false without spawning anything', () => {
    const { calls, spawn } = recordingSpawner(() => true);
    expect(writeClipboard(POINTERIZED, { platform: 'freebsd', spawn })).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it('the spawner receives exactly the given text on every attempt', () => {
    const { calls, spawn } = recordingSpawner(() => false);
    writeClipboard(POINTERIZED, { platform: 'linux', spawn });
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) expect(call.input).toBe(POINTERIZED);
  });
});
