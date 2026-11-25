/**
 * The built hooks write a recording when, and only when, the user has created
 * `~/.aka/data/hook-recordings/`, and the recording holds what the hook
 * actually answered.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import type { HookRecording } from '../../src/hooks/recording.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIR = join(HERE, '..', '..', 'scripts');
const PAYLOAD = JSON.parse(
  readFileSync(join(HERE, '..', 'fixtures', 'vscode-provisional', 'PreToolUse.json'), 'utf8'),
) as Record<string, unknown>;

let home: string;
let recordings: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-copilot-recording-e2e-'));
  recordings = join(home, '.aka', 'data', 'hook-recordings');
});

afterEach(() => {
  removeTrees([home]);
});

function run(): number {
  const result = spawnSync(process.execPath, [join(SCRIPTS_DIR, 'pre-tool-use.js'), 'preToolUse'], {
    env: { HOME: home, USERPROFILE: home },
    input: JSON.stringify({ ...PAYLOAD, cwd: home }),
    encoding: 'utf8',
  });
  return result.status ?? 1;
}

describe('hook recordings, through a built hook', () => {
  it('writes none without the directory', () => {
    expect(run()).toBe(0);
    expect(readdirSync(join(home, '.aka', 'data'))).not.toContain('hook-recordings');
  });

  it('writes one recording per run once the directory exists', () => {
    mkdirSync(recordings, { recursive: true });
    expect(run()).toBe(0);
    const files = readdirSync(recordings);
    expect(files).toHaveLength(1);
    const recording = JSON.parse(
      readFileSync(join(recordings, files[0] ?? ''), 'utf8'),
    ) as HookRecording;
    expect(recording.event).toBe('preToolUse');
    expect((recording.stdin as Record<string, unknown>).tool_name).toBe(PAYLOAD.tool_name);
    expect(recording.exitCode).toBe(0);
  });
});
