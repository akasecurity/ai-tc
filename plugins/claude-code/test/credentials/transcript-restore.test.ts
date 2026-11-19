import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  forgetSessionCredentials,
  noteTranscript,
  resolveForSession,
} from '../../src/credentials/session-credentials.ts';
import {
  createTranscriptSweeper,
  restoreHandlesInTranscript,
} from '../../src/credentials/transcript-restore.ts';
import type { RedactionScope } from '../../src/remediation/redact.ts';

const VALUE = 'ghp_demo"value\\0123456789';
let root: string;
let transcripts: string;
let scope: RedactionScope;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-cred-transcript-'));
  transcripts = join(root, 'projects');
  mkdirSync(join(transcripts, 'p'), { recursive: true });
  scope = { artifactRoots: [transcripts] };
});
afterEach(() => {
  forgetSessionCredentials();
  rmSync(root, { recursive: true, force: true });
});

const injected = new Map([['github', VALUE]]);

function transcriptLines(): string[] {
  return [
    JSON.stringify({ type: 'user', message: { content: 'call the api' } }),
    JSON.stringify({
      type: 'assistant',
      message: {
        content: [{ type: 'tool_use', input: { command: 'curl -H "x: [[aka:cred:github]]"' } }],
      },
    }),
    JSON.stringify({
      type: 'attachment',
      attachment: {
        type: 'hook_success',
        stdout: JSON.stringify({
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            updatedInput: { command: `curl -H "x: ${VALUE}"` },
          },
        }),
      },
    }),
    JSON.stringify({ type: 'user', toolUseResult: { stdout: `echoed ${VALUE}` } }),
  ];
}

describe('restoreHandlesInTranscript', () => {
  it('rewrites every spelling of an injected value to its handle and nothing else', async () => {
    const path = join(transcripts, 'p', 'session.jsonl');
    const lines = transcriptLines();
    writeFileSync(path, `${lines.join('\n')}\n`);

    await expect(restoreHandlesInTranscript(path, injected, scope)).resolves.toEqual({
      rewritten: 2,
    });

    const after = readFileSync(path, 'utf8');
    expect(after.endsWith('\n')).toBe(true);
    expect(after).not.toContain('ghp_demo');
    const afterLines = after.split('\n');
    expect(afterLines[0]).toBe(lines[0]);
    expect(afterLines[1]).toBe(lines[1]);
    for (const line of afterLines.filter(Boolean))
      expect(() => JSON.parse(line) as unknown).not.toThrow();
    const hook = JSON.parse(afterLines[2] ?? '') as { attachment: { stdout: string } };
    expect(JSON.parse(hook.attachment.stdout)).toEqual({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        updatedInput: { command: 'curl -H "x: [[aka:cred:github]]"' },
      },
    });
    expect(readdirSync(join(transcripts, 'p'))).toEqual(['session.jsonl']);
  });

  it('never writes a file outside the transcript root', async () => {
    const outside = join(root, 'elsewhere.jsonl');
    const text = `${JSON.stringify({ v: VALUE })}\n`;
    writeFileSync(outside, text);
    await expect(restoreHandlesInTranscript(outside, injected, scope)).resolves.toBeNull();
    expect(readFileSync(outside, 'utf8')).toBe(text);
  });

  it('leaves a transcript without the value byte-identical', async () => {
    const path = join(transcripts, 'p', 'clean.jsonl');
    writeFileSync(path, 'line one\n{"a":1}\n');
    await expect(restoreHandlesInTranscript(path, injected, scope)).resolves.toEqual({
      rewritten: 0,
    });
    expect(readFileSync(path, 'utf8')).toBe('line one\n{"a":1}\n');
  });
});

describe('createTranscriptSweeper', () => {
  it('runs the pass for each session holding values on flush', async () => {
    const restore = vi.fn(() => Promise.resolve({ rewritten: 1 }));
    await resolveForSession('s1', ['github'], () =>
      Promise.resolve({ resolved: [{ slug: 'github', value: VALUE }], refused: [] }),
    );
    noteTranscript('s1', '/t/s1.jsonl');
    const sweeper = createTranscriptSweeper({ delaysMs: [60_000], restore });
    sweeper.schedule('s1');
    await sweeper.flush();
    expect(restore).toHaveBeenCalledTimes(1);
    expect(restore).toHaveBeenCalledWith('/t/s1.jsonl', new Map([['github', VALUE]]));
  });

  it('runs the pass at each scheduled delay and survives a failing pass', async () => {
    vi.useFakeTimers();
    try {
      const restore = vi.fn(() => Promise.reject(new Error('busy')));
      await resolveForSession('s1', ['github'], () =>
        Promise.resolve({ resolved: [{ slug: 'github', value: VALUE }], refused: [] }),
      );
      noteTranscript('s1', '/t/s1.jsonl');
      const sweeper = createTranscriptSweeper({ delaysMs: [10, 20], restore });
      sweeper.schedule('s1');
      await vi.advanceTimersByTimeAsync(25);
      expect(restore).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
