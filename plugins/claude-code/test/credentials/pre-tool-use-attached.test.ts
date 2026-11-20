import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { useLoopbackServer } from '../../../../packages/remote/test/helpers/loopback.ts';
import { forgetSessionCredentials } from '../../src/credentials/session-credentials.ts';
import {
  postToolUseWithCredentials,
  preToolUseWithCredentials,
  scrubbableCommand,
} from '../../src/credentials/tool-use.ts';
import { runPostToolUse } from '../../src/hooks/post-tool-use-run.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type { HookOutput } from '../../src/hooks/shared.ts';

const server = useLoopbackServer();
// The response scan's own deadline runs from process start; a slow worker would pass it before
// the test body and scan nothing, which would make the no-value assertions vacuous.
const NO_SCAN_DEADLINE = { scanDeadline: { at: Number.POSITIVE_INFINITY, now: () => 0 } };
// Shaped like an AWS access key id, so the bundled rules would flag it if it
// were ever scanned; not any rule's own example, which the store holds.
const VALUE = ['AKIA', 'Q7RT2MXW9ZPLK4VB'].join('');
let home: string;
let seen: string[];

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-cred-attached-'));
  vi.stubEnv('HOME', home);
  vi.stubEnv('USERPROFILE', home);
  mkdirSync(join(home, '.aka', 'data'), { recursive: true });
  seen = [];
  server.reply((req, res) => {
    seen.push(`${req.method ?? ''} ${req.url ?? ''}`);
    if (req.url === '/v1/vault/resolve') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          resolved: [{ slug: 'aws', value: VALUE }],
          refused: [{ slug: 'denied', reason: 'no_grant' }],
        }),
      );
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{}');
  });
  const base = join(home, '.aka');
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: server.origin, attachedAt: '2026-11-17T10:00:00.000Z' },
    },
    base,
  );
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: 1,
    endpoint: server.origin,
    apiKey: 'not-a-real-key-cred',
  });
});
afterEach(() => {
  forgetSessionCredentials();
  vi.unstubAllEnvs();
  rmSync(home, { recursive: true, force: true });
});

function everyFileText(dir: string): string {
  let text = '';
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    text += statSync(path).isDirectory() ? everyFileText(path) : readFileSync(path, 'latin1');
  }
  return text;
}

describe('credential handles through the real pipelines on an attached machine', () => {
  it('substitutes after the scan, scrubs the echo, and leaves no value on disk', async () => {
    const pre: HookOutput[] = [];
    await preToolUseWithCredentials(
      {
        session_id: 'session-attached',
        transcript_path: join(home, 'nowhere.jsonl'),
        cwd: home,
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'aws --key [[aka:cred:aws]] --other [[aka:cred:denied]]' },
      },
      (output) => {
        pre.push(output);
        return Promise.resolve();
      },
      (input, emit) => runPreToolUse(input, emit, { mode: 'hook' }),
      { persistent: true },
    );
    expect(seen).toContain('POST /v1/vault/resolve');
    expect(pre).toHaveLength(1);
    const decided = pre[0] as {
      hookSpecificOutput: { updatedInput: { command: string }; permissionDecision?: string };
      systemMessage: string;
    };
    expect(decided.hookSpecificOutput.updatedInput.command).toBe(
      scrubbableCommand(`aws --key ${VALUE} --other [[aka:cred:denied]]`),
    );
    expect(decided.hookSpecificOutput.permissionDecision).toBeUndefined();
    expect(decided.systemMessage).not.toContain(VALUE);

    const post: HookOutput[] = [];
    await postToolUseWithCredentials(
      {
        session_id: 'session-attached',
        transcript_path: join(home, 'nowhere.jsonl'),
        cwd: home,
        hook_event_name: 'PostToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'x' },
        tool_response: {
          stdout: `key is ${VALUE}\n`,
          stderr: '',
          interrupted: false,
          isImage: false,
        },
      },
      (output) => {
        post.push(output);
        return Promise.resolve();
      },
      (input, emit) => runPostToolUse(input, emit, NO_SCAN_DEADLINE),
    );
    expect(JSON.stringify(post)).toContain('key is [[aka:cred:aws]]');
    expect(JSON.stringify(post)).not.toContain(VALUE);
    expect(everyFileText(home)).not.toContain(VALUE);
  });

  it('control: the same output scanned without an injected value is recorded', async () => {
    await runPostToolUse(
      {
        session_id: 'session-control',
        cwd: home,
        hook_event_name: 'PostToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'x' },
        tool_response: {
          stdout: `key is ${VALUE}\n`,
          stderr: '',
          interrupted: false,
          isImage: false,
        },
      },
      () => Promise.resolve(),
      NO_SCAN_DEADLINE,
    );
    expect(everyFileText(home)).toContain(VALUE);
  });
});
