import { expect, mock, test } from 'claude-code/testing';
import type { SessionAppendInput } from 'claude-code';

import { HOME, SESSION_CWD } from './harness.js';
import type { HelperRequest, Hooks } from './harness.js';

// The tool-result door hands each tool result to the helper to be forwarded,
// cut to the cap the capture settings name, without holding the row.

const SETTINGS_PATH = [HOME, '.aka', 'data', 'attached-capture.json'].join('/');

let nextMtime = 900;

function world(on: Hooks, settings: string | undefined): HelperRequest[] {
  nextMtime += 1;
  const mtimeMs = nextMtime;
  const asked: HelperRequest[] = [];
  mock.env(on, { HOME });
  on('session.id', () => ({ value: 'session-1' }));
  on('session.cwd', () => ({ value: SESSION_CWD }));
  on('clock.now', () => ({ value: 1_000 }));
  on('fs.write', () => ({ value: undefined }));
  on('fs.stat', (_$, e) =>
    e.path === SETTINGS_PATH && settings !== undefined
      ? { value: { kind: 'file' as const, size: settings.length, mtimeMs, isLink: false } }
      : { deny: 'ENOENT' },
  );
  on('fs.read', (_$, e) =>
    e.path === SETTINGS_PATH && settings !== undefined ? { value: settings } : { deny: 'ENOENT' },
  );
  on('process.run', (_$, e) => {
    asked.push({
      argv: e.argv,
      stdin: JSON.parse(e.init?.stdin ?? 'null') as HelperRequest['stdin'],
      timeoutMs: e.init?.timeoutMs,
    });
    return {
      value: {
        exitCode: 1,
        stdout: '',
        stderr: '',
        isStdoutTruncated: false,
        isStderrTruncated: false,
      },
    };
  });
  return asked;
}

function resultRow(text: string): SessionAppendInput {
  return {
    message: {
      type: 'user',
      role: 'user',
      content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: text }],
    },
    door: 'tool-result',
    origin: { kind: 'tool', tool: 'Read' },
    uuid: 'row-forward',
  };
}

async function settle(asked: HelperRequest[], count: number): Promise<void> {
  for (let i = 0; i < 50 && asked.length < count; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

test('hands a tool result to the helper, cut to the cap, when the settings forward it', async ($, on) => {
  const asked = world(on, JSON.stringify({ v: 1, toolOutput: { maxChars: 5 } }));
  const appended = mock.session(on).appended;

  await $.session.append(resultRow('abcdefghij'));
  await settle(asked, 1);

  expect(appended()).toHaveLength(1);
  expect(asked).toHaveLength(1);
  expect(asked[0]?.stdin.text).toBe('abcde');
  expect(asked[0]?.stdin.row).toEqual({
    door: 'tool-result',
    tool: 'Read',
    forward: { maxChars: 5, length: 10 },
  });
});

test('hands nothing over without the settings file', async ($, on) => {
  const asked = world(on, undefined);

  await $.session.append(resultRow('abcdefghij'));
  await settle(asked, 1);

  expect(asked).toHaveLength(0);
});

test('hands nothing over when the settings name no tool output', async ($, on) => {
  const asked = world(on, JSON.stringify({ v: 1, sessionHold: true }));

  await $.session.append(resultRow('abcdefghij'));
  await settle(asked, 1);

  expect(asked).toHaveLength(0);
});
