/**
 * A handoff note and a field at or above the large-input threshold, driven
 * IN-PROCESS through the PreToolUse pipeline (see pre-tool-use-handoff.test.ts
 * for the note's ordinary cases).
 *
 * The note's re-check scans in-process with no deadline. A large field is only
 * ever scanned under the bound, so a call carrying one is not taken from the
 * note: it is decided by the pipeline, whose bounded scan refuses a field it
 * cannot finish. The runtime is the real one with two seams wrapped: `enforcedIn`
 * is counted, and `capture` is recorded and answered by the test for a large
 * text, so the result does not depend on whether this process can start a scan
 * worker.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import type { CaptureResult, PluginRuntime } from '@akasecurity/plugin-sdk';
import {
  bundledDetections,
  LARGE_INPUT_THRESHOLD_CHARS,
  shippedRegexMatchers,
} from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// What the wrapped runtime saw, and what it answers for a large text. `vi.hoisted`
// makes it exist before the mock factory below runs.
const { seen } = vi.hoisted(() => {
  const seen: {
    enforcedIn: number[];
    captures: { length: number; thresholdChars: number | undefined }[];
    largeResult: unknown;
  } = { enforcedIn: [], captures: [], largeResult: null };
  return { seen };
});

vi.mock('@akasecurity/plugin-sdk', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const realCreatePluginRuntime = actual.createPluginRuntime as (
    ...args: unknown[]
  ) => PluginRuntime;
  const threshold = actual.LARGE_INPUT_THRESHOLD_CHARS as number;
  return {
    ...actual,
    createPluginRuntime: (...args: unknown[]): PluginRuntime => {
      const runtime = realCreatePluginRuntime(...args);
      const options = args[2] as { largeInput?: { thresholdChars: number } } | undefined;
      return {
        ...runtime,
        enforcedIn: (text, context) => {
          seen.enforcedIn.push(text.length);
          return runtime.enforcedIn(text, context);
        },
        capture: (input, opts) => {
          seen.captures.push({
            length: input.text.length,
            thresholdChars: options?.largeInput?.thresholdChars,
          });
          if (input.text.length >= threshold && seen.largeResult !== null) {
            return Promise.resolve(seen.largeResult as CaptureResult);
          }
          return runtime.capture(input, opts);
        },
      };
    },
  };
});

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { tooLargeToScanMessage } from '../../src/exception-guidance.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type { HookOutput } from '../../src/hooks/shared.ts';
import { authorizeValues, recordToolHandoff } from '../../src/mod/handoff.ts';

const RULE_ID = 'secrets/twilio-key';
const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
const SECRET = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0] ?? '';

const REFUSED: CaptureResult = {
  action: 'block',
  text: null,
  findings: [],
  scanIncomplete: 'timeout',
};
const CLEAN: CaptureResult = { action: 'allow', text: null, findings: [] };

// `token <SECRET>` padded to exactly `length` characters.
function contentOf(length: number): string {
  const head = `token ${SECRET}\n`;
  return head + 'a'.repeat(length - head.length);
}

describe('a handoff note is not taken for a field at or above the large-input threshold', () => {
  let home: string;
  let dataDir: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-pre-tool-use-note-large-'));
    dataDir = join(home, '.aka', 'data');
    // Both variables, so no platform resolves the developer's own ~/.aka.
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
    expect(pack, 'the twilio rule ships in a bundled pack').toBeDefined();
    const db = openLocalDatabase(dataDir, { shippedRegexMatchers: shippedRegexMatchers() });
    try {
      db.installedPacks.recordInventory(bundledDetections());
      if (pack) db.installedPacks.setPolicy(pack.namespace, pack.packId, 'block');
    } finally {
      db.close();
    }
    seen.enforcedIn = [];
    seen.captures = [];
    seen.largeResult = null;
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    removeTree(home);
  });

  async function run(tool: string, toolInput: Record<string, unknown>): Promise<HookOutput[]> {
    const out: HookOutput[] = [];
    await runPreToolUse(
      { tool_name: tool, tool_input: toolInput, session_id: 'note-large-test', cwd: home },
      (output) => {
        out.push(output);
        return Promise.resolve();
      },
      { mode: 'hook' },
    );
    return out;
  }

  // The note the helper leaves for a value it let through: the one the ordinary
  // suite shows is honoured for a small field.
  function vouchedWrite(length: number): Record<string, unknown> {
    const write = { file_path: join(home, 'notes.txt'), content: contentOf(length) };
    recordToolHandoff(dataDir, 'Write', write, Date.now(), authorizeValues(dataDir, [SECRET]));
    return write;
  }

  const tooLarge = (tool: string): HookOutput[] => [
    {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: tooLargeToScanMessage(`${tool} call`),
      },
    },
  ];

  it.each([
    ['at the threshold', LARGE_INPUT_THRESHOLD_CHARS],
    ['above the threshold', LARGE_INPUT_THRESHOLD_CHARS * 2],
  ])(
    'a field %s goes to the bounded scan, and a scan that is refused denies the call',
    async (_label, length) => {
      const write = vouchedWrite(length);
      seen.largeResult = REFUSED;

      expect(await run('Write', write)).toEqual(tooLarge('Write'));
      expect(seen.enforcedIn).toEqual([]);
      expect(seen.captures).toEqual([{ length, thresholdChars: LARGE_INPUT_THRESHOLD_CHARS }]);
    },
  );

  it('a large field the bounded scan finds clean is allowed by the pipeline, not by the note', async () => {
    const write = vouchedWrite(LARGE_INPUT_THRESHOLD_CHARS);
    seen.largeResult = CLEAN;

    expect(await run('Write', write)).toEqual([]);
    expect(seen.enforcedIn).toEqual([]);
    expect(seen.captures).toEqual([
      { length: LARGE_INPUT_THRESHOLD_CHARS, thresholdChars: LARGE_INPUT_THRESHOLD_CHARS },
    ]);
  });

  it('one large field among small ones is enough: none of them is re-checked in-process', async () => {
    const multiEdit = {
      file_path: join(home, 'notes.txt'),
      edits: [
        { old_string: 'a', new_string: 'plain text' },
        { old_string: 'b', new_string: contentOf(LARGE_INPUT_THRESHOLD_CHARS) },
      ],
    };
    recordToolHandoff(
      dataDir,
      'MultiEdit',
      multiEdit,
      Date.now(),
      authorizeValues(dataDir, [SECRET]),
    );
    seen.largeResult = REFUSED;

    expect(await run('MultiEdit', multiEdit)).toEqual(tooLarge('MultiEdit'));
    expect(seen.enforcedIn).toEqual([]);
    expect(seen.captures.map((c) => c.length)).toContain(LARGE_INPUT_THRESHOLD_CHARS);
  });

  it('a field one character below the threshold is still taken from the note', async () => {
    const length = LARGE_INPUT_THRESHOLD_CHARS - 1;
    const write = vouchedWrite(length);
    seen.largeResult = REFUSED;

    expect(await run('Write', write)).toEqual([]);
    expect(seen.enforcedIn).toEqual([length]);
    expect(seen.captures).toEqual([]);
  });
});
