/**
 * When the call's scan budget is spent before the extracted payloads are
 * scanned, the command is scanned again with every rule on rather than allowed
 * on the strength of a payload scan that never ran.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import type { CaptureResult, PluginRuntime } from '@akasecurity/plugin-sdk';
import { bundledDetections, shippedRegexMatchers } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type { HookOutput } from '../../src/hooks/shared.ts';

const spent = vi.hoisted(() => ({ value: false }));
const refusePayloads = vi.hoisted(() => ({ value: false }));

// The runtime is the real one; a code_change capture (an extracted payload) is
// answered as a scan that did not finish when the test asks for it.
vi.mock('@akasecurity/plugin-sdk', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const real = actual.createPluginRuntime as (...args: unknown[]) => PluginRuntime;
  return {
    ...actual,
    createPluginRuntime: (...args: unknown[]): PluginRuntime => {
      const runtime = real(...args);
      return {
        ...runtime,
        capture: (input, opts) =>
          refusePayloads.value && input.kind === 'code_change'
            ? Promise.resolve({
                action: 'block',
                text: null,
                findings: [],
                scanIncomplete: 'timeout',
              } satisfies CaptureResult)
            : runtime.capture(input, opts),
      };
    },
  };
});

vi.mock('../../src/hooks/large-input.ts', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  callScanBudgetSpent: () => spent.value,
}));

const pack = bundledDetections().find((p) =>
  p.rules.some((r) => r.id === 'code-flaws/deser-pickle'),
);

describe('a Bash command whose payload scan runs out of budget', () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-bash-budget-'));
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
    const db = openLocalDatabase(join(home, '.aka', 'data'), {
      shippedRegexMatchers: shippedRegexMatchers(),
    });
    try {
      db.installedPacks.recordInventory(bundledDetections());
      if (pack) db.installedPacks.setPolicy(pack.namespace, pack.packId, 'block');
    } finally {
      db.close();
    }
  });

  afterEach(() => {
    spent.value = false;
    refusePayloads.value = false;
    vi.unstubAllEnvs();
    removeTree(home);
  });

  async function denied(command: string): Promise<boolean> {
    const out: HookOutput[] = [];
    await runPreToolUse(
      { tool_name: 'Bash', tool_input: { command }, session_id: 'budget-test', cwd: home },
      (output) => {
        out.push(output);
        return Promise.resolve();
      },
      { mode: 'hook' },
    );
    return out.some(
      (o) =>
        'hookSpecificOutput' in o &&
        (o.hookSpecificOutput as { permissionDecision?: string }).permissionDecision === 'deny',
    );
  }

  const command = "cat > notes.txt <<'EOF'\nobj = pickle.loads(blob)\nEOF\n";

  it('refuses the call when the payload scan itself comes back incomplete', async () => {
    refusePayloads.value = true;
    expect(await denied(command)).toBe(true);
  });

  it('control: with budget left the .txt payload passes', async () => {
    expect(await denied(command)).toBe(false);
  });

  it('scans the command again with every rule on, so the call is not allowed silently', async () => {
    spent.value = true;
    expect(await denied(command)).toBe(true);
  });
});
