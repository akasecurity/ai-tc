import { mkdirSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import { managedUpdateRefusal } from '@akasecurity/local-ops';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { tempHomes } from '../helpers/temp-home.ts';

// The dashboard's Update action for a plugin an organization's managed
// settings installed.
//
// The page offers no Update button for such a row, but a Server Action takes
// its id over a POST, so the button's absence is not what stops it. The shared
// apply path is, and this drives it through the action unmocked, reading a real
// ledger in a redirected home.
//
// PATH is stubbed to an empty directory for every case. The refusal happens
// before anything is probed or spawned; if it ever stopped doing so, the next
// thing reached is the PATH probe for `claude`, which then answers "not on
// your PATH" instead of resolving the developer's real CLI and running a live
// marketplace registration against their machine.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

const { applyUpdate } = await import('../../app/(app)/updates/actions.ts');

const newHome = tempHomes('aka-web-updates-managed-home-');
const newEmptyPath = tempHomes('aka-web-updates-managed-path-');

function writeLedger(records: unknown[]): void {
  const dir = join(osHome.dir, '.claude', 'plugins');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'installed_plugins.json'),
    JSON.stringify({ version: 2, plugins: { 'ai-tc@akasecurity': records } }),
  );
}

beforeEach(() => {
  osHome.dir = newHome();
  vi.stubEnv('PATH', newEmptyPath());
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('applyUpdate — an install an organization manages', () => {
  it('refuses it, and says what does apply an update', async () => {
    writeLedger([{ scope: 'managed', version: '0.9.13' }]);

    const result = await applyUpdate('claude-code');

    expect(result.ok).toBe(false);
    expect(result.output).toBe(managedUpdateRefusal('Claude Code'));
    expect(result.restartRequired).toBe(false);
  });

  it('refuses it when a user copy sits beside the managed one', async () => {
    writeLedger([
      { scope: 'user', version: '0.9.14' },
      { scope: 'managed', version: '0.9.13' },
    ]);

    const result = await applyUpdate('claude-code');

    expect(result.output).toBe(managedUpdateRefusal('Claude Code'));
  });

  it('reaches the apply path for a user-scope install (positive control)', async () => {
    // The same action and the same empty PATH: a user-scope install gets past
    // the managed check and stops at the PATH probe, so the refusals above come
    // from the scope rather than from anything else in this setup.
    writeLedger([{ scope: 'user', version: '0.9.13' }]);

    const result = await applyUpdate('claude-code');

    expect(result.ok).toBe(false);
    expect(result.output).toContain("the `claude` CLI isn't on your PATH");
    expect(result.output).not.toContain('managed by your organization');
  });
});
