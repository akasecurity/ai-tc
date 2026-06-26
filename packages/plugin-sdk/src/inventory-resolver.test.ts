import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { LocalIdentity } from '@aka/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveInventoryContext } from './inventory-resolver.ts';

let cwd: string;

beforeEach(() => {
  cwd = mkdtempSync(join(tmpdir(), 'aka-resolver-'));
});

afterEach(() => {
  rmSync(cwd, { recursive: true, force: true });
});

const identity: LocalIdentity = {
  tenantId: '00000000-0000-0000-0000-0000000000a1',
  userId: '00000000-0000-0000-0000-0000000000b2',
  source: 'local',
};

function gitOrigin(url: string): void {
  mkdirSync(join(cwd, '.git'), { recursive: true });
  writeFileSync(join(cwd, '.git', 'config'), `[remote "origin"]\n\turl = ${url}\n`);
}

describe('resolveInventoryContext', () => {
  it('resolves host from node:os with os/arch in the descriptive bag', () => {
    const ctx = resolveInventoryContext({ cwd, tool: 'claude-code', identity });
    expect(ctx.host?.objectType).toBe('host');
    expect(ctx.host?.identityKey).toBe(hostname());
    // os_version/arch ride in the bag — not hashed into the id.
    expect(ctx.host?.attributes).toMatchObject({ host_name: hostname() });
    expect(ctx.host?.attributes).toHaveProperty('os_version');
    expect(ctx.host?.attributes).toHaveProperty('arch');
  });

  it('hashes the harness on tool only; version/interface stay in the bag', () => {
    const ctx = resolveInventoryContext({
      cwd,
      tool: 'claude-code',
      identity,
      harnessVersion: '1.2.3',
      harnessInterface: 'cli',
    });
    expect(ctx.harness?.identityKey).toBe('claude-code');
    expect(ctx.harness?.attributes).toEqual({ harness_version: '1.2.3', interface: 'cli' });
  });

  it('omits absent harness descriptors rather than writing undefined', () => {
    const ctx = resolveInventoryContext({ cwd, tool: 'claude-code', identity });
    expect(ctx.harness?.attributes).toEqual({});
  });

  it('keys the account dimension on the local identity user id', () => {
    const ctx = resolveInventoryContext({ cwd, tool: 'claude-code', identity });
    expect(ctx.account?.objectType).toBe('user');
    expect(ctx.account?.identityKey).toBe(identity.userId);
  });

  it('resolves the project from the git remote url, content-addressable across machines', () => {
    gitOrigin('git@github.com:org/payments-api.git');
    const ctx = resolveInventoryContext({ cwd, tool: 'claude-code', identity });
    expect(ctx.project).toEqual({
      url: 'git@github.com:org/payments-api.git',
      name: 'payments-api',
      attributes: {},
    });
  });

  it('omits the project entirely outside a git repo', () => {
    const ctx = resolveInventoryContext({ cwd, tool: 'claude-code', identity });
    expect(ctx.project).toBeUndefined();
  });
});
