import { describe, expect, it } from 'vitest';

import { applyCliUpdate, applyPluginUpdate, installAgentPlugin } from '../src/apply.ts';
import type { InstallChannel } from '../src/install-channel.ts';

// The mutating paths (npm / claude spawns) are exercised end-to-end by `aka
// update`; here we pin the fail-closed validation — no child process may ever
// run for an id the static registry doesn't know.

// A channel that cannot be updated in-process must be REFUSED, not run. Only
// the refusing channels are driven through applyCliUpdate here: a runnable one
// would spawn the real package manager against the developer's own machine,
// which is why the runnable half is asserted on `planCliUpdate` instead
// (src/install-channel.test.ts) where no spawn is reachable.
describe('applyCliUpdate refuses a channel it cannot update', () => {
  const refusing: [string, InstallChannel][] = [
    ['sea', { kind: 'sea', execPath: '/usr/local/bin/aka', installRoot: null }],
    ['homebrew', { kind: 'homebrew', packageDir: '/opt/homebrew/Cellar/aka/0.9.3' }],
    ['dev', { kind: 'dev', packageDir: '/src/ai-tc' }],
    ['unknown', { kind: 'unknown', detail: 'nowhere in particular' }],
  ];

  for (const [name, channel] of refusing) {
    it(`returns advice rather than spawning for a ${name} install`, () => {
      // Reaching a spawn at all is the failure: every one of these has a null
      // command, so an unguarded `plan.command.bin` throws instead of refusing.
      const res = applyCliUpdate(channel);
      expect(res.ok).toBe(false);
      expect(res.output).toContain('Cannot update automatically');
      expect(res.output).toContain('Run:');
      // Never the blind global install this surface used to run unconditionally.
      expect(res.output).not.toContain('npm install -g @akasecurity/cli@latest\n');
    });
  }

  it('names what to run instead, so the refusal is actionable', () => {
    const sea = applyCliUpdate({ kind: 'sea', execPath: '/usr/local/bin/aka', installRoot: null });
    expect(sea.output).toContain('install.');
  });
});

describe('applyPluginUpdate / installAgentPlugin id validation', () => {
  it('fails closed on an unknown agent id', () => {
    const res = applyPluginUpdate('definitely-not-an-agent');
    expect(res.ok).toBe(false);
    expect(res.output).toContain('unknown agent');
  });

  it('never treats flag-like input as installable', () => {
    const res = installAgentPlugin('--registry=https://evil.example');
    expect(res.ok).toBe(false);
    expect(res.output).toContain('unknown agent');
  });
});
