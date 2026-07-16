import { describe, expect, it } from 'vitest';

import { applyPluginUpdate, installAgentPlugin } from '../src/apply.ts';

// The mutating paths (npm / claude spawns) are exercised end-to-end by `aka
// update`; here we pin the fail-closed validation — no child process may ever
// run for an id the static registry doesn't know.

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
