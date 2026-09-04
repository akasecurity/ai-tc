import { builtinPolicyToAction } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { applyEnforcementCeiling, resolveEnforcedAction } from '../src/runtime.ts';

// The ceiling ships DISABLED (`ENFORCEMENT_CEILING_ENABLED = false`), so nothing
// that reads the module const can execute the capped branch — the first thing to
// run it would otherwise be the flag flip itself. Both functions under test take
// `enabled` as a parameter for exactly that reason, and every case here drives it
// explicitly rather than inheriting the shipped value.

describe('applyEnforcementCeiling', () => {
  it('floors block and redact to warn in warn mode', () => {
    expect(applyEnforcementCeiling('block', 'warn', true)).toBe('warn');
    expect(applyEnforcementCeiling('redact', 'warn', true)).toBe('warn');
  });

  it('leaves every action that is not enforcement alone', () => {
    // A ceiling that floored these would be RAISING them — 'log' and 'allow' are
    // weaker than 'warn', so capping must be a floor on the strong end only.
    for (const action of ['allow', 'log', 'warn'] as const) {
      expect(applyEnforcementCeiling(action, 'warn', true)).toBe(action);
    }
  });

  it('caps nothing while the flag is off, which is how it ships', () => {
    expect(applyEnforcementCeiling('block', 'warn', false)).toBe('block');
    expect(applyEnforcementCeiling('redact', 'warn', false)).toBe('redact');
  });

  it('caps nothing in redact mode, the only other handling mode', () => {
    expect(applyEnforcementCeiling('block', 'redact', true)).toBe('block');
    expect(applyEnforcementCeiling('redact', 'redact', true)).toBe('redact');
  });
});

describe('resolveEnforcedAction — degrade, THEN cap', () => {
  const unrewritableRedact = (
    redactFallback: 'monitor' | 'warn' | 'block',
    ceilingEnabled: boolean,
  ) =>
    resolveEnforcedAction('redact', {
      policyMode: 'warn',
      redactFallback,
      rewritable: false,
      ceilingEnabled,
    });

  // The ordering this pins is the whole of the fix. Resolved 'redact' on a field
  // the host cannot rewrite degrades to `redactFallback`; the ceiling must read
  // that DEGRADED action, so a fallback of 'block' is capped exactly as a policy
  // of 'block' is. Returning the fallback early — which is what the code did —
  // lets an inability to redact buy more enforcement than the mode allows.
  it('caps a redact that fell back to block, rather than letting the fallback through', () => {
    expect(unrewritableRedact('block', true)).toBe('warn');
  });

  // The control WITHOUT which the case above is vacuous. Both readings of it end
  // at 'warn': the degradation ran and 'block' was capped, or the degradation
  // never ran and a surviving 'redact' was capped. Only this case separates them
  // — it proves the fallback is genuinely reached, so the assertion above is
  // about the cap rather than about a value that was never produced.
  it('still degrades to the fallback when the ceiling is off', () => {
    expect(unrewritableRedact('block', false)).toBe(builtinPolicyToAction('block'));
    expect(unrewritableRedact('block', false)).toBe('block');
  });

  it('leaves a rewritable redact to be capped as a redact', () => {
    const rewritable = (ceilingEnabled: boolean) =>
      resolveEnforcedAction('redact', {
        policyMode: 'warn',
        redactFallback: 'block',
        rewritable: true,
        ceilingEnabled,
      });
    // The fallback must not be consulted at all when the host CAN rewrite, so a
    // fallback of 'block' cannot leak into a rewritable field's action.
    expect(rewritable(false)).toBe('redact');
    expect(rewritable(true)).toBe('warn');
  });

  it('degrades to a fallback the ceiling would not have capped', () => {
    // 'monitor' resolves below 'warn', so the cap is a no-op here and the
    // fallback is what shows through with the ceiling either way.
    expect(unrewritableRedact('monitor', false)).toBe(builtinPolicyToAction('monitor'));
    expect(unrewritableRedact('monitor', true)).toBe(builtinPolicyToAction('monitor'));
  });

  it('passes a block straight through the degradation step', () => {
    const block = (ceilingEnabled: boolean) =>
      resolveEnforcedAction('block', {
        policyMode: 'warn',
        redactFallback: 'monitor',
        rewritable: false,
        ceilingEnabled,
      });
    // Only a resolved 'redact' degrades; a resolved 'block' on an unrewritable
    // field must not be diverted through `redactFallback`.
    expect(block(false)).toBe('block');
    expect(block(true)).toBe('warn');
  });
});
