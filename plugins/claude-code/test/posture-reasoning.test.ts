import { severityFloorPosture } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { PostureLooseningError, validateTightenOnly } from '../src/posture-reasoning.ts';

describe('validateTightenOnly', () => {
  it('accepts a monitor -> warn tighten (config floors to monitor) and keeps every other category at the severity floor', () => {
    const floor = severityFloorPosture();
    expect(floor.config).toBe('monitor'); // sanity: this is a genuine raise from the floor

    const accepted = validateTightenOnly({ config: 'warn' });

    expect(accepted.config).toBe('warn');
    for (const category of Object.keys(floor) as DetectionCategory[]) {
      if (category === 'config') continue;
      expect(accepted[category]).toBe(floor[category]);
    }
  });

  it('accepts an evidence-grounded financial tighten above its floor (warn -> redact, e.g. Stripe + customer models)', () => {
    const floor = severityFloorPosture();
    expect(floor.financial).toBe('warn'); // sanity: financial already floors at warn

    expect(validateTightenOnly({ financial: 'redact' }).financial).toBe('redact');
  });

  it('rejects a proposal that lowers a category below its severity floor (secret warn -> monitor)', () => {
    const floor = severityFloorPosture();
    expect(floor.secret).toBe('warn'); // sanity: monitor is strictly below this floor

    expect(() => validateTightenOnly({ secret: 'monitor' })).toThrow(PostureLooseningError);
  });

  it('an empty/no-deviation proposal returns exactly the floor, unmodified', () => {
    const floor = severityFloorPosture();

    expect(validateTightenOnly({})).toEqual(floor);
  });

  it('accepts a proposal exactly equal to the floor (no-op tighten)', () => {
    const floor = severityFloorPosture();

    expect(validateTightenOnly({ secret: floor.secret })).toEqual(floor);
  });

  it('accepts an explicit block override (raise several ranks above floor)', () => {
    const accepted = validateTightenOnly({ pii: 'block' });
    expect(accepted.pii).toBe('block');
  });

  it('the rejection error carries the category, floor, and proposed levels', () => {
    try {
      validateTightenOnly({ secret: 'monitor' });
      expect.fail('expected validateTightenOnly to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(PostureLooseningError);
      const e = err as PostureLooseningError;
      expect(e.category).toBe('secret');
      expect(e.floor).toBe('warn');
      expect(e.proposed).toBe('monitor');
    }
  });

  it('accepts a custom floor override, rejecting a proposal below it', () => {
    const customFloor = { ...severityFloorPosture(), custom: 'redact' as BuiltinPolicyId };

    expect(() => validateTightenOnly({ custom: 'warn' }, customFloor)).toThrow(
      PostureLooseningError,
    );
    expect(validateTightenOnly({ custom: 'block' }, customFloor).custom).toBe('block');
  });
});
