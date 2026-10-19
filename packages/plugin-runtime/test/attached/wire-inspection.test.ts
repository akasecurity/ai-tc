import { ToolCallInspection, type ToolCallInspectionInput } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { NAME_HASH_DOMAIN, toWireInspection } from '../../src/attached/gateway.ts';

// Assembled at runtime so no literal here reads as a secret.
const VALUE_MASK = ['A', '*'.repeat(18), 'E'].join('');
const NAME = ['AWS', 'ACCESS', 'KEY', 'ID'].join('_');
const KEY = { keyVersion: 3, key: new Uint8Array(32).fill(7) };

const features = {
  ruleId: 'secrets/aws-access-key',
  category: 'secret' as const,
  validators: [],
  corroborated: false,
  shape: {
    length: 20,
    classes: ['digit' as const, 'upper' as const],
    knownPrefix: 'AKIA' as const,
    entropyBucket: 'high' as const,
  },
  placeholder: false,
  pathClass: 'source' as const,
  name: 'secret_like' as const,
  nearby: [],
};

const inspection: ToolCallInspectionInput = {
  ruleId: 'secrets/aws-access-key',
  ruleName: 'AWS access key',
  ruleVersion: '1',
  category: 'secret',
  severity: 'critical',
  span: { start: 4, end: 24 },
  maskedMatch: VALUE_MASK,
  actionTaken: 'log',
  confidence: 0.9,
  line: 2,
  col: 5,
  variableName: NAME,
  features,
};

describe('toWireInspection', () => {
  it('forwards the features and a keyed hash of the name, never the name itself', () => {
    const wire = toWireInspection(inspection, KEY);
    expect(wire.features).toEqual(features);
    expect(wire.nameHash).toMatch(/^v3\.[A-Za-z0-9_-]{43}$/);
    expect(JSON.stringify(wire)).not.toContain(NAME);
    expect(wire).not.toHaveProperty('line');
    expect(ToolCallInspection.strict().safeParse(wire).success).toBe(true);
  });

  it('gives the same hash for the same name under the same key, and a different one under another key', () => {
    const a = toWireInspection(inspection, KEY).nameHash;
    expect(toWireInspection(inspection, KEY).nameHash).toBe(a);
    expect(
      toWireInspection(inspection, { keyVersion: 3, key: new Uint8Array(32).fill(8) }).nameHash,
    ).not.toBe(a);
    expect(NAME_HASH_DOMAIN).not.toBe('aka:sighting:v1');
  });

  it('leaves the hash off without a key, and both fields off for an inspection with neither', () => {
    expect(toWireInspection(inspection, undefined)).not.toHaveProperty('nameHash');
    const bare: ToolCallInspectionInput = {
      ...inspection,
      variableName: undefined,
      features: undefined,
    };
    const wire = toWireInspection(bare, KEY);
    expect(wire).not.toHaveProperty('nameHash');
    expect(wire).not.toHaveProperty('features');
  });
});
