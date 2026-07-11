import type { DetectionListItem } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { renderDetectionsTable } from './detections.ts';

function item(overrides: Partial<DetectionListItem>): DetectionListItem {
  return {
    id: 'aka/secrets',
    name: 'Secrets',
    version: '2.0.0',
    enabled: true,
    origin: 'library',
    namespace: 'aka',
    packId: 'secrets',
    ruleCount: 21,
    ...overrides,
  };
}

describe('renderDetectionsTable', () => {
  it('renders one aligned row per pack with update status', () => {
    const table = renderDetectionsTable([
      item({}),
      item({
        id: 'aka/core-pii',
        packId: 'core-pii',
        version: '2.0.0',
        latestVersion: '2.1.0',
        ruleCount: 14,
        enabled: false,
        policyId: 'redact',
      }),
    ]);

    const lines = table.split('\n');
    expect(lines[0]).toMatch(/Pack\s+Installed\s+Latest\s+Rules\s+Enabled\s+Policy\s+Status/);
    expect(lines[1]).toContain('aka/secrets');
    expect(lines[1]).toContain('✓ up to date');
    expect(lines[1]).toContain('monitor'); // unassigned policy renders as monitor
    expect(lines[2]).toContain('aka/core-pii');
    expect(lines[2]).toContain('v2.1.0');
    expect(lines[2]).toContain('⬆ update available');
    expect(lines[2]).toContain('redact');
    expect(lines[2]).toContain('no');
  });
});
