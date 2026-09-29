// The two fragments the CLI's report and the dashboard's card both put around
// MANAGED_PLUGIN_ADVICE for one managed row. Each surface frames the note its
// own way; these parts are shared so a reword cannot leave the two surfaces
// describing the same install differently.
import { describe, expect, it } from 'vitest';

import type { ComponentStatus } from '../../src/zod/updates.ts';
import { managedPluginNoteParts } from '../../src/zod/updates.ts';

const row = (over: Partial<ComponentStatus> = {}): ComponentStatus => ({
  id: 'claude-code',
  name: 'Claude Code',
  kind: 'plugin',
  installed: '0.9.13',
  latest: '0.9.14',
  updateAvailable: false,
  managedInstall: { ref: 'org-release-8', pending: true },
  ...over,
});

describe('managedPluginNoteParts', () => {
  it('names the ref and the version on its way', () => {
    expect(managedPluginNoteParts(row())).toEqual({
      ref: ' (marketplace ref org-release-8)',
      lead: 'v0.9.14 is on its way. ',
    });
  });

  it('says nothing is on its way when the pin is not ahead', () => {
    expect(managedPluginNoteParts(row({ managedInstall: { pending: false } }))).toEqual({
      ref: '',
      lead: '',
    });
  });

  it('names no version when the pin could not be read', () => {
    // `pending` is false by construction here, but the fragment must not print
    // "vnull" if a producer ever disagreed.
    expect(
      managedPluginNoteParts(row({ latest: null, managedInstall: { pending: true } })).lead,
    ).toBe('');
  });

  it('returns empty fragments for a row nobody manages', () => {
    const unmanaged = row();
    delete unmanaged.managedInstall;
    expect(managedPluginNoteParts(unmanaged)).toEqual({
      ref: '',
      lead: '',
    });
  });
});
