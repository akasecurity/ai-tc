// @vitest-environment jsdom
//
// The unassigned option's pressed and refused states are covered by static
// markup in detection-unassigned-policy.test.ts, but those attributes hold even
// for a button whose click handler was dropped. This file proves a real click
// reaches onUnassignPolicy when the option is live, and is refused when it is
// not.
import type { DetectionDetail } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DetectionDetailView } from '../../src/detections/DetectionDetailView.tsx';
import type { DetectionPolicyFloor } from '../../src/detections/policy-floor.ts';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

const UNASSIGNED_POLICY = {
  label: 'Category policy',
  description: 'Follows the policy assigned to its category.',
};

const LOCKED_WARN_FLOOR: DetectionPolicyFloor = { floor: 'warn', locked: true };

function detection(overrides: Partial<DetectionDetail> = {}): DetectionDetail {
  return {
    id: 'aka/secrets',
    name: 'Secrets',
    version: '1.0.0',
    enabled: true,
    origin: 'library',
    ruleCount: 1,
    namespace: 'aka',
    packId: 'secrets',
    editedAt: '2026-01-01T00:00:00.000Z',
    findingsLast30d: 0,
    update: null,
    modified: false,
    policyId: 'warn',
    rules: [
      {
        id: 'secrets/example',
        name: 'Example',
        category: 'secret',
        severity: 'high',
        matcher: { type: 'keyword', keywords: ['example'], caseSensitive: false },
      },
    ],
    ...overrides,
  };
}

let mounted: MountedRoot;

beforeEach(() => {
  mounted = mountRoot();
});

afterEach(() => {
  unmountMountedRoot(mounted);
});

function unassignedOption(): HTMLButtonElement {
  const el = mounted.host.querySelector('button[data-slot="policy-unassigned-option"]');
  if (!(el instanceof HTMLButtonElement)) throw new Error('no unassigned option rendered');
  return el;
}

function mountPane(props: Partial<Parameters<typeof DetectionDetailView>[0]>) {
  const onUnassignPolicy = vi.fn();
  const onChangePolicy = vi.fn();
  renderRoot(
    mounted.root,
    <DetectionDetailView
      d={detection()}
      onOpenRule={() => undefined}
      onChangePolicy={onChangePolicy}
      unassignedPolicy={UNASSIGNED_POLICY}
      onUnassignPolicy={onUnassignPolicy}
      {...props}
    />,
  );
  return { onUnassignPolicy, onChangePolicy };
}

describe('DetectionDetailView unassigned option, clicked', () => {
  it('reaches onUnassignPolicy, and only it, on a real click', () => {
    const { onUnassignPolicy, onChangePolicy } = mountPane({});
    act(() => {
      unassignedOption().click();
    });
    expect(onUnassignPolicy).toHaveBeenCalledTimes(1);
    expect(onUnassignPolicy).toHaveBeenCalledWith();
    expect(onChangePolicy).not.toHaveBeenCalled();
  });

  it('refuses the click under editRefusal', () => {
    const { onUnassignPolicy } = mountPane({ editRefusal: 'Read-only here.' });
    const option = unassignedOption();
    // Focusable, so this is a genuine click on a live element.
    expect(option.disabled).toBe(false);
    act(() => {
      option.click();
    });
    expect(onUnassignPolicy).not.toHaveBeenCalled();
  });

  it('refuses the click under a locked floor', () => {
    const { onUnassignPolicy } = mountPane({ policyFloor: LOCKED_WARN_FLOOR });
    act(() => {
      unassignedOption().click();
    });
    expect(onUnassignPolicy).not.toHaveBeenCalled();
  });
});
