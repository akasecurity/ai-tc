// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DetailFallback } from '../../src/inventory/chips.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

let mounted: MountedRoot;
beforeEach(() => {
  mounted = mountRoot();
});
afterEach(() => {
  unmountMountedRoot(mounted);
});

const message = () => mounted.host.querySelector('[class*="place-items-center"]');
const alert = () => mounted.host.querySelector('[role="alert"]');

function render(props: Partial<Parameters<typeof DetailFallback>[0]> = {}) {
  renderRoot(
    mounted.root,
    <DetailFallback
      message="Loading credential…"
      onBack={vi.fn()}
      backLabel="Credentials"
      {...props}
    />,
  );
}

describe('DetailFallback', () => {
  it('waits quietly while there is nothing to show yet', () => {
    render();
    expect(alert()).toBeNull();
    expect(message()?.className).toContain('text-text-3');
  });

  it('announces a failure and colours it as one', () => {
    render({ message: 'No such credential', tone: 'alert' });
    expect(alert()?.textContent).toBe('No such credential');
    expect(alert()?.className).toContain('text-sev-critical-ink');
    expect(alert()?.className).not.toContain('text-text-3');
  });

  it('re-inserts the message when the tone changes, so the alert is read out', () => {
    render();
    const quiet = message();
    render({ message: 'No such credential', tone: 'alert' });

    // A live region is announced when it is INSERTED carrying its text. Without
    // the tone-keyed node React would update this element in place, the role
    // would appear on an existing node, and nothing would be read out.
    expect(quiet).not.toBeNull();
    expect(quiet?.isConnected).toBe(false);
    expect(alert()).not.toBe(quiet);
  });

  it('keeps the way back on both tones', () => {
    render({ tone: 'alert' });
    expect(mounted.host.querySelector('button[aria-label="Back to Credentials"]')).not.toBeNull();
  });
});
