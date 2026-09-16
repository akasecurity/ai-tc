// Shared jsdom mount/unmount boilerplate — every jsdom suite in this package
// used to repeat its own copy of the `IS_REACT_ACT_ENVIRONMENT` flag plus a
// `createRoot`/`unmount` pair, in its own `beforeEach`/`afterEach`.
import { act, type ReactElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';

/**
 * Sets the flag `react-dom`'s `act()` needs outside a runner that sets it for
 * you. Idempotent — safe to call from every suite's own `beforeEach`, and
 * called for you by both `mountRoot` and `createRootDetached` below.
 */
export function enableActEnvironment(): void {
  (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
}

/** Renders `ui` into `root`, flushed through `act`. */
export function renderRoot(root: Root, ui: ReactElement): void {
  act(() => {
    root.render(ui);
  });
}

/**
 * Unmounts `root`, flushed through `act` — done here rather than at the end
 * of a test body, so a failing assertion earlier cannot skip it and leave a
 * live root (and a focused element) in the document for every case after it.
 */
export function unmountRoot(root: Root): void {
  act(() => {
    root.unmount();
  });
}

/**
 * A React root with no DOM presence — for a suite that only observes what
 * was rendered through closures or return values (a hook's reported value, a
 * timer/listener count), never by querying the document.
 */
export function createRootDetached(): Root {
  enableActEnvironment();
  return createRoot(document.createElement('div'));
}

export interface MountedRoot {
  host: HTMLDivElement;
  root: Root;
}

/**
 * A React root attached to a host `<div>` appended to `document.body` — for
 * a suite that queries the rendered DOM (`host.querySelector`, or
 * `document.querySelector` for portalled content).
 */
export function mountRoot(): MountedRoot {
  enableActEnvironment();
  const host = document.createElement('div');
  document.body.append(host);
  return { host, root: createRoot(host) };
}

/** Tears a `mountRoot()` result down: unmount, then remove the host div. */
export function unmountMountedRoot({ host, root }: MountedRoot): void {
  unmountRoot(root);
  host.remove();
}
