// @vitest-environment jsdom
//
// The Scan page's pre-click notice on a SCOPED machine. The register goes only
// for a project that is an enrolled repository, so the notice and the box's
// label must say so; the machine-wide wording would promise a send that a
// not-enrolled project never makes.
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The page's own Server Actions cannot run here, and nothing below clicks Scan.
vi.mock('../../app/(app)/scan/actions', () => ({
  runScan: vi.fn(),
  listDirectory: vi.fn(),
}));

const { ScanClient } = await import('../../app/(app)/scan/ScanClient.tsx');

const LABEL = 'Acme Prod';

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
});

function mount(attachmentMode: 'machine' | 'scoped' | undefined): void {
  act(() => {
    root.render(
      createElement(ScanClient, { enabledRuleCount: 12, attachedTo: LABEL, attachmentMode }),
    );
  });
}

/** The label beside the per-scan forwarding box. */
function boxLabel(): string {
  const box = container.querySelector('input[type="checkbox"]');
  const label = box?.closest('label');
  if (label === null || label === undefined) throw new Error('no forwarding box on the page');
  return label.textContent;
}

describe('the Scan page notice on a scoped machine', () => {
  it('says the register goes only for an enrolled repository, and names the verb', () => {
    mount('scoped');
    const text = container.textContent;
    expect(text).toContain(`This machine is attached to ${LABEL} as a personal device`);
    expect(text).toContain('only when the project is a repository enrolled with `aka enroll`');
    expect(text).toContain('otherwise it stays on this machine');
    expect(boxLabel()).toBe(`Send the Data Shares register to ${LABEL} if the project is enrolled`);
  });

  it('keeps the machine-wide wording on a machine-wide machine', () => {
    mount('machine');
    expect(container.textContent).toContain('is sent there.');
    expect(container.textContent).not.toContain('aka enroll');
    expect(boxLabel()).toBe(`Send the Data Shares register to ${LABEL}`);
  });

  it('keeps the machine-wide wording when the page reports no mode', () => {
    // An unreported mode is not a scoped one, and the wider claim is the safe
    // one: the notice says the register is sent, with no enrolment condition.
    mount(undefined);
    expect(container.textContent).toContain(`This machine is attached to ${LABEL}.`);
    expect(container.textContent).toContain('is sent there.');
    expect(container.textContent).not.toContain('personal device');
    expect(container.textContent).not.toContain('aka enroll');
    expect(boxLabel()).toBe(`Send the Data Shares register to ${LABEL}`);
  });
});
