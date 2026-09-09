// @vitest-environment jsdom
//
// What the Scan page SHOWS about the forward, which neither neighbouring suite
// can see: the action suite pins what the forward did, and forward-copy.test.ts
// pins the sentences, but nothing between them asserts the page puts one on
// screen. Deleting the paragraph leaves both of those green.
//
// The result only exists after a click, so this drives the component rather
// than rendering it statically — the state the line reads from is set by the
// transition the button starts, and a static render never runs one.
//
// Two things are asserted beyond "a sentence appears". It sits AFTER the
// recorded counts, because it is about that same register and reads as an
// unrelated status anywhere else. And a refusal is coloured as one: the class
// is the only signal that a fleet's view of this project is now behind the
// user's own, and swapping the branches renders text that says "not forwarded"
// in the tone of a success.
import type { SharesForwardOutcome } from '@akasecurity/local-ops';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { ScanResult } from '../../app/(app)/scan/actions.ts';

// The page's own Server Actions cannot run here, and stubbing `runScan` is what
// lets a case choose the outcome. `listDirectory` is the Browse panel's, unused
// by anything below but part of the module this replaces.
const runScan = vi.fn<(path: string) => Promise<ScanResult>>();
vi.mock('../../app/(app)/scan/actions', () => ({
  runScan: (path: string) => runScan(path),
  listDirectory: vi.fn(),
}));

const { ScanClient } = await import('../../app/(app)/scan/ScanClient.tsx');
const { describeForward } = await import('../../app/(app)/scan/forward-copy.ts');

const LABEL = 'Acme Prod';

// A register with something in it, so the counts paragraph the forward line has
// to follow is on the page at all.
function scanned(forward?: SharesForwardOutcome): ScanResult {
  return {
    ok: true,
    scanned: 1,
    findings: 0,
    egress: {
      destinations: 1,
      endpoints: 1,
      callSites: 2,
      truncated: false,
      droppedFiles: [],
    },
    ...(forward === undefined ? {} : { forward }),
  };
}

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  runScan.mockReset();
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

/** Mount the page and click Scan, which is the only way a result reaches it. */
async function scan(result: ScanResult): Promise<void> {
  runScan.mockResolvedValue(result);
  act(() => {
    root.render(createElement(ScanClient, { enabledRuleCount: 12 }));
  });
  const button = [...container.querySelectorAll('button')].find((b) => b.textContent === 'Scan');
  if (button === undefined) throw new Error('no Scan button to click');
  await act(async () => {
    button.click();
    await Promise.resolve();
  });
}

/** Every paragraph on the page, in document order. */
function paragraphs(): HTMLParagraphElement[] {
  return [...container.querySelectorAll('p')];
}

/**
 * The paragraph whose whole text is `text`.
 *
 * Throws rather than returning undefined so an absent line names the sentence
 * it was looking for, instead of failing later on a property of nothing.
 */
function paragraph(text: string): HTMLParagraphElement {
  const found = paragraphs().find((p) => p.textContent === text);
  if (found === undefined) throw new Error(`no paragraph reading: ${text}`);
  return found;
}

describe('the Scan page forward line', () => {
  it('renders the outcome under the recorded counts', async () => {
    const forward: SharesForwardOutcome = {
      status: 'forwarded',
      endpoint: LABEL,
      callSites: 2,
    };
    await scan(scanned(forward));

    // Taken from the copy module rather than restated: this suite asserts the
    // page renders the sentence, and which sentence it is belongs to the suite
    // that owns the wording.
    const sentence = describeForward(forward);
    expect(sentence).not.toBeNull();
    const line = paragraph(sentence ?? '');

    // Under the register it describes, not above it or somewhere else.
    const rendered = paragraphs();
    const counts = rendered.findIndex((p) => p.textContent.startsWith('Data shares:'));
    expect(counts, 'the recorded counts are not on the page').toBeGreaterThan(-1);
    expect(rendered.indexOf(line)).toBeGreaterThan(counts);

    // A success is toned like the counts it follows.
    expect(line.className).toContain('text-text-2');
    expect(line.className).not.toContain('text-sev-medium-ink');
  });

  it('tones a refusal as a refusal', async () => {
    const forward: SharesForwardOutcome = {
      status: 'failed',
      endpoint: 'https://aka.acme.internal',
      kind: 'forbidden',
    };
    await scan(scanned(forward));

    const line = paragraph(describeForward(forward) ?? '');
    expect(line.className).toContain('text-sev-medium-ink');
    expect(line.className).not.toContain('text-text-2');
  });

  it('renders nothing extra for a scan that forwarded nowhere', async () => {
    // The negative control, and the standalone install's whole experience: with
    // no outcome to report the page is what it was before it could forward.
    await scan(scanned());

    expect(container.textContent).not.toContain('Forwarded to');
    expect(container.textContent).not.toContain('Not forwarded to');
  });
});
