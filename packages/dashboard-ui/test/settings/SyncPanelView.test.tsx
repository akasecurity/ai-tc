import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import {
  type SyncKindRow,
  SyncPanelView,
  type SyncPanelViewProps,
} from '../../src/settings/SyncPanelView.tsx';

const NOW = Date.parse('2026-09-12T10:00:00.000Z');

const row = (over: Partial<SyncKindRow> = {}): SyncKindRow => ({
  kind: 'llm_call',
  label: 'Model calls',
  synced: 40,
  queued: 60,
  notSent: 0,
  total: 100,
  ...over,
});

const render = (over: Partial<SyncPanelViewProps> = {}): string =>
  renderToStaticMarkup(
    <SyncPanelView
      state={{ status: 'ready', kinds: [row()] }}
      deployment="plane.example"
      renderedAt={NOW}
      running={false}
      {...over}
    />,
  );

describe('SyncPanelView', () => {
  it('renders one bar per kind it is given, and no others', () => {
    const html = render({
      state: { status: 'ready', kinds: [row(), row({ kind: 'prompt', label: 'Prompts' })] },
    });
    expect(html.match(/role="meter"/g)).toHaveLength(2);
    expect(html).toContain('Model calls');
    expect(html).toContain('Prompts');
  });

  // The store omits a kind with nothing to report rather than returning zeros,
  // and the view must not undo that by filling in a fixed list. A bar at 0%
  // says "nothing has gone yet"; nothing recorded says something else entirely.
  it('invents no row for a kind it was not given', () => {
    const html = render({ state: { status: 'ready', kinds: [row()] } });
    expect(html.match(/role="meter"/g)).toHaveLength(1);
    expect(html).not.toContain('Prompts');
  });

  // A bar implies a denominator and a direction of travel. None of these has
  // either: they are not sent as rows at all.
  it('gives the local-only entities a line, never a bar', () => {
    const html = render({
      state: { status: 'nothing-recorded' },
      localOnly: [
        {
          id: 'findings',
          label: 'Findings',
          count: 380_989,
          detail: 'derived by your deployment from the activity it receives',
        },
      ],
    });
    expect(html).toContain('Findings');
    expect(html).toContain('380,989');
    expect(html).toContain('derived by your deployment');
    expect(html).not.toContain('role="meter"');
  });

  it('says nothing is recorded rather than showing an empty bar', () => {
    const html = render({ state: { status: 'nothing-recorded' } });
    expect(html).toContain('Nothing recorded yet');
    expect(html).not.toContain('role="meter"');
    expect(html).not.toContain('0%');
  });

  // Each state has its own sentence, and they are mutually exclusive: a backlog
  // rendered beside "not shared" would be two contradictory statements about one
  // machine.
  it('offers no control, and no bars, while existing activity is not shared', () => {
    const html = render({ state: { status: 'not-shared' }, onSyncNow: vi.fn() });
    expect(html).toContain('not shared');
    expect(html).not.toContain('Sync now');
    expect(html).not.toContain('role="meter"');
  });

  it('reports a stale grant as paused, and offers no control', () => {
    const html = render({ state: { status: 'consent-stale' }, onSyncNow: vi.fn() });
    expect(html).toContain('Paused');
    expect(html).toContain('predates a change');
    expect(html).not.toContain('Sync now');
  });

  it('repeats the deployment’s refusal rather than calling it an outage', () => {
    const html = render({ lastOutcome: 'refused' });
    expect(html).toContain('refused this machine');
    expect(html).toContain('Re-attach');
  });

  // "could not reach" and "nothing was lost" are one sentence on purpose: the
  // rows stay queued, and a reader who sees only the first half reasonably
  // assumes otherwise.
  it('says an unreachable pass lost nothing', () => {
    const html = render({ lastOutcome: 'unreachable' });
    expect(html).toContain('could not reach');
    expect(html).toContain('Nothing was lost');
  });

  it('disables the control while a pass is already running', () => {
    const html = render({ onSyncNow: vi.fn(), running: true });
    expect(html).toContain('Sending…');
    expect(html).toContain('disabled');
  });

  // The child is detached, so the panel cannot see a pass fail. When it DOES
  // know a start never happened, saying so is the whole point.
  it('surfaces a start that never happened', () => {
    const html = render({ onSyncNow: vi.fn(), startError: 'Could not start a pass here.' });
    expect(html).toContain('Could not start a pass here.');
  });

  it('says what the control covers, since it does not cover the lines below it', () => {
    const html = render({ onSyncNow: vi.fn() });
    expect(html).toContain('Sends what is queued above');
  });
});
