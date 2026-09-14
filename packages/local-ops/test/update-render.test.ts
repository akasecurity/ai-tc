// The note that explains a row reading "up to date" at a version the user can
// see is not the newest published.
//
// `latest` is the version the HOST will install, which for a plugin resolved
// through a marketplace manifest is the manifest's pin rather than npm's
// latest. Without the note that renders as a report that is simply wrong, or as
// a failed update — the issue this closes reported it as indistinguishable from
// both.
import { describe, expect, it } from 'vitest';

import { renderReport } from '../src/update-render.ts';

const status = (over: Record<string, unknown> = {}): never =>
  ({
    id: 'claude-code',
    name: 'Claude Code plugin',
    kind: 'plugin',
    installed: '0.9.9',
    latest: '0.9.9',
    updateAvailable: false,
    ...over,
  }) as never;

const report = (over: Record<string, unknown> = {}): never =>
  ({ statuses: [status(over)], availablePlugins: [] }) as never;

describe('renderReport — the marketplace-pin note', () => {
  it('renders the table itself, whatever the note does', () => {
    // The positive control for every absence assertion below: an empty render
    // satisfies all of them.
    const out = renderReport(report());

    expect(out).toContain('Claude Code plugin');
    expect(out).toContain('0.9.9');
    expect(out).toContain('up to date');
  });

  it('explains a pin that is BEHIND npm, naming the marketplace that has to move', () => {
    const out = renderReport(
      report({
        marketplacePin: { marketplace: 'akasecurity', npmLatest: '0.9.10', npmAhead: true },
      }),
    );

    expect(out).toContain('Pinned by a marketplace');
    // Both versions, because the gap is the whole point, and the marketplace,
    // because under a pinned ref it is the only thing that can ever close it.
    expect(out).toContain('akasecurity');
    expect(out).toContain('v0.9.9');
    expect(out).toContain('v0.9.10');
  });

  it.each([
    ['a pin that equals npm', { marketplace: 'akasecurity', npmLatest: '0.9.9', npmAhead: false }],
    ['a pin AHEAD of npm', { marketplace: 'akasecurity', npmLatest: '0.9.8', npmAhead: false }],
    [
      'a pin with no npm answer to compare',
      { marketplace: 'akasecurity', npmLatest: null, npmAhead: false },
    ],
  ])('says nothing about %s, which explains nothing', (_label, marketplacePin) => {
    // A note on every pinned row would be noise on the happy path, where the
    // pin and npm agree — which is most of the time, and is why this defect
    // stayed latent. Only the gap is worth a line.
    expect(renderReport(report({ marketplacePin }))).not.toContain('Pinned by a marketplace');
  });

  it('says nothing when there is no pin at all', () => {
    expect(renderReport(report())).not.toContain('Pinned by a marketplace');
  });

  it('says nothing when the pinned latest could not be resolved', () => {
    // `latest: null` is "unknown", and a note comparing against an unknown
    // would be inventing a gap.
    expect(
      renderReport(
        report({
          latest: null,
          marketplacePin: { marketplace: 'akasecurity', npmLatest: '0.9.10' },
        }),
      ),
    ).not.toContain('Pinned by a marketplace');
  });
});
