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

/**
 * The release channel a row's versions were resolved against.
 *
 * Shown only when it is not stable. A column repeating `stable` on every row of
 * every default machine is noise that pushes the status off the width of a
 * terminal, while a row on another channel is the one case where the version
 * alone does not say what the machine is following.
 */
describe('renderReport — the channel column', () => {
  const headerOf = (out: string): string => out.split('\n')[0] ?? '';

  it('carries no channel column on a default report', () => {
    // Both readings of "default": a producer that predates channels and sets
    // nothing, and one that resolved stable and said so.
    for (const row of [report(), report({ channel: 'stable' })]) {
      const out = renderReport(row);
      expect(headerOf(out)).not.toContain('Channel');
      expect(out).not.toContain('stable');
      // The positive control: an empty render satisfies both absences above.
      expect(out).toContain('Claude Code plugin');
      expect(out).toContain('up to date');
    }
  });

  it('names the channel of a row that is not on stable', () => {
    const out = renderReport(report({ channel: 'beta', installed: '0.11.0-beta.2' }));

    expect(headerOf(out)).toContain('Channel');
    expect(out).toContain('beta');
    // The column is a column, not a note appended somewhere: the row carrying
    // the version has to be the row carrying the channel.
    const row = out.split('\n').find((line) => line.includes('0.11.0-beta.2'));
    expect(row).toBeDefined();
    expect(row).toContain('beta');
  });

  it('keeps the status readable beside it', () => {
    // The failure a hand-built column produces: the status ends up inside the
    // channel cell, or the cell swallows the padding and the two run together.
    const out = renderReport(
      report({ channel: 'nightly', updateAvailable: true, latest: '0.9.13' }),
    );
    const row = out.split('\n').find((line) => line.includes('0.9.13'));
    expect(row).toBeDefined();
    expect(row).toContain('nightly');
    expect(row).toContain('update available');
    expect(row).toMatch(/nightly\s+update available/);
  });
});
