// The note that explains a row reading "up to date" at a version the user can
// see is not the newest published.
//
// `latest` is the version the HOST will install, which for a plugin resolved
// through a marketplace manifest is the manifest's pin rather than npm's
// latest. Without the note that renders as a report that is simply wrong, or as
// a failed update — the issue this closes reported it as indistinguishable from
// both.
import { MANAGED_PLUGIN_ADVICE } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  managedInstallRefusal,
  managedUpdateRefusal,
  nothingToApplyLine,
  outdated,
  renderReport,
} from '../src/update-render.ts';

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
 * A RANGE pin is never orderable, so it gets a note UNCONDITIONALLY — unlike
 * an exact pin, which is only worth explaining when it is behind npm. Without
 * this the "Latest" column shows npm's own answer beside a status the machine
 * will never reach that way, and nothing says the version came from npm
 * rather than from what the host actually resolves the range to.
 */
describe('renderReport — the range-pin note', () => {
  it('notes a range pin even though npmAhead reads false for one', () => {
    // `npmAhead` is always false on a range row (there is no single pin
    // version to compare npm against) — the note must not be gated on it.
    const out = renderReport(
      report({
        marketplacePin: {
          marketplace: 'akasecurity',
          npmLatest: '0.12.0',
          npmAhead: false,
          range: '^0.11.0-beta.0',
        },
      }),
    );

    expect(out).toContain('Pinned by a marketplace');
    expect(out).toContain('akasecurity');
    expect(out).toContain('^0.11.0-beta.0');
    expect(out).toContain('npm has v0.12.0');
  });

  it('says nothing about npm when there is no npm answer to name', () => {
    const out = renderReport(
      report({
        marketplacePin: {
          marketplace: 'akasecurity',
          npmLatest: null,
          npmAhead: false,
          range: '^0.11.0-beta.0',
        },
      }),
    );

    expect(out).toContain('^0.11.0-beta.0');
    expect(out).not.toContain('npm has');
  });

  it('never prints the exact-pin sentence for a range row', () => {
    // The two branches of pinNotes must not both fire for one row. `gatherReport`
    // never actually produces `npmAhead: true` alongside a `range` (npmAhead is
    // forced false whenever a pin is a range), but this render function does not
    // itself enforce that invariant — it trusts a `continue` after the range
    // branch to skip the exact-pin branch. Set every field the exact-pin branch
    // needs (`npmAhead: true`, a non-null `latest`, a non-null `npmLatest`) so a
    // dropped `continue` produces a second, visibly wrong note rather than
    // silently agreeing with a fixture that happened not to reach it.
    const out = renderReport(
      report({
        latest: '0.9.9',
        marketplacePin: {
          marketplace: 'akasecurity',
          npmLatest: '0.12.0',
          npmAhead: true,
          range: '^0.11.0-beta.0',
        },
      }),
    );

    expect(out).toContain('^0.11.0-beta.0');
    expect(out).not.toContain('cannot install until that');
    // The stronger form of the same assertion: a dropped `continue` pushes a
    // SECOND note for this row (the exact-pin branch, alongside the range
    // one) rather than merely mentioning the exact-pin sentence — count the
    // row's own note lines directly instead of `.not.toContain`ing one string
    // the exact-pin branch happens to use.
    const rowNotes = out.split('\n').filter((line) => line.includes('Claude Code plugin:'));
    expect(rowNotes).toHaveLength(1);
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

/**
 * A row an organization's managed settings installed.
 *
 * The report never offers it as an update, so the table has to say why a
 * version behind the organization's pin is not "update available", and the
 * note has to name the route that DOES move it — or a reader concludes the
 * report is stale and goes looking for a command to run.
 */
describe('renderReport — an install an organization manages', () => {
  const managedRow = (over: Record<string, unknown> = {}): never =>
    report({
      name: 'Claude Code',
      installed: '0.9.13',
      latest: '0.9.14',
      managedInstall: { ref: 'org-release-8', pending: true },
      ...over,
    });
  const rowOf = (out: string): string =>
    out.split('\n').find((line) => line.includes('0.9.13')) ?? '';

  it('says a pending update is the organization’s, never that one is available', () => {
    const out = renderReport(managedRow());

    expect(rowOf(out)).toContain('managed — update pending');
    expect(out).not.toContain('update available');
    expect(out).toContain('Managed by your organization:');
    expect(out).toContain('Claude Code (marketplace ref org-release-8): v0.9.14 is on its way.');
    expect(out).toContain(MANAGED_PLUGIN_ADVICE);
    expect(out).toContain('`aka update` leaves it alone.');
  });

  it('says a current managed install is current', () => {
    const out = renderReport(
      managedRow({ installed: '0.9.14', managedInstall: { ref: 'org-release-8', pending: false } }),
    );

    const row = out.split('\n').find((line) => line.includes('0.9.14')) ?? '';
    expect(row).toContain('managed — up to date');
    expect(out).not.toContain('on its way');
    // Still explained: the note is what says `aka update` will not touch it.
    expect(out).toContain(MANAGED_PLUGIN_ADVICE);
  });

  it('reads as managed, not unknown, when the organization’s pin could not be read', () => {
    const out = renderReport(managedRow({ latest: null, managedInstall: { pending: false } }));

    expect(rowOf(out)).toMatch(/managed$/);
    // The Latest cell may honestly read unknown; the STATUS must not, since the
    // row is not unknown — it is the organization's.
    expect(rowOf(out)).not.toMatch(/unknown$/);
    expect(out).not.toContain('marketplace ref');
    expect(out).toContain('Claude Code: ');
  });

  it('reads as managed, not up to date, when the installed version is unknown', () => {
    // A managed record with no readable version: the row cannot claim to be
    // current against a pin it has nothing to compare with.
    const out = renderReport(
      managedRow({ installed: null, managedInstall: { ref: 'org-release-8', pending: false } }),
    );

    const row = out.split('\n').find((line) => line.includes('Claude Code  ')) ?? '';
    expect(row).toMatch(/managed$/);
    expect(row).not.toContain('up to date');
    expect(out).toContain(MANAGED_PLUGIN_ADVICE);
  });

  it('explains a managed row once, not also as a marketplace pin', () => {
    // The same row carrying pin evidence that WOULD earn a pin note: npm is
    // ahead of the organization's pin. The managed note already says who
    // decides the version, and a second note naming a marketplace "that has to
    // move" hands the reader a job that is not theirs.
    const out = renderReport(
      managedRow({
        marketplacePin: { marketplace: 'akasecurity', npmLatest: '0.9.15', npmAhead: true },
      }),
    );

    expect(out).toContain('Managed by your organization:');
    expect(out).not.toContain('Pinned by a marketplace');
    expect(out.split('\n').filter((line) => line.includes('Claude Code ('))).toHaveLength(1);
  });

  it('is never counted as something `aka update` can apply', () => {
    expect(outdated(managedRow())).toEqual([]);
  });
});

describe('nothingToApplyLine', () => {
  const withRows = (...rows: Record<string, unknown>[]): never =>
    ({ statuses: rows.map((row) => status(row)), availablePlugins: [] }) as never;

  it('says everything is up to date when nothing is pending anywhere', () => {
    expect(nothingToApplyLine(withRows({}))).toBe('Everything is up to date.');
    expect(nothingToApplyLine(withRows({ managedInstall: { pending: false } }))).toBe(
      'Everything is up to date.',
    );
  });

  it('does not call a machine current while its organization has an update on the way', () => {
    const line = nothingToApplyLine(withRows({}, { managedInstall: { pending: true } }));

    expect(line).not.toContain('up to date');
    expect(line).toContain('Nothing for `aka update` to apply');
    expect(line).toContain('Claude Code');
  });
});

describe('managedUpdateRefusal', () => {
  it('names the component, says nothing ran, and gives the route that does apply', () => {
    const line = managedUpdateRefusal('Claude Code');

    expect(line).toContain('Claude Code is managed by your organization');
    expect(line).toContain('nothing was run');
    expect(line).toContain(MANAGED_PLUGIN_ADVICE);
  });
});

describe('managedInstallRefusal', () => {
  it('says the plugin is already there, that nothing ran, and how it moves', () => {
    const line = managedInstallRefusal('Claude Code');

    expect(line).toContain('Claude Code is managed by your organization');
    expect(line).toContain('already installed');
    expect(line).toContain('nothing was run');
    expect(line).toContain(MANAGED_PLUGIN_ADVICE);
  });

  it('is not the update refusal, which answers a question nobody asked', () => {
    // An install refused with "an update was refused" reads as this command
    // having tried to update something.
    expect(managedInstallRefusal('Claude Code')).not.toBe(managedUpdateRefusal('Claude Code'));
  });
});
