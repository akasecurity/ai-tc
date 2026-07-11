import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';

import {
  gatherReportLive,
  outdated,
  readCache,
  renderReport,
  writeCache,
} from '@akasecurity/local-ops';
import { dataDir } from '@akasecurity/plugin-sdk';

import { HOME_OPTION, homeBase } from '../lib/args.ts';

// `aka check-updates` — a read-only report of installed-vs-latest for the CLI and
// every marketplace plugin, plus any not-yet-installed plugins. Changes nothing;
// just tells you what `aka update` / `aka plugins install` would do. Also refreshes
// the passive-notice cache so the post-command nudge stays current.
export function runCheckUpdates(argv: string[]): void {
  const { values } = parseArgs({ args: argv, options: HOME_OPTION });
  const home = homeBase(values.home);

  const out = process.stdout;
  out.write('Checking for updates…\n\n');
  const report = gatherReportLive();
  out.write(`${renderReport(report)}\n`);

  const ups = outdated(report);
  const anyKnown = report.statuses.some((s) => s.latest !== null);
  out.write('\n');
  if (!anyKnown) {
    out.write(
      'Could not reach the npm registry, so "Latest" is unknown. Check your\n' +
        'network connection and try again.\n',
    );
  } else if (ups.length === 0 && report.availablePlugins.length === 0) {
    out.write('Everything is up to date.\n');
  } else if (ups.length > 0) {
    out.write(`${String(ups.length)} update(s) available — run \`aka update\` to apply.\n`);
  }

  // Refresh the cache from this fresh check (only if the store exists — never
  // provision ~/.aka from a read-only command), preserving which new-plugin notices
  // were already shown so the passive nudge doesn't re-announce them.
  if (existsSync(dataDir(home))) {
    const notifiedPluginIds = readCache(home)?.notifiedPluginIds ?? [];
    writeCache(home, { checkedAt: Date.now(), report, notifiedPluginIds });
  }
}
