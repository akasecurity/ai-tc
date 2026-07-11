import { parseArgs } from 'node:util';

import { openLocalDatabase } from '@akasecurity/persistence';
import { dataDir } from '@akasecurity/plugin-sdk';
import { aggregateTokenUsage } from '@akasecurity/schema';
import { render } from 'ink';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import { Dashboard, type DashboardView } from '../tui/Dashboard.tsx';
import { buildHealthReport, buildRecommendations, findingStatus } from '../tui/report.ts';

const VIEWS: readonly DashboardView[] = ['health', 'findings', 'recommend', 'audit'];

function parseView(positionals: string[]): DashboardView {
  const first = positionals[0];
  return VIEWS.includes(first as DashboardView) ? (first as DashboardView) : 'health';
}

// `aka tui` — interactive, colour terminal dashboard (Ink) over the local store.
// It mirrors the plugin's transcript slash-command screens (/health, /findings,
// /recommend, /audit) — same layout and data, but rendered in colour because Ink
// drives a real terminal (the transcript can't render ANSI, so those screens are
// monochrome). Fetches one snapshot from @akasecurity/persistence, derives the
// report/recommendations with the shared builders, then renders. Needs a TTY
// (Ink uses raw mode for keyboard input); degrades to a message otherwise.
export async function runTui(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    options: HOME_OPTION,
    allowPositionals: true,
  });
  const home = homeBase(values.home);
  const initialView = parseView(positionals);

  if (!process.stdin.isTTY) {
    process.stderr.write('aka tui requires an interactive terminal.\n');
    process.exitCode = 1;
    return;
  }

  const db = openLocalDatabase(dataDir(home));
  // A wide finding window feeds the report derivations (recommendations, handled
  // ratio); the Findings/Audit lists slice the most recent 25 from it, matching
  // the transcript screens' limits. Token usage (folded into the Health screen)
  // is windowed to the last 90 days rather than all-time: it reads + JSON-parses
  // every `llm_call` leaf in the window, so an all-time read would grow unbounded
  // with store age on every `aka tui` launch. 90d is a recent-spend glance.
  const tokenFromMs = Date.now() - 90 * 86_400_000;
  const [summary, findings, activity, tokenReports] = await Promise.all([
    db.findings.healthSummary(),
    db.findings.recentFindings({ limit: 500 }),
    db.findings.activityByDay(7),
    db.activity.tokenReports(tokenFromMs),
  ]);
  db.close();

  const report = buildHealthReport(summary, findings, activity);
  const status = findingStatus(summary);
  const recommendations = buildRecommendations(findings);
  const tokenUsage = aggregateTokenUsage(tokenReports);

  const { waitUntilExit } = render(
    <Dashboard
      home={home}
      report={report}
      status={status}
      findings={findings.slice(0, 25)}
      recommendations={recommendations}
      tokenUsage={tokenUsage}
      initialView={initialView}
    />,
  );
  await waitUntilExit();
}
