import * as readline from 'node:readline/promises';
import { parseArgs } from 'node:util';

import {
  applyCliUpdate as applyCliUpdateShared,
  applyPluginUpdate as applyPluginUpdateShared,
  claudeAvailable,
  clearCache,
  CLI_PACKAGE,
  findAgent,
  gatherReportLive,
  outdated,
  pluginRef,
  renderReport,
} from '@akasecurity/local-ops';
import type { ComponentStatus } from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';

// `aka update [cli|<plugin-id>]` — the one command to get current. Shows the
// installed-vs-latest report, then (unless --yes) asks before applying. The CLI
// updates itself via the same `npm i -g` used to install it; plugins update through
// the `claude` plugin manager. With no target it updates everything that's behind.
export async function runUpdate(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    options: { ...HOME_OPTION, yes: { type: 'boolean', short: 'y' } },
    allowPositionals: true,
  });
  const home = homeBase(values.home);
  const target = positionals[0];

  const out = process.stdout;
  out.write('Checking for updates…\n\n');
  const report = gatherReportLive();
  out.write(`${renderReport(report)}\n\n`);

  if (target && target !== 'all' && !report.statuses.some((s) => s.id === target)) {
    process.stderr.write(
      `aka update: '${target}' isn't installed or known — run \`aka check-updates\`. ` +
        `To install a plugin, use \`aka plugins install ${target}\`.\n`,
    );
    process.exitCode = 1;
    return;
  }

  let candidates = outdated(report);
  if (target && target !== 'all') candidates = candidates.filter((s) => s.id === target);

  if (candidates.length === 0) {
    if (!report.statuses.some((s) => s.latest !== null)) {
      out.write(
        'Could not reach the package registry (offline, or missing auth). Try again later.\n',
      );
    } else {
      out.write(
        target && target !== 'all'
          ? `${target} is already up to date.\n`
          : 'Everything is up to date.\n',
      );
    }
    return;
  }

  out.write('Will update:\n');
  for (const c of candidates) {
    out.write(`  • ${c.name}: ${c.installed ?? '—'} → ${String(c.latest)}\n`);
  }
  out.write('\n');

  if (!values.yes) {
    if (!process.stdin.isTTY) {
      out.write('Re-run with --yes to apply (no interactive terminal detected).\n');
      return;
    }
    if (!(await confirm('Apply these updates? [y/N] '))) {
      out.write('Aborted — nothing changed.\n');
      return;
    }
    out.write('\n');
  }

  let updatedPlugin = false;
  let anyFailed = false;
  for (const c of candidates) {
    const ok = c.kind === 'cli' ? applyCliUpdate() : applyPluginUpdate(c);
    if (c.kind === 'plugin' && ok) updatedPlugin = true;
    if (!ok) anyFailed = true;
  }

  // Invalidate the cache: this process still reports the pre-update versions, so a
  // fresh cache would re-nag. The next command recomputes cleanly.
  clearCache(home);

  if (updatedPlugin) {
    out.write('\n↻ Restart Claude Code to load the updated plugin(s).\n');
  }
  if (anyFailed) process.exitCode = 1;
}

async function confirm(question: string): Promise<boolean> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(question)).trim().toLowerCase();
    return answer === 'y' || answer === 'yes';
  } finally {
    rl.close();
  }
}

function applyCliUpdate(): boolean {
  process.stdout.write(`Updating the aka CLI (npm install -g ${CLI_PACKAGE}@latest)…\n`);
  const { ok } = applyCliUpdateShared('inherit');
  process.stdout.write(ok ? '✓ CLI updated.\n' : '✗ CLI update failed (see npm output above).\n');
  return ok;
}

function applyPluginUpdate(status: ComponentStatus): boolean {
  const agent = findAgent(status.id);
  const ref = agent ? pluginRef(agent) : undefined;
  if (!agent || !ref) {
    process.stderr.write(`✗ ${status.name}: no update coordinates in the registry.\n`);
    return false;
  }
  if (!claudeAvailable()) {
    process.stderr.write(
      `✗ ${status.name}: the \`claude\` CLI isn't on your PATH — install Claude Code, ` +
        `then run \`claude plugin update ${ref}\`.\n`,
    );
    return false;
  }
  process.stdout.write(`Updating ${status.name} (claude plugin update ${ref})…\n`);
  const { ok } = applyPluginUpdateShared(status.id, 'inherit');
  process.stdout.write(ok ? `✓ ${status.name} updated.\n` : `✗ ${status.name} update failed.\n`);
  return ok;
}
