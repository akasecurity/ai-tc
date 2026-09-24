import * as readline from 'node:readline/promises';
import { parseArgs } from 'node:util';

import {
  applyCliUpdate as applyCliUpdateShared,
  applyPluginUpdate as applyPluginUpdateShared,
  channelOfVersion,
  clearCache,
  cliVersion,
  createCliPluginManager,
  describeChannel,
  detectInstallChannel,
  findAgent,
  gatherReportLive,
  installedPluginScope,
  managedPluginInstall,
  managedUpdateRefusal,
  nothingToApplyLine,
  outdated,
  parseSwitchableChannel,
  planCliUpdate,
  pluginRef,
  renderReport,
  SWITCHABLE_CHANNELS,
} from '@akasecurity/local-ops';
import type { CliUpdateTarget, ComponentStatus, ReleaseChannel } from '@akasecurity/schema';
import { MANAGED_PLUGIN_ADVICE, RELEASE_CHANNEL, RELEASE_TAG_SOURCE } from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import { cliInstallOrigin } from '../lib/install-origin.ts';

// `aka update [cli|<plugin-id>]` — the one command to get current. Shows the
// installed-vs-latest report, then (unless --yes) asks before applying. The CLI
// updates itself through whichever channel THIS copy came from — the package
// manager and location are derived from where the running code lives, not from
// what `npm` on PATH happens to point at (see local-ops' install-channel.ts);
// plugins update through the `claude` plugin manager. With no target it updates
// everything that's behind.
//
// `--channel <stable|beta|nightly>` moves THIS copy of the CLI onto another
// published line. With no flag, every component follows the channel its own
// installed version says it is on, so a bare run never changes a machine's
// channel in either direction.
export async function runUpdate(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      ...HOME_OPTION,
      yes: { type: 'boolean', short: 'y' },
      channel: { type: 'string' },
    },
    allowPositionals: true,
  });
  const home = homeBase(values.home);
  const target = positionals[0];

  // The FIRST argv-sourced token on this path that could reach a child
  // process's argv, so it is parsed against the closed union HERE — before the
  // registry is read and before anything is spawned — and a miss returns
  // without running any of it. `local-ops`' shelled spawn routes through
  // cmd.exe on Windows, where Node concatenates argv without escaping it, so
  // nothing a user typed may travel further than this line.
  //
  // The refusal names the values it accepts and never echoes what was typed:
  // the accepted set is what a user needs, and the rejected token is the one
  // string on this path that is not from this repo.
  const rawChannel = values.channel;
  const requestedChannel = rawChannel === undefined ? null : parseSwitchableChannel(rawChannel);
  if (rawChannel !== undefined && requestedChannel === null) {
    process.stderr.write(
      `aka update: --channel must be one of ${SWITCHABLE_CHANNELS.join(', ')}.\n`,
    );
    process.exitCode = 1;
    return;
  }
  if (requestedChannel !== null && target !== undefined && target !== 'all' && target !== 'cli') {
    process.stderr.write(pluginChannelRefusal(target, requestedChannel));
    process.exitCode = 1;
    return;
  }

  // One value for the whole run: the report resolves the CLI row against it,
  // and the install builds its spec from that row's own resolved version, so
  // the version this command prints is the version it fetches. Deriving the
  // channel twice lets the two disagree, and resolving the report against the
  // channel being LEFT makes a switch report nothing to do — `updateAvailable`
  // is what decides whether anything is applied.
  const cliChannel = requestedChannel ?? channelOfVersion(cliVersion());

  const out = process.stdout;
  out.write('Checking for updates…\n\n');
  const report = gatherReportLive(cliChannel);

  // A channel asked for BY NAME is refused here in either of two registry
  // states — after the one registry read that can answer the question, and
  // before the table is rendered, before the confirmation, and before any
  // install spawn.
  //
  // Unpublished: the channel serves no tag at all. The report still carries a
  // version there, because falling back to the stable tag is the right offer
  // for a machine whose own prerelease tag has been retired. It is the wrong
  // answer for a request: the install would ask the registry for a tag
  // nothing publishes and fail there instead. So the refusal reads the row's
  // `latestFrom` rather than its version, which is the only field that
  // separates the two cases.
  //
  // Graduated: the channel HAD a tag, but the stable release has since
  // overtaken it — `resolveChannel` returns the STABLE version as `latest`
  // there, not a version the requested line ever published. Left unrefused,
  // `aka update --channel beta` would render that stable version beside
  // `(beta)`, which is the same false sentence the Unpublished case exists to
  // prevent: a line the user named printed beside a version it never served,
  // while this machine stays on stable.
  //
  // Both come BEFORE the render because the row itself is the false claim: the
  // table would say a version is available on a line that never published it,
  // and that sentence is the one a user acts on.
  //
  // Scoped to `requestedChannel`, so the DERIVED path keeps graduating as
  // before — a beta machine with no flag on the command line must still move
  // onto the stable release rather than being stranded on its own tag.
  const cliRow = report.statuses.find((s) => s.id === 'cli');
  if (requestedChannel !== null && cliRow?.latestFrom === RELEASE_TAG_SOURCE.Unpublished) {
    process.stderr.write(
      `aka update: nothing has been published on the ${requestedChannel} channel — ` +
        'there is no release there to install.\n',
    );
    process.exitCode = 1;
    return;
  }
  if (requestedChannel !== null && cliRow?.latestFrom === RELEASE_TAG_SOURCE.Graduated) {
    const ownRelease =
      cliRow.channelLatest !== undefined
        ? `${requestedChannel}'s newest release is ${cliRow.channelLatest}, and `
        : '';
    process.stderr.write(
      `aka update: the ${requestedChannel} channel has graduated — ${ownRelease}the stable ` +
        `release (${String(cliRow.latest)}) is newer than anything published there. Run ` +
        '`aka update` (no --channel) to install the stable.\n',
    );
    process.exitCode = 1;
    return;
  }

  out.write(`${renderReport(report)}\n\n`);

  if (target && target !== 'all' && !report.statuses.some((s) => s.id === target)) {
    process.stderr.write(
      `aka update: '${target}' isn't installed or known — run \`aka check-updates\`. ` +
        `To install a plugin, use \`aka plugins install ${target}\`.\n`,
    );
    process.exitCode = 1;
    return;
  }

  // A plugin an organization's managed settings installed is never applied
  // here — `outdated` already leaves it out — and naming it explicitly is
  // refused rather than answered with "already up to date", which would read
  // as this command having checked and found nothing to do. The version is
  // the organization's to set, and the host's own autoupdate moves it.
  const targetRow =
    target && target !== 'all' ? report.statuses.find((s) => s.id === target) : undefined;
  if (targetRow?.managedInstall) {
    process.stderr.write(`aka update: ${managedUpdateRefusal(targetRow.name)}\n`);
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
    } else if (requestedChannel !== null) {
      // A switch with nothing to install is a different sentence from a machine
      // that is current. The asked-for channel publishes nothing this copy is
      // behind, and this command only ever moves forward, so reporting
      // "everything is up to date" would read as the switch having happened.
      out.write(
        `Nothing to install on the ${requestedChannel} channel — it publishes nothing newer ` +
          'than what is here. `aka update` only moves forward, so going back to an older ' +
          'line means installing that version by name.\n',
      );
    } else {
      out.write(
        target && target !== 'all'
          ? `${target} is already up to date.\n`
          : `${nothingToApplyLine(report)}\n`,
      );
    }
    return;
  }

  out.write('Will update:\n');
  for (const c of candidates) {
    // The channel is named only when it is not stable: every default machine
    // is on stable, so printing it there is noise, and a machine that is not is
    // the one case where the version pair does not say what is being followed.
    const channel =
      c.channel === undefined || c.channel === RELEASE_CHANNEL.Stable ? '' : ` (${c.channel})`;
    out.write(`  • ${c.name}: ${c.installed ?? '—'} → ${String(c.latest)}${channel}\n`);
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
    // With no `--channel`, `cliChannel` is the channel THIS copy is already on,
    // derived from its own version: a bare `aka update` on a beta machine must
    // not quietly move it back to stable.
    //
    // The VERSION comes off the candidate row — the same field the bullet above
    // printed — so the line a user just read names the spec that is about to
    // run. Re-resolving it here, or letting the install fall back to the
    // channel's dist-tag, is what let a graduating beta machine be offered
    // 0.11.0 and re-install 0.11.0-beta.3.
    const ok =
      c.kind === 'cli'
        ? applyCliUpdate({ channel: cliChannel, version: c.latest })
        : applyPluginUpdate(c);
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

/**
 * Why `--channel` cannot be carried out for a plugin target.
 *
 * A plugin's channel is decided by the marketplace registration its host
 * resolves installs through, which only that host's CLI can change — so there
 * is nothing this command could do with the flag. Accepting and ignoring it
 * would tell a user they had switched a plugin's channel while the one thing
 * that decides it was untouched.
 *
 * The line to run instead is taken from the host's own verb table rather than
 * written here, so it names the right binary and the right verbs for every
 * host, including the one with no update verb at all.
 */
function pluginChannelRefusal(target: string, channel: ReleaseChannel): string {
  const agent = findAgent(target);
  const ref = agent ? pluginRef(agent) : undefined;
  const head =
    `aka update: --channel ${channel} applies to the CLI only — a plugin's channel is its ` +
    `marketplace registration, which the host CLI owns.\n`;
  if (!agent || !ref || !agent.cliBin) {
    return `${head}  Update ${target} through its host, then re-run \`aka check-updates\`.\n`;
  }
  // The recipe below re-registers the marketplace from its source with no
  // ref. On a host that accepts that, a managed install's pinned registration
  // is replaced with an unpinned one, so it is never offered for a plugin an
  // organization manages.
  if (managedPluginInstall(agent) !== null) {
    return `${head}  ${agent.name} is managed by your organization. ${MANAGED_PLUGIN_ADVICE}\n`;
  }
  const recipe = createCliPluginManager(agent.cliBin).updateRecipe(ref, agent.marketplaceSource);
  return (
    `${head}  To move ${agent.name} onto another channel, register the marketplace that ` +
    `serves it and re-install:\n\n    ${recipe.join(' && ')}\n\n`
  );
}

function applyCliUpdate(target: CliUpdateTarget): boolean {
  const channel = detectInstallChannel(cliInstallOrigin());
  const plan = planCliUpdate(channel, process.platform, target);
  if (plan.command === null) {
    process.stderr.write(
      `✗ aka CLI: ${plan.reason ?? 'this install cannot be updated automatically'}.\n` +
        `  This copy is a ${describeChannel(channel)}.\n` +
        `  To update it, run:\n\n    ${plan.display}\n\n`,
    );
    return false;
  }
  process.stdout.write(`Updating the aka CLI — ${describeChannel(channel)}\n`);
  process.stdout.write(`  ${plan.display}\n`);
  // The same install channel AND the same target that produced the line above,
  // so the command printed is the command run — down to the version in the spec.
  // `hasBin` is left at its default: that parameter is a probe seam for tests,
  // and this caller wants the real PATH lookup.
  const { ok } = applyCliUpdateShared(channel, 'inherit', undefined, target);
  process.stdout.write(
    ok ? '✓ CLI updated.\n' : `✗ CLI update failed (see the ${plan.command.bin} output above).\n`,
  );
  return ok;
}

function applyPluginUpdate(status: ComponentStatus): boolean {
  const agent = findAgent(status.id);
  const ref = agent ? pluginRef(agent) : undefined;
  const cliBin = agent?.cliBin;
  if (!agent || !ref || !cliBin) {
    process.stderr.write(`✗ ${status.name}: no update coordinates in the registry.\n`);
    return false;
  }
  // Two renders off the host's own verb table — a hardcoded `plugin update` is
  // wrong for Codex, which has no such subcommand — and they are NOT
  // interchangeable.
  //
  // The RECIPE is the manual equivalent: what a user retypes when this process
  // cannot run it for them. It is joined with `&&`, so it carries only steps
  // whose failure should stop the chain, which is why the survivable snapshot
  // refresh is deliberately absent. It leads with `marketplace add` because
  // `available()` proves only that the binary is on PATH, never that the
  // marketplace was ever registered.
  //
  // The SPAWN PLAN is the disclosure: every command this process is about to
  // run, refresh included. Announcing the recipe here named two of the three
  // spawns — the same under-disclosure the dashboard's confirm dialog had, and
  // worse on this surface, since a terminal is where a user watches commands go
  // by and notices one they were not told about. It is printed as a list and
  // never joined with `&&`: that join would state a chaining rule this code
  // does not follow, since a failed refresh is survivable here.
  // Bound to the scope the plugin is really installed at, so the printed
  // recipe, the announced spawn plan and the spawn itself all name the same
  // install — the version comparison reads a record at any scope, while the
  // host's update verb defaults to `user`.
  const manager = createCliPluginManager(cliBin, installedPluginScope(ref));
  const recipe = manager.updateRecipe(ref, agent.marketplaceSource).join(' && ');
  if (!manager.available()) {
    process.stderr.write(
      `✗ ${status.name}: the \`${cliBin}\` CLI isn't on your PATH — install ${agent.name}, ` +
        `then run \`${recipe}\`.\n`,
    );
    return false;
  }
  const plan = manager.updateSpawnPlan(ref, agent.marketplaceSource, agent.marketplace);
  process.stdout.write(
    `Updating ${status.name}, running:\n` + plan.map((command) => `  ${command}\n`).join(''),
  );
  const { ok } = applyPluginUpdateShared(status.id, 'inherit');
  process.stdout.write(ok ? `✓ ${status.name} updated.\n` : `✗ ${status.name} update failed.\n`);
  return ok;
}
