import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';

import {
  AGENT_PLUGINS,
  createCliPluginManager,
  findAgent,
  hostCliVersion,
  installAgentPlugin,
  installedAgentPluginVersions,
  pluginRef,
} from '@akasecurity/local-ops';
import { openLocalDatabase } from '@akasecurity/persistence';
import { dataDir, dbPath, hostFloorGaps, requiredHostVersion } from '@akasecurity/plugin-sdk';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import type { Prompter } from '../lib/prompter.ts';
import { terminalPrompter } from '../lib/prompter.ts';

/**
 * Seams for the install gate: the host version to judge, and the IO to ask on.
 * Injected so a test never shells out to a real `claude` — the PATH shims in
 * this repo fail OPEN, so an unstubbed probe would reach the developer's own
 * installed CLI rather than erroring.
 */
export interface InstallDeps {
  hostVersion?: (bin: 'claude' | 'codex') => string | undefined;
  prompter?: Prompter;
  /**
   * The caller already has the user's consent, so the floor warning is printed
   * but not turned into a question. `aka init --yes` sets it: without this the
   * gate re-asks a user who passed `--yes` precisely to avoid being asked, and
   * a scripted Enter answers "no" and installs nothing.
   */
  assumeYes?: boolean;
  /**
   * Whether declining the floor prompt is a FAILURE of the command.
   *
   * True for `aka plugins install`, where the decline is the whole operation:
   * `aka plugins install … && aka init` must not read it as a success. False for
   * `aka init`, where the plugin is an optional extra offered after the store is
   * already created — init succeeded, and the user simply passed on the offer,
   * exactly like `offerPluginInstall`'s own decline path. Scoped to the DECLINE
   * rather than cleared by the caller, so a genuine install failure below still
   * reports non-zero to init.
   */
  declineIsFailure?: boolean;
}

// `aka plugins [list|install <agent>]` — the optional plugin hub.
export function runPlugins(argv: string[], deps: InstallDeps = {}): void | Promise<void> {
  const [sub, ...rest] = argv;
  if (!sub || sub === 'list') return listPlugins(rest);
  if (sub === 'install') return installPlugin(rest, deps);
  process.stderr.write(`aka plugins: unknown subcommand '${sub}' (try: list, install <agent>)\n`);
  process.exitCode = 1;
}

async function listPlugins(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: HOME_OPTION });
  const home = homeBase(values.home);

  // Which agents have actually recorded findings into the local store? (Sampled
  // from recent findings — a best-effort "active" marker, not authoritative.)
  // Only read if the store ALREADY exists: openLocalDatabase creates + migrates +
  // seeds on open, and a read-only `list` must not provision a store on a fresh
  // machine. (A try/catch wouldn't help — open doesn't throw on a missing file, it
  // creates one, which is exactly what we're avoiding.)
  const active = new Set<string>();
  if (existsSync(dbPath(home))) {
    const db = openLocalDatabase(dataDir(home));
    try {
      const recent = await db.findings.recentFindings({ limit: 1000 });
      for (const f of recent) active.add(f.sourceTool);
    } finally {
      db.close();
    }
  }

  // Installed versions, keyed by `<plugin>@<marketplace>`, merged from every
  // registered agent's own install ledger/cache (Claude Code's
  // installed_plugins.json, Codex CLI's plugins/cache directory layout).
  const installed = installedAgentPluginVersions();

  const out = process.stdout;
  out.write('Agent plugins (the CLI is an optional hub — plugins also self-install):\n\n');
  for (const a of AGENT_PLUGINS) {
    const ref = pluginRef(a);
    const version = ref ? installed.get(ref) : undefined;
    const state = version
      ? `installed v${version}`
      : active.has(a.sourceTool)
        ? 'active'
        : 'available';
    out.write(`  ${a.id.padEnd(16)} ${state.padEnd(16)} ${a.name}\n`);
    out.write(`  ${' '.padEnd(16)} ${' '.padEnd(16)} ${a.description}\n`);
  }
  out.write('\nInstall:  aka plugins install <agent>\n');
  out.write('Update:   aka update            (or: aka check-updates)\n');
}

async function installPlugin(argv: string[], deps: InstallDeps): Promise<void> {
  const { positionals } = parseArgs({ args: argv, options: HOME_OPTION, allowPositionals: true });
  const id = positionals[0];
  if (!id) {
    process.stderr.write('aka plugins install: missing <agent> (try: aka plugins list)\n');
    process.exitCode = 1;
    return;
  }
  const agent = findAgent(id);
  if (!agent) {
    process.stderr.write(`aka plugins install: unknown agent '${id}' (try: aka plugins list)\n`);
    process.exitCode = 1;
    return;
  }
  const ref = pluginRef(agent);
  const cliBin = agent.cliBin;
  if (!ref || !cliBin) {
    process.stdout.write(
      agent.installHint
        ? `${agent.installHint}\n`
        : `${agent.name} has no automated install path yet — install it from the AKA ` +
            `marketplace in ${agent.name}, then run \`aka init\`.\n`,
    );
    return;
  }

  // Delegate to the host CLI's own plugin manager (it owns the plugin cache +
  // lifecycle). If it isn't on PATH, fall back to the manual in-app path so
  // the command stays honest and actionable.
  // Hint copy comes from the host's own verb table, never a hardcoded verb —
  // `claude plugin install` and `codex plugin add` are not interchangeable, and
  // naming the wrong one hands the user a command their CLI rejects.
  const manager = createCliPluginManager(cliBin);
  const recipe = manager.installRecipe(ref, agent.marketplaceSource);
  if (!manager.available()) {
    process.stdout.write(
      `Installing ${agent.name}…\n\n` +
        `The \`${cliBin}\` CLI isn't on your PATH, so I can't install it automatically.\n` +
        `Install it from inside ${agent.name}:\n` +
        recipe.map((c) => `  ${c}\n`).join('') +
        `\nThen run \`aka init\` to set up the local store.\n`,
    );
    return;
  }

  // A host too old for some of the events AKA's manifest registers will DROP
  // those entries and load the rest, so the plugin installs clean and a
  // protection is silently missing. Say so before installing, and let the user
  // decide — install is still the better default, because everything else AKA
  // does works on an old host and refusing would trade all of it for one gap.
  //
  // Asking the binary is sound HERE and nowhere else: this install delegates to
  // the `claude` resolved from PATH, so that is the install being changed.
  if (cliBin === 'claude') {
    const version = (deps.hostVersion ?? hostCliVersion)(cliBin);
    const gaps = hostFloorGaps(version);
    const required = requiredHostVersion(gaps);
    if (version !== undefined && required !== undefined) {
      const io = deps.prompter ?? terminalPrompter();
      io.out(
        `This ${cliBin} is ${version}, which is older than AKA needs for ` +
          `${gaps.map((g) => g.label).join(', ')}.\n` +
          `Those protections will be inactive until you update Claude Code to ` +
          `${required} or newer. Everything else AKA does works normally.\n`,
      );
      // Ask only when there is somebody to answer AND they have not already
      // said yes. Non-interactive (CI, a script) proceeds rather than hanging on
      // a question nobody can answer — the warning above is still on the record.
      if (io.isInteractive && deps.assumeYes !== true) {
        const answer = (await io.ask('Install anyway? [y/N] ')).trim().toLowerCase();
        if (answer !== 'y' && answer !== 'yes') {
          io.out('Not installed. Update Claude Code, then run this again.\n');
          // Non-zero for a direct `aka plugins install`, where the decline IS the
          // operation failing. Not for `aka init`, which offers the plugin as an
          // optional extra once the store is already built — see declineIsFailure.
          if (deps.declineIsFailure !== false) process.exitCode = 1;
          return;
        }
      }
    }
  }

  // Announce every command that is about to run, not just the host binary's
  // name. The install path spawns marketplace prep before the op exactly as the
  // update path does, and "via claude" named none of the three.
  const plan = manager.installSpawnPlan(ref, agent.marketplaceSource, agent.marketplace);
  process.stdout.write(
    `Installing ${agent.name} via ${cliBin}, running:\n` +
      plan.map((command) => `  ${command}\n`).join(''),
  );
  const { ok } = installAgentPlugin(agent.id, 'inherit');
  if (ok) {
    process.stdout.write(
      `\n✓ Installed ${agent.name}.\n` +
        `  ↻ Restart ${agent.name} to load it.\n` +
        `  Run \`aka init\` to scaffold your local store (if you haven't already).\n`,
    );
  } else {
    process.stderr.write(
      `\n✗ Install failed — see the output above, or add it in ${agent.name} with ` +
        `\`${recipe.join(' && ')}\`.\n`,
    );
    process.exitCode = 1;
  }
}
