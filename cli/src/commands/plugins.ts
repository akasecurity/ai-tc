import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';

import {
  AGENT_PLUGINS,
  claudeAvailable,
  findAgent,
  installAgentPlugin,
  installedPluginVersions,
  pluginRef,
} from '@akasecurity/local-ops';
import { openLocalDatabase } from '@akasecurity/persistence';
import { dataDir, dbPath } from '@akasecurity/plugin-sdk';

import { HOME_OPTION, homeBase } from '../lib/args.ts';

// `aka plugins [list|install <agent>]` — the optional plugin hub.
export function runPlugins(argv: string[]): void | Promise<void> {
  const [sub, ...rest] = argv;
  if (!sub || sub === 'list') return listPlugins(rest);
  if (sub === 'install') {
    installPlugin(rest);
    return;
  }
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

  // Installed versions, keyed by `<plugin>@<marketplace>`, from Claude Code's ledger.
  const installed = installedPluginVersions();

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

function installPlugin(argv: string[]): void {
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
  if (!ref) {
    process.stdout.write(
      `${agent.name} has no automated install path yet — install it from the AKA ` +
        `marketplace in Claude Code, then run \`aka init\`.\n`,
    );
    return;
  }

  // Delegate to the `claude` plugin manager (it owns the plugin cache + lifecycle).
  // If it isn't on PATH, fall back to the manual in-app path so the command stays
  // honest and actionable.
  if (!claudeAvailable()) {
    process.stdout.write(
      `Installing ${agent.name}…\n\n` +
        `The \`claude\` CLI isn't on your PATH, so I can't install it automatically.\n` +
        `Install it from inside Claude Code:\n` +
        `  /plugin marketplace add ${agent.marketplaceSource ?? ''}\n` +
        `  /plugin install ${ref}\n\n` +
        `Then run \`aka init\` to set up the local store.\n`,
    );
    return;
  }

  process.stdout.write(`Installing ${agent.name} via Claude Code…\n`);
  const { ok } = installAgentPlugin(agent.id, 'inherit');
  if (ok) {
    process.stdout.write(
      `\n✓ Installed ${agent.name}.\n` +
        `  ↻ Restart Claude Code to load it.\n` +
        `  Run \`aka init\` to scaffold your local store (if you haven't already).\n`,
    );
  } else {
    process.stderr.write(
      `\n✗ Install failed — see the output above, or add it in Claude Code with ` +
        `\`/plugin install ${ref}\`.\n`,
    );
    process.exitCode = 1;
  }
}
