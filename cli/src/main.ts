import { cliVersion, notifyFromCache, refreshCache } from '@akasecurity/local-ops';

import { commandsHelp } from './command-manifest.ts';
import { runAttach, runDetach, runStatus } from './commands/attach.ts';
import { runCheckUpdates } from './commands/check-updates.ts';
import { runCompletion } from './commands/completion.ts';
import { runDashboard, runDashboardServer } from './commands/dashboard.ts';
import { runDetections } from './commands/detections.ts';
import { runException } from './commands/exception.ts';
import { runExtension } from './commands/extension.ts';
import { runInit } from './commands/init.ts';
import { runPlugins } from './commands/plugins.ts';
import { runScan } from './commands/scan.ts';
import { runStats } from './commands/stats.ts';
import { runTui } from './commands/tui.tsx';
import { runUpdate } from './commands/update.ts';
import { runVault } from './commands/vault.ts';
import { homeBase } from './lib/args.ts';
import type { ExternalDispatchDeps } from './lib/external-dispatch.ts';
import {
  dispatchExternal,
  externalDispatchSupported,
  shouldDispatchExternal,
} from './lib/external-dispatch.ts';

// The local-first AKA CLI. Every command reads and writes the local SQLite
// store directly via @akasecurity/persistence. The attach verbs are the only
// ones that reach a network, and only against a deployment this machine's own
// settings name.
const COMMANDS: Record<string, (argv: string[]) => void | Promise<void>> = {
  init: runInit,
  scan: runScan,
  stats: runStats,
  detections: runDetections,
  plugins: runPlugins,
  dashboard: runDashboard,
  extension: runExtension,
  exception: (argv) => runException(argv),
  vault: (argv) => runVault(argv),
  attach: (argv) => runAttach(argv),
  detach: (argv) => {
    runDetach(argv);
  },
  status: (argv) => runStatus(argv),
  tui: runTui,
  update: runUpdate,
  'check-updates': runCheckUpdates,
  completion: (argv) => {
    runCompletion(argv);
  },
  // Hidden: the detached background refresh spawned by the passive update notice.
  '__update-refresh': (argv) => {
    refreshCache(homeFromArgv(argv));
  },
  // Hidden: boots the bundled Next standalone server in-process (see dashboard.ts).
  // `aka dashboard` spawns this so a SEA binary can serve the dashboard without
  // exec-ing an external script. Returns the promise so main() awaits the boot.
  '__dashboard-server': (argv) => runDashboardServer(argv),
};

// Commands that already surface (or manage) update state — the passive post-command
// notice would be redundant or recursive after these.
const SKIP_NOTICE = new Set([
  'update',
  'check-updates',
  '__update-refresh',
  '__dashboard-server',
  'completion',
]);

const USAGE = `aka — AI Traffic Control (local-first; nothing leaves your machine unless you attach it)

Usage: aka <command> [options]

Commands:
${commandsHelp()}
${
  externalDispatchSupported()
    ? `\nAnything else runs an external 'aka-<command>' from your PATH (so 'aka claude' runs aka-claude).\n`
    : ''
}
Options:
  --home <dir>        Use an alternate AKA home (default: ~/.aka)
  --no-update-check   Skip the post-command "updates available" notice
  -v, --version       Print the CLI version
  -h, --help          Show this help
`;

// Resolve the AKA home from a --home flag anywhere in argv (best-effort — the
// notifier needs it before the command's own parseArgs runs). Supports both
// `--home <dir>` and `--home=<dir>`.
function homeFromArgv(argv: string[]): string {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === undefined) continue;
    if (arg === '--home') return homeBase(argv[i + 1]);
    if (arg.startsWith('--home=')) return homeBase(arg.slice('--home='.length));
  }
  return homeBase(undefined);
}

// `argv` is the tail after the binary name; `dispatchDeps` exists so the wiring
// below can be driven in tests without spawning a real child.
export async function main(
  argv: string[] = process.argv.slice(2),
  dispatchDeps: ExternalDispatchDeps = {},
): Promise<void> {
  if (argv[0] === '-v' || argv[0] === '--version' || argv[0] === 'version') {
    process.stdout.write(`${cliVersion() ?? 'unknown'}\n`);
    return;
  }

  const [command, ...rawRest] = argv;

  if (!command || command === '-h' || command === '--help') {
    process.stdout.write(USAGE);
    return;
  }

  // A global flag, honoured for every command — strip it before the subcommand's
  // own parseArgs (which is strict and would reject an unknown option).
  const noUpdateCheck = rawRest.includes('--no-update-check');
  const rest = rawRest.filter((a) => a !== '--no-update-check');

  // `Object.hasOwn`, not a truthy lookup: `COMMANDS` is an object literal, so a
  // plain index walks the prototype and `COMMANDS['constructor']` yields
  // `Object`. That is the one inherited name `isExternalCommandName` accepts, so
  // a truthy check would both call `Object(rest)` for `aka constructor` and stop
  // an `aka-constructor` on PATH from ever dispatching.
  const handler = Object.hasOwn(COMMANDS, command) ? COMMANDS[command] : undefined;

  // Git-style external dispatch: run `aka-<command>` from PATH with the verbatim
  // tail (an external command owns its whole argv, including --no-update-check).
  // A built-in handler takes precedence, so this never shadows a built-in; the
  // early return skips the post-command update notice.
  if (shouldDispatchExternal(command, handler !== undefined)) {
    const external = dispatchExternal(command, rawRest, dispatchDeps);
    if (external.found) {
      process.exitCode = external.status;
      return;
    }
  }

  if (!handler) {
    process.stderr.write(`aka: unknown command '${command}'\n\n${USAGE}`);
    process.exitCode = 1;
    return;
  }

  await handler(rest);

  // Passive, fail-open update notice. Suppressed for update-related commands, when
  // opted out, or when stdout isn't a TTY (pipes / CI) so machine output stays clean.
  if (!noUpdateCheck && !SKIP_NOTICE.has(command) && process.stdout.isTTY) {
    try {
      notifyFromCache(homeFromArgv(rest), { isTty: true });
    } catch {
      // the notice must never break a command
    }
  }
}
