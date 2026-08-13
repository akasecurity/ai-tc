// Pure helpers for the /aka:dashboard launcher (src/dashboard.ts). Kept free of
// I/O so the arg parsing + user-facing copy unit-test without spawning anything;
// the entry script owns the child_process spawn + stdout.

import type { BareCommandPlan } from '@akasecurity/plugin-sdk/bare-command';

// The CLI's default dashboard port + landing route — mirrors
// cli/src/commands/dashboard.ts so the URL we print matches where `aka`
// actually serves.
export const DEFAULT_PORT = '4319';
const ROUTE = '/security';

// The port `aka dashboard` will bind: honour a forwarded `--port <N>` / `--port=N`
// so the printed URL tracks the CLI; default otherwise.
export function parsePort(argv: string[]): string {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? '';
    if (arg === '--port') return argv[i + 1] ?? DEFAULT_PORT;
    if (arg.startsWith('--port=')) return arg.slice('--port='.length);
  }
  return DEFAULT_PORT;
}

export function dashboardUrl(port: string): string {
  return `http://localhost:${port}${ROUTE}`;
}

export function startMessage(url: string): string {
  return (
    `Starting the AKA dashboard at ${url} — it opens in your browser once ready.\n` +
    `It serves your local store at ~/.aka/data; leave it running (stop it with Ctrl-C in that process).`
  );
}

// Shown when the `aka` CLI isn't on PATH: the plugin ships no web server of its
// own, so the dashboard is launched by @akasecurity/cli.
export const INSTALL_HINT =
  'The AKA dashboard is launched by the `aka` CLI, which the plugin does not bundle.\n' +
  'Install it and run /aka:dashboard again:\n' +
  '  npm i -g @akasecurity/cli      # then it is on your PATH as `aka`\n' +
  'From a repo checkout instead:  pnpm --filter @akasecurity/cli dev dashboard';

// Shown when a forwarded flag cannot be handed to the command interpreter that
// reaches `aka` on Windows. Deliberately NOT INSTALL_HINT: the CLI is installed
// and reachable, so telling the user to install it points them at the one place
// the problem is not. `reason` names an argv position and a character class,
// never the value sitting at it.
export function unsupportedArgvMessage(reason: string): string {
  return (
    `The AKA dashboard could not be launched: ${reason}.\n` +
    'Re-run without that flag, or start the dashboard directly:\n' +
    '  aka dashboard'
  );
}

// What the probe asks `aka`, to find out whether it answers at all.
export const PROBE_FLAG = '--help';

// The spawn options a probe is run with — the plan's own, plus a silenced stdio.
export interface ProbeOptions {
  readonly stdio: 'ignore';
  readonly shell?: true;
  readonly cwd?: string;
}

// The one field of a spawn result this module reads. Narrow on purpose: the
// entry script passes `spawnSync`, and nothing else here needs to know that.
export type ProbeSpawn = (
  file: string,
  args: readonly string[],
  options: ProbeOptions,
) => { error?: Error | undefined };

// Is the `aka` CLI unreachable?
//
// Answered from the SAME plan the launch then spawns, so the probe can never
// report on a spawn the launcher does not make — a shell-free probe in front of
// a shelled spawn reports a false miss, and the reverse reports a false pass.
//
// What "missing" looks like differs by path, and BOTH readings have to be
// written down or the answer is wrong on one of them:
//
//   - Shell-free — POSIX always, and Windows when `aka` resolved to a real
//     executable (the binary channel's `aka.exe`). The spawn itself reports
//     ENOENT, which is the original test, unchanged.
//   - Through cmd.exe — Windows, where an npm-installed `aka` is a `.cmd` shim.
//     The interpreter is what gets spawned, so the spawn SUCCEEDS whether or not
//     `aka` exists, and a missing CLI comes back as cmd's own "not recognized"
//     exit code. ENOENT is unreachable there, so an ENOENT test could only ever
//     answer "installed" — including when it was not. Resolution is the question
//     on that path, and the plan has already asked it.
//
// `probe` is a parameter so this file stays free of I/O and both readings are
// unit-testable; the entry script passes the real `spawnSync`.
export function akaMissing(
  plan: Pick<BareCommandPlan, 'viaShell' | 'resolved' | 'file' | 'options'>,
  probe: ProbeSpawn,
): boolean {
  if (plan.viaShell) return plan.resolved === undefined;
  const { error } = probe(plan.file, [PROBE_FLAG], { stdio: 'ignore', ...plan.options });
  return (error as NodeJS.ErrnoException | undefined)?.code === 'ENOENT';
}
