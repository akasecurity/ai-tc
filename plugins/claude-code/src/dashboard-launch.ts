// Pure helpers for the /aka:dashboard launcher (src/dashboard.ts). Kept free of
// I/O so the arg parsing + user-facing copy unit-test without spawning anything;
// the entry script owns the child_process spawn + stdout.

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
