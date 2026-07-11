import { spawn } from 'node:child_process';

// Open a URL in the user's default browser, cross-platform. Best-effort: a
// headless/SSH environment has no opener, so failures are swallowed (the URL is
// always printed too).
export function openUrl(url: string): void {
  const platform = process.platform;
  const command = platform === 'darwin' ? 'open' : platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try {
    spawn(command, args, { stdio: 'ignore', detached: true }).unref();
  } catch {
    // No opener available — the caller has already printed the URL.
  }
}
