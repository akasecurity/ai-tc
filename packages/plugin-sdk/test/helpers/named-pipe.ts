import { execFileSync, spawn } from 'node:child_process';

/**
 * Runs `fn` with a named pipe at `path` that a background writer feeds `content`. The writer
 * reopens the pipe after each reader, so any number of reads finish, and code that reads the pipe
 * fails an assertion instead of hanging. The pause gives a reader time to see end-of-file before
 * the next open; without it a read can go on indefinitely.
 */
export function withNamedPipe<T>(path: string, content: string, fn: () => T): T {
  execFileSync('mkfifo', [path]);
  const writer = spawn(
    'sh',
    ['-c', 'while :; do printf "%s\n" "$1" > "$2" || break; sleep 0.01; done', 'sh', content, path],
    { stdio: 'ignore' },
  );
  try {
    return fn();
  } finally {
    writer.kill('SIGKILL');
  }
}
