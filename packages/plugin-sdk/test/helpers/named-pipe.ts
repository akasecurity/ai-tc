import { execFileSync, spawn } from 'node:child_process';

/**
 * Runs `fn` with a named pipe at `path` that a background writer feeds `content`. The writer lets
 * a read of the pipe finish, so a test whose code reads it fails an assertion instead of hanging.
 */
export function withNamedPipe<T>(path: string, content: string, fn: () => T): T {
  execFileSync('mkfifo', [path]);
  const writer = spawn('sh', ['-c', 'printf "%s\n" "$1" > "$2"', 'sh', content, path], {
    stdio: 'ignore',
  });
  try {
    return fn();
  } finally {
    writer.kill('SIGKILL');
  }
}
