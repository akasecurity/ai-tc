// Removing a temp tree, with the Windows facts accounted for.
//
// The suites here open a real `LocalDatabase` over a temp `~/.aka` — the fs
// scan pipeline and the egress-record path both write through one. Closing that
// handle gives the file back, but Windows can still hold the store's files for
// a moment afterwards: the `-wal` and `-shm` sidecars outlive the connection
// briefly, and `rmSync` meets EPERM on a tree that POSIX would unlink without
// complaint. That is a teardown failing AFTER its test's assertions have all
// passed, which reads in CI as the test itself being broken on Windows.
//
// The scan suites add a second holder that POSIX also hides: a `worker_thread`
// running the guarded scan keeps its own handles, and `terminate()` resolves
// before the OS has necessarily released them.
//
// `@akasecurity/persistence` solves this in its own test harness, but that sits
// behind a package wall — its `exports` map is `"." -> "./src/index.ts"` alone —
// so this package carries the same rules again:
//
//   retry     through the window where a handle is merely on its way out;
//   tolerate  on win32 only, handing the tree to the OS temp sweeper rather
//             than failing a test whose assertions already passed.
//
// POSIX keeps throwing. There, these codes mean a cleanup genuinely did not run
// — a store or a worker left open, say — and that is a defect in the test, not
// a property of the platform.
import { rmSync } from 'node:fs';

const STILL_HELD = new Set(['EPERM', 'EBUSY', 'EACCES', 'ENOTEMPTY']);

export function removeTree(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (process.platform !== 'win32' || code === undefined || !STILL_HELD.has(code)) throw err;
  }
}
