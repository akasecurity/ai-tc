// Removing a temp tree, with the Windows facts accounted for.
//
// The native-messaging host suite opens a real `LocalDatabase` over a temp
// `~/.aka`. Closing that handle gives the file back, but Windows can still hold
// the store's files for a moment afterwards: the `-wal` and `-shm` sidecars
// outlive the connection briefly, and `rmSync` meets EPERM on a tree that POSIX
// would unlink without complaint. That is a teardown failing AFTER its test's
// assertions have all passed, which reads in CI as the test itself being broken
// on Windows.
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
// — a store left open, say — and that is a defect in the test, not a property
// of the platform.
//
// This package is not in the Windows leg's `--filter` list, so the tolerance
// here is not exercised by CI on the platform it is for. It is carried because
// the host opens the same store on the same shape of tree as the packages that
// are, and a suite that starts running there should not have to rediscover it.
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
