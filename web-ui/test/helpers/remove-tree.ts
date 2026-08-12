// Removing a temp tree, with the Windows facts accounted for.
//
// The action and page suites here run against a real `~/.aka`, reached by
// mocking `node:os` so `homedir()` returns a per-test temp dir. Closing the
// store gives its file back, but Windows can still hold it for a moment
// afterwards: the `-wal` and `-shm` sidecars outlive the connection briefly,
// and `rmSync` meets EPERM on a tree that POSIX would unlink without complaint.
// That is a teardown failing AFTER its test's assertions have all passed, which
// reads in CI as the test itself being broken on Windows.
//
// The memoised handle is what makes this sharper here than elsewhere:
// `app/lib/db.ts` keeps its `LocalDatabase` on `globalThis.__akaDb` across
// requests and HMR reloads, so the connection outlives any single action call
// and is released only when a hook closes and drops it. A suite that drops it
// without closing, or that reopens it mid-test through a second handle, reaches
// teardown with a live connection on the tree being removed.
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
// — `__akaDb` left open, say — and that is a defect in the test, not a property
// of the platform.
//
// Not for `store-bytes.test.ts`, which opens no store at all and so has nothing
// to be held: its temp tree is plain files, and a bare `rmSync` there is right.
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
