// Removing a temp store's tree, with the Windows facts accounted for.
//
// A test here opens a real `LocalDatabase` on a temp base — through
// `createVaultGlue`, which owns the handle. Closing the glue gives that handle
// back, but Windows can still hold the store's files for a moment afterwards:
// the `-wal` and `-shm` sidecars outlive the connection briefly, and `rmSync`
// meets EPERM on a tree that POSIX would unlink without complaint.
//
// `@akasecurity/persistence` solves this in its own test harness, but that
// harness is behind a package wall and is not importable here, so plugin-sdk
// carries the same rules in miniature:
//
//   retry     through the window where a handle is merely on its way out;
//   tolerate  on win32 only, handing the tree to the OS temp sweeper rather
//             than failing a test whose assertions already passed.
//
// POSIX keeps throwing. There, these codes mean a cleanup genuinely did not run
// — a glue left unclosed, say — and that is a defect in the test, not a
// property of the platform.
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
