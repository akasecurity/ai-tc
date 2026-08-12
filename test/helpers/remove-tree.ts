// Removing a temp tree, with the Windows facts accounted for.
//
// A test that opens a real store on a temp base hands its handle back when it
// closes, but Windows can still hold the files for a moment afterwards: the
// `-wal` and `-shm` sidecars outlive the connection briefly, and `rmSync` meets
// EPERM on a tree POSIX would unlink without complaint. So:
//
//   retry     through the window where a handle is merely on its way out;
//   tolerate  on win32 only, handing the tree to the OS temp sweeper rather
//             than failing a test whose assertions already passed.
//
// POSIX keeps throwing. There, these codes mean a cleanup genuinely did not run
// — a store left unclosed, say — and that is a defect in the test, not a
// property of the platform.
//
// It sits at the repo root for the reason the no-network guard and the
// adversarial fixture corpus do: nine packages' teardowns need the SAME rule,
// `@akasecurity/persistence`'s own harness is behind a package wall and is not
// importable from any of them, and private copies of a platform rule drift
// apart. A relative import reaches this from every one of them, which is how
// `test/fixtures/adversarial/hostile-repo` is already consumed.
//
// Its suite is `packages/plugin-sdk/test/helpers/remove-tree.test.ts`, not a
// sibling of this file: the repo root is not a workspace package, so `turbo run
// test` reaches no test task here and a root-level suite would run outside both
// the no-network setupFile and the guard that enumerates vitest packages.
//
// `test/helpers/**` is in turbo's `globalDependencies` for the reason
// `test/setup/**` is — outside every package, nothing else would put this file
// in a `test` task's hash, and weakening it would leave every package replaying
// a cached green produced under the old rule.
import { rmSync } from 'node:fs';

// Typed to admit `undefined` so an error carrying no `code` is simply not a
// member — which is why no `code === undefined` guard appears below. Such a
// guard cannot change the outcome (a miss on the set already rethrows) and so
// no mutation of it can be killed; unkillable code sitting beside a suite whose
// every other line is pinned reads as one more pinned property.
const STILL_HELD: ReadonlySet<string | undefined> = new Set([
  'EPERM',
  'EBUSY',
  'EACCES',
  'ENOTEMPTY',
]);

export function removeTree(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (process.platform !== 'win32' || !STILL_HELD.has(code)) throw err;
  }
}
