// What a package's `test` task hashes, and what one of its suites reads from
// outside the package — the two halves a cross-package guard has to hold
// against each other.
//
// A suite that reads a file in another package asserts something turbo does not
// know about: the default inputs are the package's own tracked files, so an
// edit to that other file leaves the task hash unchanged and a cached pass is
// replayed. The remedy is to name the file in the task's `inputs`; this module
// is what lets a suite prove it did.
//
//   declaredTestInputs     the `inputs` array of the package's own turbo.json,
//                          PARSED. A substring match over the file is satisfied
//                          by a commented-out entry and by a longer path that
//                          merely contains the one named, and turbo hashes
//                          nothing for either.
//   crossPackageSpecifiers every relative string literal in a test file that
//                          resolves outside its package, so the set of files a
//                          guard demands is derived from the reads rather than
//                          listed beside them.
//
// It sits at the repo root for the reason `remove-tree.ts` does: several
// packages need the same rule and a package wall blocks the import. Its suite
// is `packages/plugin-sdk/test/helpers/turbo-inputs.test.ts`, since the repo
// root is not a workspace package and `turbo run test` reaches no task here.
import { readFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';

/** How a repo-relative path is spelled as a turbo input. */
export function turboRootInput(repoRelative: string): string {
  return `$TURBO_ROOT$/${repoRelative}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The `tasks.test.inputs` array of `<packageDir>/turbo.json`.
 *
 * Full-line `//` comments are dropped before parsing, so a commented-out entry
 * reads as the absence it is. Anything else that is not JSON throws.
 */
export function declaredTestInputs(packageDir: string): string[] {
  const file = join(packageDir, 'turbo.json');
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    throw new Error(
      `${file} does not exist, so this package's test task falls back to the root ` +
        'definition and hashes nothing outside the package',
      { cause: err },
    );
  }
  const config: unknown = JSON.parse(text.replace(/^[ \t]*\/\/.*$/gm, ''));
  const tasks = isRecord(config) ? config.tasks : undefined;
  const test = isRecord(tasks) ? tasks.test : undefined;
  const inputs = isRecord(test) ? test.inputs : undefined;
  if (!Array.isArray(inputs) || !inputs.every((entry) => typeof entry === 'string')) {
    throw new Error(`${file} declares no tasks.test.inputs array of strings`);
  }
  return inputs;
}

export interface CrossPackageScan {
  /** Absolute path of the test file whose source is scanned. */
  testFile: string;
  /** Absolute path of the package that owns it. */
  packageDir: string;
  /** Absolute path of the repository root. */
  repoRoot: string;
}

/**
 * Repo-relative POSIX paths of every relative string literal in `testFile`
 * that resolves outside `packageDir`, sorted and de-duplicated. A literal
 * naming a directory the package sits inside is an anchor, not a read, and is
 * left out.
 *
 * Module specifiers of static `import`/`export … from` statements are left out:
 * those are code, reached through the shared `test/` trees turbo hashes
 * globally. Every other literal counts, including one in a comment or one
 * carrying an interpolation — both come back as paths no input will match, so
 * the scan errs toward demanding an input rather than toward missing a read.
 */
export function crossPackageSpecifiers({
  testFile,
  packageDir,
  repoRoot,
}: CrossPackageScan): string[] {
  const source = readFileSync(testFile, 'utf8').replace(
    /^[ \t]*(?:import|export)\b[^;'"`]*?from\s*(['"])[^'"]*\1;?/gm,
    '',
  );
  const found = new Set<string>();
  for (const [, , literal] of source.matchAll(/(['"`])(\.\.?\/[^'"`]*)\1/g)) {
    if (literal === undefined) continue;
    const target = resolve(dirname(testFile), literal);
    const fromPackage = relative(packageDir, target);
    if (fromPackage !== '..' && !fromPackage.startsWith(`..${sep}`)) continue;
    // A directory the package sits inside is an anchor to resolve against —
    // the repo root, typically — and never a file that could be hashed.
    const toPackage = relative(target, packageDir);
    if (toPackage !== '..' && !toPackage.startsWith(`..${sep}`)) continue;
    found.add(relative(repoRoot, target).split(sep).join('/'));
  }
  return [...found].sort();
}
