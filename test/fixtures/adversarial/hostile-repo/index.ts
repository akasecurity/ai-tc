/**
 * The shared adversarial repository corpus.
 *
 * "Review this repo for me" on attacker-authored code is the realistic hostile
 * input for every tree walk here — the project-file inventory walk, the
 * dashboard's folder scan, and the standalone scanner. They need the SAME
 * inputs, and three private copies of a symlink loop drift, so the shapes live
 * at the repo root beside the no-network guard rather than inside any one
 * package.
 *
 * GENERATORS, NOT CHECKED-IN TREES. Half of these cannot live in git at all — a
 * symlink loop, a 500k-file tree, a chain deeper than a path can address — and
 * the ones that could would read as a mistake in a repository listing.
 * Everything is materialised into a temp dir and removed by
 * {@link HostileRepo.cleanup}.
 *
 * Every shape starts from {@link createHostileRepo}, which mints the `.git`
 * marker the walkers use to recognise a repository root. Nothing here knows what
 * a walker does with the tree: these functions build directories, and the
 * assertions belong to the caller.
 */
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

export interface HostileRepo {
  /** Absolute path to the repository root (already carrying a `.git` dir). */
  readonly root: string;
  /**
   * Removes the tree. Safe to call twice, and safe after a shape threw halfway —
   * a fixture that cannot be torn down leaves a temp dir behind on every run.
   */
  cleanup: () => void;
  /**
   * Teardown a shape has to run before the tree can simply be removed. Only
   * {@link deepChain} sets one; it is on the interface rather than hidden behind
   * a cast because a fixture whose cleanup contract is invisible is one nobody
   * maintains correctly.
   *
   * Register through {@link HostileRepo.addUnwind} rather than assigning: one
   * slot plus a plain assignment means the second shape to want a teardown
   * silently drops the first one's, and what is left behind is then exactly the
   * deep chain that `rmSync` is worst at removing.
   */
  unwind?: (() => void) | undefined;
  /** Registers `fn` to run before any teardown already registered. */
  addUnwind: (fn: () => void) => void;
}

/**
 * How a shape that cannot be built everywhere reports itself. A caller gates on
 * `created` and skips with `reason` rather than asserting against a tree the
 * platform refused to make — an early `return` would report as a pass.
 */
export interface ShapeOutcome {
  created: boolean;
  reason: string;
}

const BUILT = 'built';

/**
 * Files per directory, refused rather than clamped when it cannot make progress.
 * The `while (made < count)` loops below advance by `Math.min(perDir, …)`, so a
 * `perDir` of zero adds nothing on every pass and the fixture spins until the
 * suite's timeout — surfacing as the walker hanging, which is the defect these
 * shapes exist to detect.
 */
function batchSize(perDir: number): number {
  if (!Number.isInteger(perDir) || perDir < 1) {
    throw new RangeError(`perDir must be a positive integer, got ${String(perDir)}`);
  }
  return perDir;
}

/** A repository root in a fresh temp dir, with the `.git` marker in place. */
export function createHostileRepo(prefix = 'aka-hostile-'): HostileRepo {
  const root = mkdtempSync(join(tmpdir(), prefix));
  mkdirSync(join(root, '.git'));
  const repo: HostileRepo = {
    root,
    addUnwind(fn) {
      const previous = repo.unwind;
      // Newest first: shapes come apart in the reverse of the order they were
      // built, and a later shape may sit inside an earlier one's tree.
      repo.unwind =
        previous === undefined
          ? fn
          : () => {
              fn();
              previous();
            };
    },
    cleanup() {
      const pending = repo.unwind;
      repo.unwind = undefined;
      pending?.();
      rmSync(root, { recursive: true, force: true });
    },
  };
  return repo;
}

// ─── Scale shapes ─────────────────────────────────────────────────────────────

/**
 * `count` ordinary source files, spread `perDir` to a directory so no single
 * `readdir` returns an unrealistic number of entries.
 */
export function flatFiles(repo: HostileRepo, count: number, perDir = 500): void {
  const batch = batchSize(perDir);
  let made = 0;
  let bucket = 0;
  while (made < count) {
    const take = Math.min(batch, count - made);
    const dir = join(repo.root, `pkg${String(bucket)}`);
    mkdirSync(dir, { recursive: true });
    for (let i = 0; i < take; i++) writeFileSync(join(dir, `f${String(i)}.ts`), 'x');
    made += take;
    bucket++;
  }
}

/**
 * `count` files inside a directory the root `.gitignore` names. A walk that
 * honours the layer refuses the directory outright and never looks inside — the
 * cheap half of "500k gitignored files".
 */
export function ignoredSubtree(repo: HostileRepo, count: number, dirName = 'vendor-cache'): void {
  writeFileSync(join(repo.root, '.gitignore'), `${dirName}/\n`);
  writeFileSync(join(repo.root, 'index.ts'), 'x');
  let made = 0;
  let bucket = 0;
  while (made < count) {
    const take = Math.min(1000, count - made);
    const dir = join(repo.root, dirName, `d${String(bucket)}`);
    mkdirSync(dir, { recursive: true });
    for (let i = 0; i < take; i++) writeFileSync(join(dir, `f${String(i)}.bin`), 'x');
    made += take;
    bucket++;
  }
}

/**
 * `count` files ignored by PATTERN rather than by directory, so every one of
 * them comes back from a `readdir` and is tested before being dropped. This is
 * the expensive half of "500k gitignored files", and the one traversal cost has
 * to survive: `MAX_FILES` caps what is KEPT, and none of these is.
 */
export function ignoredByPattern(repo: HostileRepo, count: number, perDir = 1000): void {
  const batch = batchSize(perDir);
  writeFileSync(join(repo.root, '.gitignore'), '*.tmp\n');
  writeFileSync(join(repo.root, 'index.ts'), 'x');
  let made = 0;
  let bucket = 0;
  while (made < count) {
    const take = Math.min(batch, count - made);
    const dir = join(repo.root, `d${String(bucket)}`);
    mkdirSync(dir, { recursive: true });
    for (let i = 0; i < take; i++) writeFileSync(join(dir, `f${String(i)}.tmp`), 'x');
    made += take;
    bucket++;
  }
}

/**
 * `dirs` SIBLING directories, each carrying its own `.gitignore`. Every entry is
 * tested against the root layer plus its own directory's — two, however many
 * directories there are.
 */
export function gitignorePerDirectory(repo: HostileRepo, dirs: number, filesPerDir = 2): void {
  for (let i = 0; i < dirs; i++) {
    const dir = join(repo.root, `d${String(i)}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, '.gitignore'), `*.log\nbuild-${String(i)}/\n`);
    for (let f = 0; f < filesPerDir; f++) writeFileSync(join(dir, `f${String(f)}.ts`), 'x');
  }
}

/**
 * `depth` NESTED directories, each carrying its own `.gitignore`, with `files`
 * source files at the bottom.
 *
 * This and the sibling arrangement above are both "N directories each with a
 * `.gitignore`", and they cost different orders of magnitude: layers ACCUMULATE
 * down the tree, so each bottom file here is tested against `depth` of them
 * while each file in the sibling shape is tested against two. Patterns are
 * unique per level so none of them matches — the case where no layer can answer
 * and all `depth` are consulted.
 *
 * Reports `created: false` with the depth it reached when the platform's path
 * ceiling cuts the chain short; the files are still written at whatever depth it
 * got to, so the shape stays walkable and a caller can report the shortfall
 * rather than skip.
 */
export interface NestedChain extends ShapeOutcome {
  /** Levels actually built — equal to the requested depth only when `created`. */
  depth: number;
}

export function nestedGitignoreChain(repo: HostileRepo, depth: number, files: number): NestedChain {
  let cur = repo.root;
  let built = 0;
  for (let i = 0; i < depth; i++) {
    const next = join(cur, 'd');
    try {
      mkdirSync(next);
      writeFileSync(join(next, '.gitignore'), `*.log${String(i)}\nbuild-${String(i)}/\n`);
    } catch (err) {
      // Almost always ENAMETOOLONG: each level costs two characters, so Windows'
      // default 260-character MAX_PATH stops this around depth 100 where macOS
      // reaches ~470 and Linux ~2,000. Reported rather than thrown, because a
      // ceiling the platform imposes is not the walker misbehaving.
      for (let f = 0; f < files; f++) writeFileSync(join(cur, `f${String(f)}.ts`), 'x');
      return {
        created: false,
        reason: `chain stopped at depth ${String(built)} of ${String(depth)}: ${String(err)}`,
        depth: built,
      };
    }
    cur = next;
    built = i + 1;
  }
  for (let i = 0; i < files; i++) writeFileSync(join(cur, `f${String(i)}.ts`), 'x');
  return { created: true, reason: BUILT, depth: built };
}

// ─── Depth ────────────────────────────────────────────────────────────────────

export interface DeepChain extends ShapeOutcome {
  /** Levels an ABSOLUTE path can still address under the repo root. */
  addressable: number;
  /** Absolute path to the deepest addressable directory. */
  deepest: string;
  /** Levels built past `addressable`, reachable only by a relative path. */
  beyond: number;
  /** Whether those levels really did become unaddressable. */
  unaddressable: boolean;
}

/**
 * One nested chain that runs as deep as an absolute path can go, and then a
 * little further.
 *
 * TWO DIFFERENT THINGS ARE BEING BUILT, and they need different tactics.
 *
 * The addressable part is the ceiling on how far a recursive walk can ever
 * recurse, and it is an OS limit rather than a V8 one: every walker here calls
 * `readdirSync` with an absolute path, and `PATH_MAX` caps that string. With the
 * one-character names used here it MEASURES 476 on macOS, where `PATH_MAX` is
 * 1024 and each level costs two characters; the same arithmetic over Linux's
 * 4096 puts it near 2,000, and on Windows it moves by two orders of magnitude
 * with the long-path setting. Orders of magnitude below where a JS stack is at
 * risk, either way — which is the answer to "does 10,000-deep nesting overflow".
 * It is built with plain absolute `mkdirSync`, one call per level, and probed
 * rather than hardcoded because only the first of those three was measured.
 *
 * The part PAST the ceiling can only be created through a relative path, which
 * means `process.chdir`, and that is where the cost lives: the OS re-resolves an
 * ever-longer working directory on every step, so a chdir descent is QUADRATIC
 * in depth. Measured on an arm64 Mac: the first 500 levels take 35 ms, the next
 * 1,000 take 4.0 s, the next 2,000 take 31 s and the next 4,000 take 156 s — a
 * 10,000-level chdir chain costs about 348 s to build and about as long to
 * remove. So this descends only a handful of levels, and gets past the ceiling
 * by making the NAMES long (255 characters, the component limit) rather than the
 * chain deep. A couple of levels clear `PATH_MAX` on macOS and Linux; a
 * long-path Windows needs more, which is why it stops as soon as the deepest
 * directory has genuinely stopped being addressable.
 *
 * Reports `unaddressable: false` if it never managed that within `maxBeyond` —
 * a caller asserting on truncation must gate on it rather than assume.
 * `process.chdir` is absent inside a worker thread, so that reports
 * `created: false` instead of throwing.
 */
export function deepChain(
  repo: HostileRepo,
  { limit = 4_096, maxBeyond = 160 }: { limit?: number; maxBeyond?: number } = {},
): DeepChain {
  // Build down to the ceiling with absolute paths — cheap, one syscall a level.
  let addressable = 0;
  let deepest = repo.root;
  for (let i = 0; i < limit; i++) {
    const next = join(deepest, 'd');
    try {
      mkdirSync(next);
    } catch {
      break;
    }
    deepest = next;
    addressable = i + 1;
  }

  const base: DeepChain = {
    created: false,
    reason: BUILT,
    addressable,
    deepest,
    beyond: 0,
    unaddressable: false,
  };
  // Whatever happens next, the addressable part still has to come back out.
  let unwindBeyond: () => void = () => undefined;
  repo.addUnwind(() => {
    unwindBeyond();
    let cur = deepest;
    for (let i = addressable; i > 0; i--) {
      try {
        for (const entry of readdirSync(cur, { withFileTypes: true })) {
          if (!entry.isDirectory()) unlinkSync(join(cur, entry.name));
        }
        rmdirSync(cur);
      } catch {
        // Already gone, or never made.
      }
      cur = dirname(cur);
    }
  });

  if (typeof process.chdir !== 'function') {
    return { ...base, reason: 'process.chdir is unavailable in a worker thread' };
  }

  const LONG = 'x'.repeat(255);
  const before = process.cwd();
  let beyond = 0;
  let unaddressable = false;
  let failure: string | undefined;
  // Nothing between here and the restore may suspend: the working directory is
  // process-wide, so an await inside this window hands a wrong cwd to whatever
  // runs next.
  try {
    process.chdir(deepest);
    let abs = deepest;
    for (let i = 0; i < maxBeyond && !unaddressable; i++) {
      mkdirSync(LONG);
      process.chdir(LONG);
      beyond++;
      abs = join(abs, LONG);
      try {
        readdirSync(abs);
      } catch {
        unaddressable = true;
      }
    }
    writeFileSync('leaf.ts', 'x');
  } catch (err) {
    failure = `relative descent stopped at ${String(beyond)}: ${String(err)}`;
  } finally {
    process.chdir(before);
  }

  const madeBeyond = beyond;
  unwindBeyond = () => {
    const restore = process.cwd();
    try {
      process.chdir(deepest);
      for (let i = 0; i < madeBeyond; i++) process.chdir(LONG);
      for (let i = 0; i < madeBeyond; i++) {
        // Clear the level before leaving it. The leaf is not the only thing down
        // here — a caller may have planted markers — and one survivor turns the
        // `rmdir` below into ENOTEMPTY.
        for (const entry of readdirSync('.', { withFileTypes: true })) {
          if (!entry.isDirectory()) unlinkSync(entry.name);
        }
        process.chdir('..');
        // Relative and non-recursive on purpose: `rmSync({ recursive: true })`
        // resolves to an absolute path, meets PATH_MAX, and then RETRIES, which
        // is what turns a teardown into minutes.
        rmdirSync(LONG);
      }
    } catch {
      // Best effort; the absolute part below still comes out.
    } finally {
      process.chdir(restore);
    }
  };

  return {
    created: failure === undefined,
    reason: failure ?? BUILT,
    addressable,
    deepest,
    beyond,
    unaddressable,
  };
}

// ─── Hostile shapes ───────────────────────────────────────────────────────────

/**
 * Symlink loops: a link to the repo root, a link to its own parent, a mutual
 * pair, and a dangling one. A walker that follows directory symlinks fails to
 * terminate on any of them.
 *
 * Windows needs a privilege for `symlink`, so an unprivileged run reports
 * `created: false` instead of failing.
 */
export function symlinkLoops(repo: HostileRepo): ShapeOutcome {
  const a = join(repo.root, 'a');
  const b = join(repo.root, 'b');
  mkdirSync(a, { recursive: true });
  mkdirSync(b, { recursive: true });
  writeFileSync(join(a, 'real.ts'), 'x');
  writeFileSync(join(b, 'real.ts'), 'x');
  try {
    symlinkSync(repo.root, join(a, 'to-root'), 'dir');
    symlinkSync(a, join(a, 'to-self'), 'dir');
    symlinkSync(b, join(a, 'to-b'), 'dir');
    symlinkSync(a, join(b, 'to-a'), 'dir');
    symlinkSync(join(repo.root, 'nowhere'), join(repo.root, 'dangling'), 'dir');
  } catch (err) {
    return { created: false, reason: `symlink unavailable: ${String(err)}` };
  }
  return { created: true, reason: BUILT };
}

/**
 * Entries whose NAMES contain `..`. None escapes anything on its own — the point
 * is that a walker joining them into a repo-relative path must not produce one
 * that climbs out of the repository.
 */
export function dotDotNames(repo: HostileRepo): void {
  const dir = join(repo.root, 'weird');
  mkdirSync(dir, { recursive: true });
  for (const name of ['..hidden.ts', '...three.ts', 'a..b.ts']) {
    writeFileSync(join(dir, name), 'x');
  }
  const nested = join(dir, '..nested');
  mkdirSync(nested, { recursive: true });
  writeFileSync(join(nested, 'inner.ts'), 'x');
}

/**
 * A `.gitignore` that ignores the entire repository. The inventory walk must
 * read "nothing survived" as a failed walk and drop the scan, never publish an
 * empty tree that would prune whatever is already stored.
 */
export function ignoreEverything(repo: HostileRepo): void {
  writeFileSync(join(repo.root, '.gitignore'), '*\n');
  writeFileSync(join(repo.root, 'index.ts'), 'x');
  const dir = join(repo.root, 'src');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'app.ts'), 'x');
}
