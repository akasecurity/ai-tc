#!/usr/bin/env node
/**
 * Renders the Homebrew formula, the Scoop manifest and the VERSION file for one
 * binary release from the SHA256SUMS that release publishes.
 *
 *   node tools/package-manifests/src/render-manifests.ts \
 *     --version 0.9.11 --repo akasecurity/ai-tc --sums dist/SHA256SUMS --out dist
 *
 * Exit 0 having written all three, or exit 1 naming the fault having written
 * none: a directory holding a formula and no VERSION still satisfies a release
 * step's glob, and publishes a formula whose upgrade probe points at a file that
 * does not exist.
 */
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  type ManifestInput,
  ManifestInputError,
  parseSums,
  renderFormula,
  renderScoopManifest,
  renderVersionFile,
} from './lib.ts';

/** The three renderers, injectable so the all-or-none order can be driven. */
export interface Renderers {
  formula: (input: ManifestInput) => string;
  scoop: (input: ManifestInput) => string;
  version: (version: string) => string;
}

/** Everything this entry touches outside itself. */
export interface EntryIo {
  renderers: Renderers;
  readFile: (path: string) => string;
  ensureDir: (path: string) => void;
  write: (path: string, body: string) => void;
  writeErr: (text: string) => void;
}

export const defaultIo: EntryIo = {
  renderers: {
    formula: renderFormula,
    scoop: renderScoopManifest,
    version: renderVersionFile,
  },
  readFile: (path) => readFileSync(path, 'utf8'),
  ensureDir: (path) => {
    mkdirSync(path, { recursive: true });
  },
  write: (path, body) => {
    writeFileSync(path, body);
  },
  writeErr: (text) => {
    process.stderr.write(text);
  },
};

/** The value of `--name value` or `--name=value`. Refuses an absent or empty one. */
export function flagValue(argv: readonly string[], name: string): string {
  for (const [index, token] of [...argv].entries()) {
    if (token === name) {
      const next = argv[index + 1];
      if (next === undefined || next === '' || next.startsWith('--')) break;
      return next;
    }
    if (token.startsWith(`${name}=`)) {
      const value = token.slice(name.length + 1);
      if (value === '') break;
      return value;
    }
  }
  throw new ManifestInputError(`${name} is required and takes a value`);
}

/** The filenames written into `--out`, in the order they are rendered. */
export const OUTPUT_NAMES = ['aka.rb', 'aka.json', 'VERSION'] as const;

function render(argv: readonly string[], io: EntryIo): void {
  const version = flagValue(argv, '--version');
  const repo = flagValue(argv, '--repo');
  const sumsPath = flagValue(argv, '--sums');
  const out = flagValue(argv, '--out');

  const input: ManifestInput = { version, repo, sums: parseSums(io.readFile(sumsPath)) };

  // Rendered first, written second. Every refusal above and inside these three
  // calls therefore lands before the first byte reaches the output directory.
  const rendered: readonly (readonly [string, string])[] = [
    ['aka.rb', io.renderers.formula(input)],
    ['aka.json', io.renderers.scoop(input)],
    ['VERSION', io.renderers.version(version)],
  ];

  io.ensureDir(out);
  for (const [name, body] of rendered) {
    io.write(join(out, name), body);
  }
}

/** Runs one render and returns the process exit code. */
export function main(argv: readonly string[], io: EntryIo): number {
  try {
    render(argv, io);
    return 0;
  } catch (err) {
    const reason = err instanceof ManifestInputError ? err.message : String(err);
    io.writeErr(`package-manifests: ${reason}\n`);
    return 1;
  }
}

/**
 * Whether `invokedAs` names this module. Both sides are resolved through
 * symlinks: the loader reports the real path, while argv carries whatever path
 * the caller typed.
 */
export function isEntry(invokedAs: string | undefined, moduleUrl: string): boolean {
  if (invokedAs === undefined) return false;
  try {
    return realpathSync(invokedAs) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

if (isEntry(process.argv[1], import.meta.url)) {
  process.exitCode = main(process.argv.slice(2), defaultIo);
}
