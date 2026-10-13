import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, sep } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { collectFiles } from '../src/fs-scan.ts';

let base: string;
let home: string;
let akaHome: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-fs-scan-locations-'));
  home = join(base, 'home');
  akaHome = join(home, '.aka');
  mkdirSync(home);
});

afterEach(() => {
  removeTrees([base]);
});

function write(path: string): string {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, 'x\n');
  return path;
}

function walked(target: string): string[] {
  return [...collectFiles(target, { home, akaHome })]
    .map((f) => relative(target, f.path).split(sep).join('/'))
    .sort();
}

const HOME_SECRET_FILES = [
  '.aws/credentials',
  '.config/gh/hosts.yml',
  '.docker/config.json',
  '.gem/credentials',
  '.kube/config',
];

describe('collectFiles — dot-directories inside a project', () => {
  it('enters dot-directories that are not generated or cache directories', () => {
    const project = join(home, 'code', 'app');
    write(join(project, '.aws', 'credentials'));
    write(join(project, '.docker', 'config.json'));
    write(join(project, '.config', 'tool', 'settings.json'));
    write(join(project, '.github', 'workflows', 'ci.yml'));
    write(join(project, 'src', 'app.ts'));

    expect(walked(project)).toEqual([
      '.aws/credentials',
      '.config/tool/settings.json',
      '.docker/config.json',
      '.github/workflows/ci.yml',
      'src/app.ts',
    ]);
  });

  it.each(['.git', '.venv', '.cache', '.next', '.turbo', '.yarn', '.gradle', '.terraform', '.tox'])(
    'still skips the generated directory %s',
    (name) => {
      const project = join(home, 'code', 'app');
      write(join(project, name, 'inner', 'file.txt'));
      write(join(project, 'keep.ts'));

      expect(walked(project)).toEqual(['keep.ts']);
    },
  );

  it('lets an .akaignore exclude a dot-directory', () => {
    const project = join(home, 'code', 'app');
    write(join(project, '.aws', 'credentials'));
    writeFileSync(join(project, '.akaignore'), '.aws/\n');

    expect(walked(project)).toEqual(['.akaignore']);
  });

  it('does not read the home secret files when the target is a project under home', () => {
    for (const file of HOME_SECRET_FILES) write(join(home, file));
    const project = join(home, 'code', 'app');
    write(join(project, 'app.ts'));

    expect(walked(project)).toEqual(['app.ts']);
  });
});

describe('collectFiles — the home directory as the target', () => {
  it('reads the home secret files and root dotfiles, and enters no other home dot-directory', () => {
    for (const file of HOME_SECRET_FILES) write(join(home, file));
    write(join(home, '.env'));
    write(join(home, '.zshrc'));
    write(join(home, '.npmrc'));
    write(join(home, '.netrc'));
    write(join(home, '.cache', 'big.bin'));
    write(join(home, '.claude', 'projects', 'session.jsonl'));
    write(join(home, '.config', 'other', 'settings.json'));
    write(join(home, '.aws', 'config'));
    write(join(home, 'notes', 'todo.md'));

    expect(walked(home)).toEqual(
      [...HOME_SECRET_FILES, '.env', '.netrc', '.npmrc', '.zshrc', 'notes/todo.md'].sort(),
    );
  });

  it('skips a home secret file that is absent or is a directory', () => {
    write(join(home, '.aws', 'credentials'));
    mkdirSync(join(home, '.kube', 'config'), { recursive: true });

    expect(walked(home)).toEqual(['.aws/credentials']);
  });

  it('honours the home .akaignore for a secret file and for its directory', () => {
    for (const file of HOME_SECRET_FILES) write(join(home, file));
    writeFileSync(join(home, '.akaignore'), '.aws/\n.config/gh/hosts.yml\n');

    expect(walked(home)).toEqual(
      ['.akaignore', '.docker/config.json', '.gem/credentials', '.kube/config'].sort(),
    );
  });

  it('yields a home secret file once when an .akaignore negation re-includes its directory', () => {
    write(join(home, '.aws', 'credentials'));
    write(join(home, '.aws', 'config'));
    writeFileSync(join(home, '.akaignore'), '!.aws/\n');

    expect(walked(home)).toEqual(['.akaignore', '.aws/config', '.aws/credentials']);
  });

  it('marks a home secret file under a gitignored directory as gitignored', () => {
    write(join(home, '.aws', 'credentials'));
    writeFileSync(join(home, '.gitignore'), '.aws/\n');

    const found = [...collectFiles(home, { home, akaHome })].find((f) =>
      f.path.endsWith(join('.aws', 'credentials')),
    );
    expect(found).toEqual({ path: join(home, '.aws', 'credentials'), gitignored: true });
  });

  it('keeps the home dot-directory floor when home is reached from a parent target', () => {
    for (const file of HOME_SECRET_FILES) write(join(home, file));
    write(join(home, '.env'));
    write(join(home, 'notes', 'todo.md'));

    expect(walked(base)).toEqual(['home/.env', 'home/notes/todo.md']);
  });
});
