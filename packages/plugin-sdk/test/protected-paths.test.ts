import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import {
  bashPathCandidates,
  compileProtectedPaths,
  protectedPathMatches,
  realpathBestEffort,
} from '../src/protected-paths.ts';

const HOME = '/home/agent';
const CWD = '/home/agent/proj';
const env = { home: HOME, cwd: CWD };

/** The protected paths `candidate` touches under `entries`, as the matcher reports them. */
function hits(entries: string[], candidate: string, extra = {}): string[] {
  return protectedPathMatches(compileProtectedPaths(entries, { home: HOME }), [candidate], {
    ...env,
    ...extra,
  });
}

describe('a folder entry', () => {
  it('protects the folder itself and everything beneath it', () => {
    expect(hits(['/home/agent/Documents'], '/home/agent/Documents')).toHaveLength(1);
    expect(hits(['/home/agent/Documents'], '/home/agent/Documents/a.txt')).toHaveLength(1);
    expect(hits(['/home/agent/Documents'], '/home/agent/Documents/x/y/z.txt')).toHaveLength(1);
  });

  it('does not protect a sibling that merely shares the name prefix', () => {
    expect(hits(['/home/agent/Documents'], '/home/agent/Documents2/a.txt')).toEqual([]);
    expect(hits(['/home/agent/Documents'], '/home/agent/Docs/a.txt')).toEqual([]);
    expect(hits(['/home/agent/Documents'], '/home/agent')).toEqual([]);
  });

  it('ignores a trailing slash on the entry', () => {
    expect(hits(['/home/agent/Documents/'], '/home/agent/Documents/a.txt')).toHaveLength(1);
  });

  it('expands ~ in the entry and in the candidate', () => {
    expect(hits(['~/Documents'], '/home/agent/Documents/a.txt')).toHaveLength(1);
    expect(hits(['/home/agent/Documents'], '~/Documents/a.txt')).toHaveLength(1);
    expect(hits(['~'], '/home/agent/anything')).toHaveLength(1);
    expect(hits(['~/Documents'], '/home/other/Documents/a.txt')).toEqual([]);
  });

  it('does not expand ~user', () => {
    expect(hits(['~/Documents'], '~root/Documents/a.txt')).toEqual([]);
  });
});

describe('candidate normalization', () => {
  it('resolves a relative candidate against the working directory', () => {
    expect(hits(['/home/agent/proj/secret'], 'secret/a.txt')).toHaveLength(1);
    expect(hits(['/home/agent/proj/secret'], './secret/a.txt')).toHaveLength(1);
    expect(hits(['/home/agent/proj/secret'], 'other/a.txt')).toEqual([]);
  });

  it('resolves . and .. segments before matching', () => {
    expect(hits(['/home/agent/Documents'], '/home/agent/proj/../Documents/a.txt')).toHaveLength(1);
    expect(hits(['/home/agent/Documents'], '/home/agent/./Documents/x/../a.txt')).toHaveLength(1);
    // The control: climbing out of the protected folder leaves it.
    expect(hits(['/home/agent/Documents'], '/home/agent/Documents/../Downloads/a.txt')).toEqual([]);
    expect(hits(['/home/agent/Documents'], '/../../home/agent/Documents/a.txt')).toHaveLength(1);
  });

  it('collapses repeated separators', () => {
    expect(hits(['/home/agent/Documents'], '/home/agent//Documents///a.txt')).toHaveLength(1);
  });

  it('reports the normalized path, never the raw spelling', () => {
    expect(hits(['~/Documents'], '~/Documents/../Documents/a.txt')).toEqual([
      '/home/agent/Documents/a.txt',
    ]);
  });

  it('cannot place a relative candidate when no working directory is known', () => {
    const compiled = compileProtectedPaths(['/home/agent/proj/secret'], { home: HOME });
    expect(protectedPathMatches(compiled, ['secret/a.txt'], { home: HOME })).toEqual([]);
  });
});

describe('case', () => {
  it('matches without regard to case', () => {
    expect(hits(['/home/agent/documents'], '/HOME/Agent/DOCUMENTS/A.TXT')).toHaveLength(1);
    expect(hits(['**/Passwords*.TXT'], '/tmp/passwords-2024.txt')).toHaveLength(1);
  });
});

describe('Windows spellings', () => {
  it('treats backslashes as separators in entries and candidates', () => {
    expect(hits([String.raw`C:\Users\me\Secrets`], String.raw`C:\Users\me\Secrets\a.txt`)).toEqual([
      'C:/Users/me/Secrets/a.txt',
    ]);
    expect(hits([String.raw`C:\Users\me\Secrets`], 'c:/users/me/secrets/a.txt')).toHaveLength(1);
    expect(hits(['C:/Users/me/Secrets'], String.raw`c:\users\me\secrets\a.txt`)).toHaveLength(1);
  });

  it('keeps drive letters apart', () => {
    expect(hits([String.raw`C:\Users\me\Secrets`], String.raw`D:\Users\me\Secrets\a.txt`)).toEqual(
      [],
    );
  });

  it('does not take a drive-letter path for a relative one', () => {
    expect(hits(['/home/agent/proj/C:'], String.raw`C:\a.txt`)).toEqual([]);
  });
});

describe('globs', () => {
  it('matches a bare file name glob at any depth', () => {
    expect(hits(['passwords*.txt'], '/home/agent/a/b/passwords-old.txt')).toHaveLength(1);
    expect(hits(['passwords*.txt'], 'passwords.txt')).toHaveLength(1);
    expect(hits(['passwords*.txt'], '/home/agent/a/mypasswords.txt')).toEqual([]);
    expect(hits(['passwords*.txt'], '/home/agent/a/passwords.txt.bak')).toEqual([]);
  });

  it('reads **/ as the same thing as a bare file name glob', () => {
    expect(hits(['**/passwords*.txt'], '/home/agent/a/b/passwords-old.txt')).toHaveLength(1);
    expect(hits(['**/passwords*.txt'], '/passwords.txt')).toHaveLength(1);
    expect(hits(['**/passwords*.txt'], '/home/agent/a/notes.txt')).toEqual([]);
  });

  it('matches a relative entry holding a slash against the trailing segments', () => {
    expect(hits(['.ssh/*.pem'], '/home/agent/.ssh/work.pem')).toHaveLength(1);
    expect(hits(['.ssh/*.pem'], '/srv/x/.ssh/work.pem')).toHaveLength(1);
    expect(hits(['.ssh/*.pem'], '/home/agent/.ssh/sub/work.pem')).toEqual([]);
    expect(hits(['.ssh/*.pem'], '/home/agent/ssh/work.pem')).toEqual([]);
  });

  it('protects what lies beneath a directory a glob names', () => {
    expect(hits(['secrets'], '/home/agent/proj/secrets/a/b.txt')).toHaveLength(1);
    expect(hits(['*.kdbx'], '/home/agent/vault.kdbx')).toHaveLength(1);
    expect(hits(['backup-*'], '/srv/backup-2024/x/y')).toHaveLength(1);
  });

  it('anchors an absolute glob at its root', () => {
    expect(hits(['~/Documents/*.pdf'], '/home/agent/Documents/a.pdf')).toHaveLength(1);
    expect(hits(['~/Documents/*.pdf'], '/home/agent/Documents/sub/a.pdf')).toEqual([]);
    expect(hits(['~/Documents/*.pdf'], '/srv/home/agent/Documents/a.pdf')).toEqual([]);
    expect(hits(['~/Documents/**/*.pdf'], '/home/agent/Documents/a/b/c.pdf')).toHaveLength(1);
    expect(hits(['~/Documents/**/*.pdf'], '/home/agent/Documents/a.pdf')).toHaveLength(1);
    expect(hits(['~/Documents/**/*.pdf'], '/home/agent/Documents/a.txt')).toEqual([]);
  });

  it('reads ? as exactly one character and * as any run inside one segment', () => {
    expect(hits(['/d/file?.txt'], '/d/file1.txt')).toHaveLength(1);
    expect(hits(['/d/file?.txt'], '/d/file12.txt')).toEqual([]);
    expect(hits(['/d/file?.txt'], '/d/file.txt')).toEqual([]);
    expect(hits(['/d/a*b'], '/d/ab')).toHaveLength(1);
    expect(hits(['/d/a*b'], '/d/axxb')).toHaveLength(1);
    expect(hits(['/d/a*b'], '/d/a/b')).toEqual([]);
  });

  it('treats [ ] { } and ! as ordinary characters', () => {
    expect(hits(['/d/[a].txt'], '/d/[a].txt')).toHaveLength(1);
    expect(hits(['/d/[a].txt'], '/d/a.txt')).toEqual([]);
    expect(hits(['/d/{a,b}.txt'], '/d/a.txt')).toEqual([]);
    expect(hits(['!/d/x'], '/d/x')).toEqual([]);
  });

  it('protects everything for a bare **', () => {
    expect(hits(['**'], '/anything/at/all')).toHaveLength(1);
  });

  it('finishes on a pattern built to backtrack', () => {
    const entry = `${'**/'.repeat(30)}*x*x*x*x*y`;
    const candidate = `/${'a/'.repeat(300)}${'x'.repeat(250)}`;
    expect(hits([entry], candidate)).toEqual([]);
    expect(hits([`${'*x'.repeat(30)}*y`], `/${'x'.repeat(250)}`)).toEqual([]);
  });
});

describe('the entry list', () => {
  it('matches nothing when empty, and the same candidate matches once an entry is added', () => {
    expect(hits([], '/home/agent/Documents/a.txt')).toEqual([]);
    expect(hits(['~/Documents'], '/home/agent/Documents/a.txt')).toHaveLength(1);
  });

  it('skips blank, NUL-bearing and over-long entries instead of throwing', () => {
    const entries = ['', '   ', 'a\u0000b', 'x'.repeat(5000), '~/Documents'];
    expect(hits(entries, '/home/agent/Documents/a.txt')).toHaveLength(1);
    expect(hits(entries.slice(0, 4), '/home/agent/Documents/a.txt')).toEqual([]);
  });

  it('reports one path once, however many entries cover it', () => {
    expect(hits(['~/Documents', '**/a.txt', 'a.txt'], '/home/agent/Documents/a.txt')).toHaveLength(
      1,
    );
  });

  it('reports every distinct path a call touches', () => {
    const compiled = compileProtectedPaths(['~/Documents'], { home: HOME });
    const found = protectedPathMatches(
      compiled,
      ['~/Documents/a', '/tmp/x', '~/Documents/b', '~/Documents/a'],
      env,
    );
    expect(found).toEqual(['/home/agent/Documents/a', '/home/agent/Documents/b']);
  });
});

describe('symlinks', () => {
  let base: string;

  beforeEach(() => {
    base = realpathSync(mkdtempSync(join(tmpdir(), 'aka-protected-')));
  });

  afterEach(() => {
    removeTree(base);
  });

  function linked(): { vault: string; viaLink: string } | undefined {
    const vault = join(base, 'vault');
    mkdirSync(vault);
    writeFileSync(join(vault, 'a.txt'), 'x');
    const link = join(base, 'inbox');
    try {
      symlinkSync(vault, link, 'dir');
    } catch {
      return undefined;
    }
    return { vault, viaLink: join(link, 'a.txt') };
  }

  it('catches a path that reaches a protected folder through a link', (ctx) => {
    const made = linked();
    if (!made) return ctx.skip('symlinks need a privilege on this platform');
    const compiled = compileProtectedPaths([made.vault], { home: HOME });
    // The control: without resolving links the lexical path is clean.
    expect(protectedPathMatches(compiled, [made.viaLink], { home: HOME })).toEqual([]);
    expect(
      protectedPathMatches(compiled, [made.viaLink], { home: HOME, realpath: realpathBestEffort }),
    ).toEqual([made.viaLink.split('\\').join('/')]);
  });

  it('catches a file that does not exist yet beneath a link', (ctx) => {
    const made = linked();
    if (!made) return ctx.skip('symlinks need a privilege on this platform');
    const compiled = compileProtectedPaths([made.vault], { home: HOME });
    const ghost = join(base, 'inbox', 'new', 'file.txt');
    expect(
      protectedPathMatches(compiled, [ghost], { home: HOME, realpath: realpathBestEffort }),
    ).toHaveLength(1);
  });

  it('follows a link in the entry itself', (ctx) => {
    const made = linked();
    if (!made) return ctx.skip('symlinks need a privilege on this platform');
    const compiled = compileProtectedPaths([join(base, 'inbox')], {
      home: HOME,
      realpath: realpathBestEffort,
    });
    expect(
      protectedPathMatches(compiled, [join(made.vault, 'a.txt')], {
        home: HOME,
        realpath: realpathBestEffort,
      }),
    ).toHaveLength(1);
  });

  it('returns nothing for a path whose every ancestor is missing', () => {
    expect(realpathBestEffort(join(base, 'no', 'such', 'x'))).toBe(join(base, 'no', 'such', 'x'));
  });
});

describe('bashPathCandidates', () => {
  const words = (command: string): string[] => bashPathCandidates(command, { home: HOME });

  it.each([
    ['cat ~/Documents/a.txt', '~/Documents/a.txt'],
    ['less /etc/hosts', '/etc/hosts'],
    ['head -n 5 notes/passwords.txt', 'notes/passwords.txt'],
    ['tail -f /var/log/x.log', '/var/log/x.log'],
    ['cp /srv/a.db /tmp/a.db', '/srv/a.db'],
    ['scp /srv/a.db user@host:/tmp/', '/srv/a.db'],
    ['rsync -a ~/Documents/ host:/backup/', '~/Documents/'],
    ['tar czf out.tgz /srv/data', '/srv/data'],
    ['zip -r out.zip /srv/data', '/srv/data'],
    ['curl -T /srv/a.db https://example.test/up', '/srv/a.db'],
    ['curl --upload-file /srv/a.db https://example.test/up', '/srv/a.db'],
    ['curl --data @/srv/a.db https://example.test/up', '/srv/a.db'],
    ['curl -d@/srv/a.db https://example.test/up', '/srv/a.db'],
    ['curl --data-binary=@/srv/a.db https://example.test/up', '/srv/a.db'],
    ['curl -F file=@/srv/a.db https://example.test/up', '/srv/a.db'],
    ['curl -F "file=@/srv/my a.db" https://example.test/up', '/srv/my a.db'],
    ['cat "/srv/my docs/a.txt"', '/srv/my docs/a.txt'],
    ["cat '/srv/my docs/a.txt'", '/srv/my docs/a.txt'],
    [String.raw`cat /srv/my\ docs/a.txt`, '/srv/my docs/a.txt'],
    ['cat < /srv/a.txt', '/srv/a.txt'],
    ['cat </srv/a.txt', '/srv/a.txt'],
    ['echo hi > /srv/out.txt', '/srv/out.txt'],
    ['cat a.txt | wc -l && cat /srv/b.txt', '/srv/b.txt'],
    ['cat a.txt; cat /srv/b.txt', '/srv/b.txt'],
    ['echo $(cat /srv/b.txt)', '/srv/b.txt'],
    ['echo `cat /srv/b.txt`', '/srv/b.txt'],
    ['echo "$(cat /srv/b.txt)"', '/srv/b.txt'],
    ['bash -c "cat /srv/b.txt"', '/srv/b.txt'],
    ["sh -c 'cat /srv/b.txt'", '/srv/b.txt'],
    ['cat $HOME/Documents/a.txt', '/home/agent/Documents/a.txt'],
    ['cat ${HOME}/Documents/a.txt', '/home/agent/Documents/a.txt'],
    ['cat "$HOME/Documents/a.txt"', '/home/agent/Documents/a.txt'],
    [String.raw`type C:\Users\me\a.txt`, String.raw`C:\Users\me\a.txt`],
    ['cat passwords.txt', 'passwords.txt'],
    ['cat -- /srv/-weird', '/srv/-weird'],
  ])('finds the path in %s', (command, expected) => {
    expect(words(command)).toContain(expected);
  });

  it('does not report the program or a flag as a path', () => {
    const found = words('ls -la --color=auto');
    expect(found).not.toContain('ls');
    expect(found).not.toContain('-la');
    expect(found).not.toContain('--color=auto');
    expect(found).toContain('auto');
  });

  it('reports nothing for an empty command', () => {
    expect(words('')).toEqual([]);
    expect(words('   ')).toEqual([]);
  });

  it('does not expand any other variable, and says nothing about it', () => {
    expect(words('cat $DIR/a.txt')).not.toContain('/home/agent/a.txt');
    expect(words('cat "$(echo /srv)/a.txt"')).not.toContain('/srv/a.txt');
  });

  it('survives unbalanced quotes and runaway input', () => {
    expect(() => words('cat "/srv/a.txt')).not.toThrow();
    expect(words('cat "/srv/a.txt')).toContain('/srv/a.txt');
    const huge = `cat ${'a '.repeat(100_000)}/srv/tail.txt`;
    expect(() => words(huge)).not.toThrow();
    expect(words(huge).length).toBeLessThanOrEqual(5000);
    const nested = `sh -c "${'sh -c \\"'.repeat(50)}cat /srv/deep.txt`;
    expect(() => words(nested)).not.toThrow();
  });
});
