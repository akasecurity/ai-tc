// The Read/Grep path gate is a shell script that decides whether node starts
// at all. A path it drops never reaches the credential-path check, with no
// error and no finding, so the property under test is the one that matters:
// the gate forwards every input `mayNameCredentialFile` would capture.
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { mayNameCredentialFile, pathGateScript } from '../../src/hooks/credential-name-hints.ts';
import { buildCorpus } from '../helpers/leak-corpus.ts';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
const FIXTURES = join(
  REPO_ROOT,
  'rules',
  'command-risk',
  'fixtures',
  'credential-file-access.json',
);

// The gate, with a stand-in `node` first on PATH that echoes the script it was
// asked to run and the stdin it was handed, so a forward is visible as output
// and both can be checked. A shell stand-in keeps each forward at a few ms.
const dir = mkdtempSync(join(tmpdir(), 'aka-path-gate-'));
const gate = join(dir, 'path-gate.sh');
writeFileSync(gate, pathGateScript());
chmodSync(gate, 0o755);
const fakeNode = join(dir, 'node');
writeFileSync(fakeNode, '#!/bin/sh\nprintf "FORWARDED %s\\n" "$1"\ncat\n');
chmodSync(fakeNode, 0o755);
// eslint-disable-next-line n/no-process-env -- the gate needs the host PATH, with the stand-in first
const HOST_ENV = process.env;
const GATE_ENV = { ...HOST_ENV, PATH: `${dir}${delimiter}${HOST_ENV.PATH ?? ''}` };
// The gate joins with '/', which Git Bash on Windows accepts after a backslash path.
const FORWARD_LINE = `FORWARDED ${dir}/pre-tool-use.js\n`;
afterAll(() => {
  removeTree(dir);
});

// Windows runs hooks under Git Bash, whose sh is on PATH rather than at /bin.
const SHELLS =
  process.platform === 'win32'
    ? ['sh']
    : ['/bin/sh', '/bin/dash', '/bin/bash'].filter((shell) => existsSync(shell));

function payload(tool: string, toolInput: Record<string, unknown>, extra = {}): string {
  return JSON.stringify({
    session_id: 'gate-test',
    transcript_path: '/home/agent/.claude/projects/-home-agent-proj/s.jsonl',
    cwd: '/home/agent/proj',
    permission_mode: 'default',
    hook_event_name: 'PreToolUse',
    tool_name: tool,
    tool_input: toolInput,
    ...extra,
  });
}

function runGate(stdin: string, shell = '/bin/sh'): { status: number | null; stdout: string } {
  const run = spawnSync(shell, [gate], { input: stdin, encoding: 'utf8', env: GATE_ENV });
  return { status: run.status, stdout: run.stdout };
}

const forwards = (stdin: string, shell?: string): boolean =>
  runGate(stdin, shell).stdout.startsWith('FORWARDED');

const fixturePaths = (JSON.parse(readFileSync(FIXTURES, 'utf8')) as { text: string }[]).map(
  (f) => f.text,
);
const corpusCalls = buildCorpus().calls.filter((c) => c.tool === 'Read' || c.tool === 'Grep');

const VARIANTS = [
  '/HOME/AGENT/PROJ/.ENV',
  String.raw`C:\Users\agent\.aws\credentials`,
  String.raw`C:\Users\agent\.ssh\ID_ED25519`,
  '/home/agent/.aws/config',
  '/srv/tls/server.KEY',
  '/home/agent/.Bash_Profile',
  '/home/agent/.config/gh/Credentials.json',
];

const ORDINARY = [
  '/home/agent/proj/src/index.ts',
  '/home/agent/proj/README.md',
  '/var/log/system.log',
  String.raw`C:\Users\agent\proj\src\main.go`,
];

describe('the path gate forwards everything the credential-path capture would take', () => {
  it('has at least one shell to run under', () => {
    expect(SHELLS.length).toBeGreaterThan(0);
  });

  it.each(SHELLS)('covers every rule fixture and variant as a Read path, under %s', (shell) => {
    const captured = [...fixturePaths, ...VARIANTS].filter((p) => mayNameCredentialFile(p));
    // The control: the fixtures must hold captured paths for this to say anything.
    expect(captured.length).toBeGreaterThan(20);
    const dropped = captured.filter((p) => !forwards(payload('Read', { file_path: p }), shell));
    expect(dropped, 'captured paths the gate never hands to node').toEqual([]);
  });

  it('covers every captured path as a Grep path', () => {
    const captured = [...fixturePaths, ...VARIANTS].filter((p) => mayNameCredentialFile(p));
    const dropped = captured.filter((p) => !forwards(payload('Grep', { pattern: 'x', path: p })));
    expect(dropped).toEqual([]);
  });

  it('covers every Read and Grep call in the leak corpus that the capture takes', () => {
    const taken = corpusCalls.filter((c) => {
      const path = c.tool === 'Read' ? c.input.file_path : c.input.path;
      return typeof path === 'string' && mayNameCredentialFile(path);
    });
    expect(taken.length).toBeGreaterThan(0);
    const dropped = taken.filter((c) => !forwards(payload(c.tool, c.input))).map((c) => c.id);
    expect(dropped).toEqual([]);
  });

  it('hands the payload on byte for byte, to the pre-tool-use.js beside it', () => {
    const stdin = payload('Read', { file_path: '/home/agent/proj/.env', limit: 20 });
    expect(runGate(stdin).stdout).toBe(`${FORWARD_LINE}${stdin}`);
  });

  it('forwards non-ASCII input and \\u escapes rather than matching their bytes', () => {
    // U+212A KELVIN SIGN lowercases to "k" in JavaScript, so ".\u212Aey" is
    // ".key" to the capture; a byte-wise shell match would miss it.
    expect(mayNameCredentialFile('/srv/tls/server.\u212Aey')).toBe(true);
    expect(forwards(payload('Read', { file_path: '/srv/tls/server.\u212Aey' }))).toBe(true);
    expect(forwards(payload('Read', { file_path: '/home/agent/café/notes.md' }))).toBe(true);
    const escaped = payload('Read', { file_path: '/home/agent/proj/.XNV' }).replace(
      'XNV',
      String.raw`\u0065nv`,
    );
    expect(forwards(escaped)).toBe(true);
  });
});

describe('the path gate keeps node out of the ordinary call', () => {
  it.each(SHELLS)('answers an ordinary Read with nothing and exit 0, under %s', (shell) => {
    for (const p of ORDINARY) {
      expect(mayNameCredentialFile(p)).toBe(false);
      expect(runGate(payload('Read', { file_path: p }), shell)).toEqual({ status: 0, stdout: '' });
    }
  });

  it('answers an ordinary Grep with nothing', () => {
    expect(runGate(payload('Grep', { pattern: 'TODO', path: '/home/agent/proj/src' }))).toEqual({
      status: 0,
      stdout: '',
    });
    expect(runGate(payload('Grep', { pattern: 'TODO' })).stdout).toBe('');
  });

  it('ignores hints in the fields before tool_input', () => {
    // cwd and transcript_path name the project, not the file read; a project
    // directory called "environment" must not send every Read through node.
    const stdin = payload(
      'Read',
      { file_path: '/repo/src/a.ts' },
      {
        cwd: '/srv/environment',
        transcript_path: '/srv/.claude/projects/-srv-environment/s.jsonl',
      },
    );
    expect(runGate(stdin).stdout).toBe('');
  });
});
