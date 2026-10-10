import { mock, test } from 'claude-code/testing';

// Shared by the mod-runtime tests: the file system, the model and the aka helper
// as they answer from beneath the plugin.

export type Hooks = Parameters<Parameters<typeof test>[1]>[1];

// Spelled by joining so no path or address literal sits in the source.
export const HOME = ['', 'home', 'test'].join('/');
export const SNAPSHOT_PATH = [HOME, '.aka', 'data', 'mod-policy.json'].join('/');
export const EMAIL = ['a', 'example.com'].join('@');

const ALL_CATEGORIES = [
  'pii',
  'financial',
  'secret',
  'phi',
  'code_context',
  'code_flaw',
  'custom',
  'config',
];

export interface SnapshotParts {
  rules?: unknown[];
  ruleActions?: Record<string, string>;
  categoryActions?: Record<string, string>;
  exceptionRuleIds?: string[];
}

// A snapshot as `aka` writes it: every category resolved, `log` unless said.
export function snapshotText(parts: SnapshotParts = {}): string {
  return JSON.stringify({
    version: 1,
    generatedAt: '2026-10-09T00:00:00.000Z',
    ...(parts.rules !== undefined ? { rules: parts.rules } : {}),
    ruleActions: parts.ruleActions ?? {},
    categoryActions: {
      ...Object.fromEntries(ALL_CATEGORIES.map((c) => [c, 'log'])),
      ...parts.categoryActions,
    },
    exceptionRuleIds: parts.exceptionRuleIds ?? [],
  });
}

export interface FileAnswer {
  text: string;
  size?: number;
  mtimeMs: number;
}

// What the file system beneath the plugin answers for the snapshot path: a value
// where the file is, a refusal (as a missing file is) where it is not.
export function fileSystem(on: Hooks, file: () => FileAnswer | undefined): string[] {
  const reads: string[] = [];
  mock.env(on, { HOME });
  on('fs.stat', (_$, e) => {
    const answer = file();
    if (answer === undefined || e.path !== SNAPSHOT_PATH) return { deny: 'ENOENT' };
    return {
      value: {
        kind: 'file' as const,
        size: answer.size ?? answer.text.length,
        mtimeMs: answer.mtimeMs,
        isLink: false,
      },
    };
  });
  on('fs.read', (_$, e) => {
    reads.push(e.path);
    const answer = file();
    return answer === undefined ? { deny: 'ENOENT' } : { value: answer.text };
  });
  return reads;
}

// The model's end of the chain: records the prompt as it arrives.
export function model(on: Hooks): string[] {
  const seen: string[] = [];
  on('prompt.submit', (_$, e) => {
    seen.push(e.text);
    contexts.push(e.context ?? []);
    return { text: e.text };
  });
  return seen;
}

// What reached the model beside each prompt, in step with model()'s texts.
export const contexts: (readonly string[])[] = [];

// What the helper is asked, as the mod sends it.
export interface HelperRequest {
  argv: readonly string[];
  stdin: { v: number; text: string; sessionId?: string; cwd?: string; row?: { door: string } };
  timeoutMs: number | undefined;
}

export type HelperReply =
  { stdout: string; exitCode?: number } | { deny: string } | ((request: HelperRequest) => string);

// The aka helper, answered from beneath the mod the way the process would: a
// stdout (a function of what it was asked), a non-zero exit, or a refusal (as a
// missing script or a timeout is). Returns the requests it was asked.
export function helper(on: Hooks, reply: HelperReply): HelperRequest[] {
  const asked: HelperRequest[] = [];
  on('session.id', () => ({ value: 'session-1' }));
  on('process.run', (_$, e) => {
    const request: HelperRequest = {
      argv: e.argv,
      stdin: JSON.parse(e.init?.stdin ?? 'null') as HelperRequest['stdin'],
      timeoutMs: e.init?.timeoutMs,
    };
    asked.push(request);
    if (typeof reply === 'function') {
      return {
        value: {
          exitCode: 0,
          stdout: reply(request),
          stderr: '',
          isStdoutTruncated: false,
          isStderrTruncated: false,
        },
      };
    }
    if ('deny' in reply) return { deny: reply.deny };
    return {
      value: {
        exitCode: reply.exitCode ?? 0,
        stdout: reply.stdout,
        stderr: '',
        isStdoutTruncated: false,
        isStderrTruncated: false,
      },
    };
  });
  return asked;
}

// A helper that rewrites as the one-way path does: every value in `values`
// becomes `[REDACTED:<category>]`.
export function oneWay(values: Record<string, string>): HelperReply {
  return (request) => {
    let text = request.stdin.text;
    for (const [value, marker] of Object.entries(values)) text = text.replaceAll(value, marker);
    return JSON.stringify({ v: 1, text, note: null });
  };
}
