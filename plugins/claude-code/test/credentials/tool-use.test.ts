import { spawnSync } from 'node:child_process';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CredentialResolver } from '../../src/credentials/session-credentials.ts';
import {
  forgetSessionCredentials,
  hasPendingCalls,
  resolveForSession,
} from '../../src/credentials/session-credentials.ts';
import {
  postToolUseWithCredentials,
  preToolUseWithCredentials,
  scrubbableCommand,
} from '../../src/credentials/tool-use.ts';
import type { HookOutput } from '../../src/hooks/shared.ts';

const GITHUB = 'ghp_demo_value_0123456789abcdef';
const STRIPE = 'sk_test_demo_value_abcdefghij';

afterEach(() => {
  forgetSessionCredentials();
});

const grants: CredentialResolver = (slugs) =>
  Promise.resolve({
    resolved: slugs
      .filter((slug) => slug !== 'denied')
      .map((slug) => ({ slug, value: slug === 'github' ? GITHUB : STRIPE })),
    refused: slugs
      .filter((slug) => slug === 'denied')
      .map((slug) => ({ slug, reason: 'no_grant' as const })),
  });

function payload(toolInput: Record<string, unknown>): Record<string, unknown> {
  return {
    session_id: 'session-1',
    transcript_path: '/nowhere/session-1.jsonl',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: toolInput,
  };
}

async function runPre(
  input: Record<string, unknown>,
  decided: HookOutput | undefined,
  resolve: CredentialResolver = grants,
): Promise<{ emitted: HookOutput[]; scanned: unknown[]; onValuesUsed: ReturnType<typeof vi.fn> }> {
  const emitted: HookOutput[] = [];
  const scanned: unknown[] = [];
  const onValuesUsed = vi.fn();
  await preToolUseWithCredentials(
    input,
    (output) => {
      emitted.push(output);
      return Promise.resolve();
    },
    async (seen, emit) => {
      scanned.push(seen.tool_input);
      if (decided !== undefined) await emit(decided);
    },
    { resolve, onValuesUsed, persistent: true },
  );
  return { emitted, scanned, onValuesUsed };
}

describe('preToolUseWithCredentials', () => {
  it('refuses a call with a handle outside the hook server, resolving nothing', async () => {
    const resolve = vi.fn(grants);
    const emitted: HookOutput[] = [];
    await preToolUseWithCredentials(
      payload({ command: 'x [[aka:cred:github]]' }),
      (output) => {
        emitted.push(output);
        return Promise.resolve();
      },
      () => Promise.resolve(),
      { resolve },
    );
    expect(resolve).not.toHaveBeenCalled();
    expect(emitted).toHaveLength(1);
    expect(emitted[0]).toMatchObject({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny' },
    });
    expect(JSON.stringify(emitted)).toContain('Run the same call again');
  });

  it('records a call it gave a value until its output is seen', async () => {
    await runPre(
      { ...payload({ command: 'x [[aka:cred:github]]' }), tool_use_id: 'toolu_9' },
      undefined,
    );
    expect(hasPendingCalls()).toBe(true);
    await postToolUseWithCredentials(
      { session_id: 'session-1', tool_use_id: 'toolu_9', tool_name: 'Bash', tool_response: 'ok' },
      () => Promise.resolve(),
      () => Promise.resolve(),
    );
    expect(hasPendingCalls()).toBe(false);
  });

  it('passes a call without handles straight through and resolves nothing', async () => {
    const resolve = vi.fn(grants);
    const { emitted } = await runPre(payload({ command: 'ls' }), undefined, resolve);
    expect(emitted).toEqual([]);
    expect(resolve).not.toHaveBeenCalled();
  });

  it('scans the input as written and answers with every handle substituted, nested and repeated', async () => {
    const input = payload({
      command: 'curl -H "Authorization: Bearer [[aka:cred:github]]" https://api.example',
      env: { list: ['STRIPE=[[aka:cred:stripe]]', 'AGAIN=[[aka:cred:github]]'] },
      timeout: 1000,
    });
    const { emitted, scanned, onValuesUsed } = await runPre(input, undefined);

    expect(JSON.stringify(scanned)).not.toContain(GITHUB);
    expect(JSON.stringify(scanned)).toContain('[[aka:cred:github]]');
    expect(emitted).toHaveLength(1);
    const output = emitted[0] as {
      hookSpecificOutput: { updatedInput: unknown; permissionDecision?: string };
      systemMessage: string;
    };
    expect(output.hookSpecificOutput.updatedInput).toEqual({
      command: scrubbableCommand(`curl -H "Authorization: Bearer ${GITHUB}" https://api.example`),
      env: { list: [`STRIPE=${STRIPE}`, `AGAIN=${GITHUB}`] },
      timeout: 1000,
    });
    expect(output.hookSpecificOutput.permissionDecision).toBeUndefined();
    expect(output.systemMessage).toContain('[[aka:cred:github]]');
    expect(output.systemMessage).not.toContain(GITHUB);
    expect(onValuesUsed).toHaveBeenCalledWith('session-1');
  });

  it('leaves a deny alone and asks for no value', async () => {
    const resolve = vi.fn(grants);
    const deny: HookOutput = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: 'blocked',
      },
    };
    const { emitted } = await runPre(payload({ command: 'x [[aka:cred:github]]' }), deny, resolve);
    expect(emitted).toEqual([deny]);
    expect(resolve).not.toHaveBeenCalled();
  });

  it('substitutes into an input the pipeline already rewrote, keeping its decision', async () => {
    const decided: HookOutput = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        updatedInput: { content: '[REDACTED] then [[aka:cred:github]]' },
      },
      systemMessage: 'AKA redacted something.',
    };
    const { emitted } = await runPre(
      payload({ content: 'secret then [[aka:cred:github]]' }),
      decided,
    );
    expect(emitted).toEqual([
      {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'allow',
          updatedInput: { content: `[REDACTED] then ${GITHUB}` },
        },
        systemMessage:
          'AKA redacted something. AKA supplied [[aka:cred:github]] to this Bash call.',
      },
    ]);
  });

  it('keeps a warning and adds the input when the pipeline only warned', async () => {
    const { emitted } = await runPre(payload({ command: 'echo [[aka:cred:github]]' }), {
      systemMessage: 'AKA flagged something.',
    });
    expect(emitted).toEqual([
      {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          updatedInput: { command: scrubbableCommand(`echo ${GITHUB}`) },
        },
        systemMessage: 'AKA flagged something. AKA supplied [[aka:cred:github]] to this Bash call.',
      },
    ]);
  });

  it('fails open on a refusal: the handle stays, the call runs, and the note names no value', async () => {
    const { emitted } = await runPre(
      payload({ command: 'A=[[aka:cred:denied]] B=[[aka:cred:github]]' }),
      undefined,
    );
    const output = emitted[0] as {
      hookSpecificOutput: { updatedInput: unknown };
      systemMessage: string;
    };
    expect(output.hookSpecificOutput.updatedInput).toEqual({
      command: scrubbableCommand(`A=[[aka:cred:denied]] B=${GITHUB}`),
    });
    expect(output.systemMessage).toContain('could not supply [[aka:cred:denied]]');
  });

  it('emits only a note when nothing resolves, and nothing when the machine is not attached', async () => {
    const refused = await runPre(payload({ command: 'x [[aka:cred:denied]]' }), undefined);
    expect(refused.emitted).toEqual([
      {
        systemMessage:
          'AKA could not supply [[aka:cred:denied]] to this Bash call; it runs with the handle as written.',
      },
    ]);
    const offline = await runPre(payload({ command: 'x [[aka:cred:github]]' }), undefined, () =>
      Promise.resolve(undefined),
    );
    expect(offline.emitted).toEqual([
      {
        systemMessage:
          'AKA could not supply [[aka:cred:github]] to this Bash call; it runs with the handle as written.',
      },
    ]);
  });

  it('supplies values only to Bash, leaving the handle in any other tool', async () => {
    const resolve = vi.fn(grants);
    const { emitted } = await runPre(
      { ...payload({ content: 'token [[aka:cred:github]]' }), tool_name: 'Write' },
      undefined,
      resolve,
    );
    expect(emitted).toEqual([
      {
        systemMessage:
          'AKA supplies credentials only to Bash commands, so [[aka:cred:github]] stays as written in this Write call.',
      },
    ]);
    expect(resolve).not.toHaveBeenCalled();
  });

  it('supplies nothing to a call without a session id', async () => {
    const resolve = vi.fn(grants);
    const input = payload({ command: 'x [[aka:cred:github]]' });
    delete input.session_id;
    const { emitted } = await runPre(input, undefined, resolve);
    expect(JSON.stringify(emitted)).not.toContain(GITHUB);
    expect(JSON.stringify(emitted)).toContain('no session id');
    expect(resolve).not.toHaveBeenCalled();
    expect(hasPendingCalls()).toBe(false);
  });

  it('does not supply a value too short to scrub from the output', async () => {
    const short: CredentialResolver = (slugs) =>
      Promise.resolve({ resolved: slugs.map((slug) => ({ slug, value: 'pw12345' })), refused: [] });
    const { emitted } = await runPre(
      payload({ command: 'x [[aka:cred:github]]' }),
      undefined,
      short,
    );
    expect(JSON.stringify(emitted)).not.toContain('pw12345');
    expect(emitted).toEqual([
      {
        systemMessage:
          'AKA did not supply [[aka:cred:github]]: the value is too short to keep out of the output. It runs with the handle as written.',
      },
    ]);
  });

  it('emits what the pipeline decided when resolving throws', async () => {
    const warned: HookOutput = { systemMessage: 'warned' };
    const { emitted } = await runPre(payload({ command: 'x [[aka:cred:github]]' }), warned, () =>
      Promise.reject(new Error('boom')),
    );
    expect(emitted).toEqual([warned]);
  });

  it('still substitutes when the pipeline throws, and rethrows for the fail-open count', async () => {
    const emitted: HookOutput[] = [];
    await expect(
      preToolUseWithCredentials(
        payload({ command: 'x [[aka:cred:github]]' }),
        (output) => {
          emitted.push(output);
          return Promise.resolve();
        },
        () => Promise.reject(new Error('store')),
        { resolve: grants, persistent: true },
      ),
    ).rejects.toThrow('store');
    expect(JSON.stringify(emitted)).toContain(`x ${GITHUB}`);
  });
});

describe('scrubbableCommand', () => {
  const run = (command: string) =>
    spawnSync('sh', ['-c', scrubbableCommand(command)], { encoding: 'utf8' });

  it('keeps the output of a command that succeeds', () => {
    const result = run('echo hi');
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('hi\n');
    expect(result.stderr).toBe('');
  });

  it('reports a failing status in the output and still succeeds', () => {
    const result = run('echo out; echo err >&2; exit 3');
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('out\n');
    expect(result.stderr).toBe('err\n\n(exit code 3)\n');
  });

  it('survives a trailing comment and a heredoc', () => {
    expect(run('echo kept # trailing comment').stdout).toBe('kept\n');
    expect(run('cat <<EOT\nbody\nEOT').stdout).toBe('body\n');
  });
});

describe('postToolUseWithCredentials', () => {
  const post = (response: unknown): Record<string, unknown> => ({
    session_id: 'session-1',
    transcript_path: '/nowhere/session-1.jsonl',
    hook_event_name: 'PostToolUse',
    tool_name: 'Bash',
    tool_input: { command: 'x' },
    tool_response: response,
  });

  async function runPost(
    input: Record<string, unknown>,
    decided?: (seen: Record<string, unknown>) => HookOutput | undefined,
  ): Promise<{ emitted: HookOutput[]; seen: unknown[] }> {
    const emitted: HookOutput[] = [];
    const seen: unknown[] = [];
    await postToolUseWithCredentials(
      input,
      (output) => {
        emitted.push(output);
        return Promise.resolve();
      },
      async (clean, emit) => {
        seen.push(clean.tool_response);
        const output = decided?.(clean);
        if (output !== undefined) await emit(output);
      },
    );
    return { emitted, seen };
  }

  it('passes output through when nothing was injected in the session', async () => {
    const { emitted, seen } = await runPost(post({ stdout: GITHUB, stderr: '' }));
    expect(emitted).toEqual([]);
    expect(seen).toEqual([{ stdout: GITHUB, stderr: '' }]);
  });

  it('replaces an injected value before the scan and answers with the replaced output', async () => {
    await resolveForSession('session-1', ['github'], grants);
    const response = {
      stdout: `> Authorization: Bearer ${GITHUB}\n`,
      stderr: '',
      interrupted: false,
      isImage: false,
    };
    const { emitted, seen } = await runPost(post(response));

    expect(JSON.stringify(seen)).not.toContain(GITHUB);
    expect(emitted).toHaveLength(1);
    const output = emitted[0] as {
      hookSpecificOutput: { hookEventName: string; updatedToolOutput: unknown };
      systemMessage: string;
    };
    expect(output.hookSpecificOutput).toEqual({
      hookEventName: 'PostToolUse',
      updatedToolOutput: {
        stdout: '> Authorization: Bearer [[aka:cred:github]]\n',
        stderr: '',
        interrupted: false,
        isImage: false,
      },
    });
    expect(output.systemMessage).toContain('[[aka:cred:github]]');
    expect(JSON.stringify(emitted)).not.toContain(GITHUB);
  });

  it('keeps the pipeline rewrite, which was made over the replaced output', async () => {
    await resolveForSession('session-1', ['github'], grants);
    const { emitted } = await runPost(post({ stdout: GITHUB, stderr: '' }), (clean) => ({
      hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: clean.tool_response },
      systemMessage: 'withheld',
    }));
    expect(emitted).toEqual([
      {
        hookSpecificOutput: {
          hookEventName: 'PostToolUse',
          updatedToolOutput: { stdout: '[[aka:cred:github]]', stderr: '' },
        },
        systemMessage: 'withheld',
      },
    ]);
  });

  it('still replaces the output when the pipeline throws', async () => {
    await resolveForSession('session-1', ['github'], grants);
    const emitted: HookOutput[] = [];
    await expect(
      postToolUseWithCredentials(
        post({ stdout: GITHUB }),
        (output) => {
          emitted.push(output);
          return Promise.resolve();
        },
        () => Promise.reject(new Error('store')),
      ),
    ).rejects.toThrow('store');
    expect(JSON.stringify(emitted)).toContain('[[aka:cred:github]]');
    expect(JSON.stringify(emitted)).not.toContain(GITHUB);
  });
});
