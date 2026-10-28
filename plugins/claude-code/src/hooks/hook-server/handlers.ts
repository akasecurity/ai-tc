// The hooks the server runs, each as the same pipeline its node entry runs with
// the same fail-open handling: an error leaves stdout empty and is counted.
import { chdir } from 'node:process';

import { loadConfig } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid } from '@akasecurity/schema';

import { runPostToolUse } from '../post-tool-use-run.ts';
import { runPreToolUse } from '../pre-tool-use-run.ts';
import type { HookOutput } from '../shared.ts';
import { countFailOpen, parseJson } from '../shared.ts';
import { closingGateways, dropHeldGateway } from '../store-health.ts';
import { applyRequestEnv } from './request-env.ts';
import type { HookHandler } from './server.ts';

/** The standard error text a hook wrote, to the server's log rather than to a terminal nobody reads. */
async function capturingStderr<T>(
  sink: (text: string) => void,
  work: () => Promise<T>,
): Promise<T> {
  const stream = process.stderr;
  const original = stream.write.bind(stream);
  stream.write = (chunk: string | Uint8Array, ...rest: unknown[]): boolean => {
    sink(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    const callback = rest.find((r): r is () => void => typeof r === 'function');
    callback?.();
    return true;
  };
  try {
    return await work();
  } finally {
    stream.write = original;
  }
}

/** Runs `run` with the request's environment and working directory in place. */
async function withRequestState<T>(
  request: { cwd: string | undefined; env: Readonly<Record<string, string>> },
  sink: (text: string) => void,
  run: () => Promise<T>,
): Promise<T> {
  const previousCwd = process.cwd();
  const restoreEnv = applyRequestEnv(request.env);
  try {
    if (request.cwd !== undefined) {
      try {
        chdir(request.cwd);
      } catch {
        // A directory that is gone: the hook falls back to the payload's own cwd.
      }
    }
    return await capturingStderr(sink, () => closingGateways(run));
  } finally {
    restoreEnv();
    try {
      chdir(previousCwd);
    } catch {
      // Nothing to go back to.
    }
  }
}

/** A hook's pipeline, given what the hook read and where it writes. */
type HookRun = (
  input: Record<string, unknown>,
  emit: (output: HookOutput) => Promise<void>,
) => Promise<unknown>;

function handlerFor(run: HookRun, log: (line: string) => void): HookHandler {
  return (request) =>
    withRequestState(request, log, async () => {
      // A machine with the vault turned on keeps the node hook: that path opens
      // the vault's own store handle per call, which this process does not hold.
      try {
        if (isVaultConsentValid(loadConfig().settings.vaultConsent)) return null;
      } catch {
        return null;
      }
      const written: string[] = [];
      const emit = (output: HookOutput): Promise<void> => {
        written.push(JSON.stringify(output));
        return Promise.resolve();
      };
      try {
        const input = parseJson(request.payload);
        if (input) await run(input, emit);
      } catch {
        countFailOpen();
        // Whatever failed may be the store; the next hook opens it afresh.
        await dropHeldGateway();
      }
      return written.join('');
    });
}

export function preToolUseHandler(log: (line: string) => void): HookHandler {
  return handlerFor((input, emit) => runPreToolUse(input, emit, { mode: 'hook' }), log);
}

export function postToolUseHandler(log: (line: string) => void): HookHandler {
  return handlerFor(runPostToolUse, log);
}
