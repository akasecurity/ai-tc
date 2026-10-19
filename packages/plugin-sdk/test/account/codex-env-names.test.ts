import { describe, expect, it } from 'vitest';

import {
  CODEX_ACCOUNT_ENV_NAMES,
  codexEnvVetoed,
  codexHomeDir,
  readCodexAccountEnv,
} from '../../src/account/account-env.ts';

// The test setup clears the Codex variables by name, from CODEX_ACCOUNT_ENV_NAMES.
// That list is kept by hand, so these cases read the environment through a
// recorder and hold it to what the account check reads.

// eslint-disable-next-line n/no-process-env -- a test guard, not product code: it swaps the environment the check reads for a recorder.
const realEnv = process.env;

/** Every variable name `read` asks the environment about, with every variable unset. */
function namesRead(read: () => unknown): string[] {
  const names = new Set<string>();
  const note = (key: string | symbol): void => {
    if (typeof key === 'string') names.add(key);
  };
  // eslint-disable-next-line n/no-process-env -- the recorder stands in for the environment so each lookup is seen.
  process.env = new Proxy<NodeJS.ProcessEnv>(
    {},
    {
      get: (target, key) => {
        note(key);
        return Reflect.get(target, key) as unknown;
      },
      has: (target, key) => {
        note(key);
        return Reflect.has(target, key);
      },
      getOwnPropertyDescriptor: (target, key) => {
        note(key);
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    },
  );
  try {
    read();
  } finally {
    // eslint-disable-next-line n/no-process-env -- puts back the environment the suite started with.
    process.env = realEnv;
  }
  return [...names].sort();
}

describe('the variables the Codex account check reads', () => {
  it('are exactly the ones CODEX_ACCOUNT_ENV_NAMES lists', () => {
    expect(namesRead(readCodexAccountEnv)).toEqual([...CODEX_ACCOUNT_ENV_NAMES].sort());
  });

  it('are the same when the veto and the home are asked for on their own', () => {
    expect(namesRead(() => codexEnvVetoed())).toEqual([...CODEX_ACCOUNT_ENV_NAMES].sort());
    expect(namesRead(() => codexHomeDir())).toEqual([...CODEX_ACCOUNT_ENV_NAMES].sort());
  });
});
