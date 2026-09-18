import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The passive update notice runs after a command, when stdout is a TTY. Under
// `__native-host` stdout is Chrome's native-messaging channel, so the notice
// must never be reached there, whatever stdout looks like. Both seams are
// mocked: the notice so nothing touches a real home, and the host so no real
// host script starts reading this process's stdin.
const { notifyFromCache, runNativeHost } = vi.hoisted(() => ({
  notifyFromCache: vi.fn(),
  runNativeHost: vi.fn(() => Promise.resolve()),
}));

vi.mock('@akasecurity/local-ops', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@akasecurity/local-ops')>()),
  notifyFromCache,
}));

vi.mock('../src/commands/extension.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/commands/extension.ts')>()),
  runNativeHost,
}));

const { main } = await import('../src/main.ts');

let isTty: PropertyDescriptor | undefined;
let exitCode: typeof process.exitCode;

beforeEach(() => {
  exitCode = process.exitCode;
  isTty = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
  vi.spyOn(process.stdout, 'write').mockReturnValue(true);
  vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  notifyFromCache.mockClear();
  runNativeHost.mockClear();
});

afterEach(() => {
  if (isTty === undefined) Reflect.deleteProperty(process.stdout, 'isTTY');
  else Object.defineProperty(process.stdout, 'isTTY', isTty);
  vi.restoreAllMocks();
  process.exitCode = exitCode;
});

describe('main — the update notice', () => {
  it('fires after a command outside the skip list when stdout is a TTY', async () => {
    // The positive control: without it, a notice that never fires at all would
    // satisfy the case below. `extension` with an unknown subcommand does
    // nothing but print its usage.
    await main(['extension', 'no-such-subcommand']);

    expect(notifyFromCache).toHaveBeenCalledTimes(1);
  });

  it('never fires after `__native-host`, even with stdout a TTY', async () => {
    await main(['__native-host']);

    expect(runNativeHost).toHaveBeenCalledTimes(1);
    expect(notifyFromCache).not.toHaveBeenCalled();
  });
});
