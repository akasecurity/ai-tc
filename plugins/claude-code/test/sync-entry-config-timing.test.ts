// The detached policy-sync child hands the device-command channel a scan whose
// configuration is read when a command RUNS, not when the child spawned.
//
// The runtime's own suite pins that for `commandScanFor`. What it cannot pin is
// this entry's use of it: `const config = loadConfig()` above the call, with
// `() => config` passed in, satisfies every test of the runtime and reads the
// settings at spawn. So this imports the entry itself, with the real
// `commandScanFor` and only the three things around it replaced: the sync run,
// the config loader and the scanner. The entry does its work at module load and
// ends by calling `process.exit`, so `exit` is stubbed and the module registry
// is reset before each import.
import type * as Runtime from '@akasecurity/plugin-runtime';
import type * as Sdk from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from 'vitest';

const mocks = vi.hoisted(() => ({
  runAttachedSync: vi.fn<typeof Runtime.runAttachedSync>(),
  loadConfig: vi.fn<typeof Sdk.loadConfig>(),
  scanWorktree: vi.fn<Runtime.WorktreeScan>(),
}));

vi.mock('@akasecurity/plugin-runtime', async (importActual) => ({
  ...(await importActual<typeof Runtime>()),
  runAttachedSync: mocks.runAttachedSync,
}));
vi.mock('@akasecurity/plugin-sdk', async (importActual) => ({
  ...(await importActual<typeof Sdk>()),
  loadConfig: mocks.loadConfig,
}));
vi.mock('@akasecurity/scanner', () => ({ scanWorktree: mocks.scanWorktree }));

// Identity is all these cases compare, so a marker stands in for a config.
const configA = { marker: 'config-a' } as unknown as Sdk.PluginConfig;
const configB = { marker: 'config-b' } as unknown as Sdk.PluginConfig;

describe('the claude-code sync entry', () => {
  let exit: MockInstance<typeof process.exit>;

  // The first import of the real runtime and SDK is the slow part: it is where
  // their source is transformed, which takes seconds on a busy machine and
  // longer on a slow runner. Paying it here, under a hook timeout sized for
  // that, keeps it out of the first case, whose own timeout is the default and
  // which would otherwise still be importing when the next case began. Only the
  // two real modules are loaded: importing the entry would run it.
  beforeAll(async () => {
    await vi.importActual('@akasecurity/plugin-runtime');
    await vi.importActual('@akasecurity/plugin-sdk');
  }, 120_000);

  beforeEach(() => {
    mocks.runAttachedSync.mockReset().mockResolvedValue(undefined);
    mocks.loadConfig.mockReset();
    mocks.scanWorktree.mockReset().mockResolvedValue({ scanned: 1 });
    exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as typeof process.exit);
    vi.resetModules();
  });

  afterEach(() => {
    exit.mockRestore();
  });

  // The one scan the entry handed `runAttachedSync`.
  async function importEntry(): Promise<Runtime.CommandScan> {
    await import('../src/sync.ts');
    expect(mocks.runAttachedSync).toHaveBeenCalledTimes(1);
    const scan = mocks.runAttachedSync.mock.calls[0]?.[1]?.scan;
    if (scan === undefined) throw new Error('runAttachedSync was not handed a scan');
    return scan;
  }

  it('hands runAttachedSync a scan without loading the configuration, and exits 0', async () => {
    await importEntry();

    expect(mocks.loadConfig).not.toHaveBeenCalled();
    expect(exit).toHaveBeenCalledWith(0);
  });

  it('loads the configuration once per run and scans this tool and directory with it', async () => {
    mocks.loadConfig.mockReturnValue(configA);
    const scan = await importEntry();

    await scan.run();

    expect(mocks.loadConfig).toHaveBeenCalledTimes(1);
    expect(mocks.scanWorktree).toHaveBeenCalledTimes(1);
    const [config, options] = mocks.scanWorktree.mock.calls[0] ?? [];
    expect(config).toBe(configA);
    expect(options).toMatchObject({
      sourceTool: SOURCE_TOOL.ClaudeCode,
      rootDir: process.cwd(),
    });
  });

  it('loads it again on a second run, so the scan sees the settings in force when it runs', async () => {
    mocks.loadConfig.mockReturnValueOnce(configA).mockReturnValueOnce(configB);
    const scan = await importEntry();

    await scan.run();
    await scan.run();

    expect(mocks.loadConfig).toHaveBeenCalledTimes(2);
    expect(mocks.scanWorktree).toHaveBeenCalledTimes(2);
    expect(mocks.scanWorktree.mock.calls[0]?.[0]).toBe(configA);
    expect(mocks.scanWorktree.mock.calls[1]?.[0]).toBe(configB);
  });
});
