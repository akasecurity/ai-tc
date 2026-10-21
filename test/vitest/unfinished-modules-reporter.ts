import type { Reporter, TestModule, VitestPluginContext } from 'vitest/node';

/**
 * Names every test file that started and never finished.
 *
 * When a test worker process dies mid-file (a V8 abort, a native crash), vitest
 * reports only "Worker exited unexpectedly" and a file count one short, and its
 * default reporter in CI does not list the files that passed, so nothing says
 * which file was running. This reporter tracks starts and ends and prints the
 * difference when the run ends.
 */
export class UnfinishedModulesReporter implements Reporter {
  private readonly running = new Set<string>();

  constructor(
    private readonly write: (line: string) => void = (line) => {
      process.stderr.write(`${line}\n`);
    },
  ) {}

  onTestModuleStart(testModule: TestModule): void {
    this.running.add(testModule.relativeModuleId);
  }

  onTestModuleEnd(testModule: TestModule): void {
    this.running.delete(testModule.relativeModuleId);
  }

  onTestRunEnd(): void {
    if (this.running.size === 0) return;
    this.write('Test files that started and never finished (their worker likely exited):');
    for (const id of [...this.running].sort()) this.write(`  ${id}`);
  }
}

/**
 * Adds {@link UnfinishedModulesReporter} BESIDE the reporters vitest picked,
 * rather than replacing them.
 *
 * A `reporters` list in the config switches off what vitest adds when that list
 * is empty: `github-actions` under `GITHUB_ACTIONS=true`, which turns a failure
 * into a PR annotation, and `agent` in place of `default` under an AI agent.
 * Choosing those here would mean reading the environment from a config file.
 * `configureVitest` runs after vitest has resolved its defaults and before it
 * instantiates them, so appending to the resolved list keeps every one of them.
 * The instance list (`vitest.reporters`) is the wrong target: it is assigned
 * from the resolved list after this hook runs, which discards anything pushed
 * onto it here.
 */
export function unfinishedModulesReporter(): {
  name: string;
  configureVitest: (context: VitestPluginContext) => void;
} {
  return {
    name: 'unfinished-modules-reporter',
    configureVitest({ vitest }) {
      const { reporters } = vitest.config;
      if (reporters.some((r) => r instanceof UnfinishedModulesReporter)) return;
      reporters.push(new UnfinishedModulesReporter());
    },
  };
}
