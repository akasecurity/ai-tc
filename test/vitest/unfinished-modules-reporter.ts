import type { Reporter, TestModule } from 'vitest/node';

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

  constructor(private readonly write: (line: string) => void = (line) => console.error(line)) {}

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
