import { describe, expect, it } from 'vitest';
import type { TestModule } from 'vitest/node';

import { UnfinishedModulesReporter } from '../../../../test/vitest/unfinished-modules-reporter.ts';

const mod = (relativeModuleId: string): TestModule =>
  ({ moduleId: `/repo/${relativeModuleId}`, relativeModuleId }) as unknown as TestModule;

function run(drive: (r: UnfinishedModulesReporter) => void): string[] {
  const lines: string[] = [];
  const reporter = new UnfinishedModulesReporter((line) => lines.push(line));
  drive(reporter);
  reporter.onTestRunEnd();
  return lines;
}

describe('UnfinishedModulesReporter', () => {
  it('names a file whose worker died after it started', () => {
    const lines = run((r) => {
      r.onTestModuleStart(mod('test/a.test.ts'));
      r.onTestModuleStart(mod('test/b.test.ts'));
      r.onTestModuleEnd(mod('test/a.test.ts'));
    });
    expect(lines.join('\n')).toContain('test/b.test.ts');
    expect(lines.join('\n')).not.toContain('test/a.test.ts');
  });

  it('prints nothing when every started file finished', () => {
    expect(
      run((r) => {
        r.onTestModuleStart(mod('test/a.test.ts'));
        r.onTestModuleEnd(mod('test/a.test.ts'));
      }),
    ).toEqual([]);
  });
});
