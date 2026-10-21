import { describe, expect, it } from 'vitest';
import type { TestModule, VitestPluginContext } from 'vitest/node';

import {
  UnfinishedModulesReporter,
  unfinishedModulesReporter,
} from '../../../../test/vitest/unfinished-modules-reporter.ts';

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

describe('unfinishedModulesReporter', () => {
  const configure = (reporters: unknown[]): unknown[] => {
    const context = { vitest: { config: { reporters } } } as unknown as VitestPluginContext;
    unfinishedModulesReporter().configureVitest(context);
    return reporters;
  };

  it('appends to the reporters vitest resolved, keeping every one of them', () => {
    const reporters = configure([
      ['default', {}],
      ['github-actions', {}],
    ]);
    expect(reporters.slice(0, 2)).toEqual([
      ['default', {}],
      ['github-actions', {}],
    ]);
    expect(reporters).toHaveLength(3);
    expect(reporters[2]).toBeInstanceOf(UnfinishedModulesReporter);
  });

  it('adds itself once when the hook runs again', () => {
    const reporters = configure([['agent', {}]]);
    unfinishedModulesReporter().configureVitest({
      vitest: { config: { reporters } },
    } as unknown as VitestPluginContext);
    expect(reporters.filter((r) => r instanceof UnfinishedModulesReporter)).toHaveLength(1);
  });
});
