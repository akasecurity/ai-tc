import { describe, expect, it } from 'vitest';

import { buildReinvocation, isSea, reinvokeArgv } from './self-exec.ts';

describe('buildReinvocation', () => {
  it('plain node: re-runs the entry script, then the subcommand and args', () => {
    expect(
      buildReinvocation(false, '/usr/bin/node', '/pkg/dist/cli.js', '__update-refresh', [
        '--home',
        '/home/.aka',
      ]),
    ).toEqual({
      command: '/usr/bin/node',
      args: ['/pkg/dist/cli.js', '__update-refresh', '--home', '/home/.aka'],
    });
  });

  it('SEA: drops the entry script — the embedded main ignores argv[1]', () => {
    expect(
      buildReinvocation(true, '/opt/aka', '/pkg/dist/cli.js', '__dashboard-server', [
        '--server-js',
        '/opt/web-ui/server.js',
      ]),
    ).toEqual({
      command: '/opt/aka',
      args: ['__dashboard-server', '--server-js', '/opt/web-ui/server.js'],
    });
  });

  it('SEA passes the subcommand as the FIRST arg (never a script path)', () => {
    const r = buildReinvocation(true, '/opt/aka', '/pkg/dist/cli.js', '__update-refresh', []);
    expect(r?.args[0]).toBe('__update-refresh');
  });

  it('plain node with no entry script cannot self-spawn', () => {
    expect(buildReinvocation(false, '/usr/bin/node', undefined, '__update-refresh', [])).toBeNull();
  });
});

describe('isSea / reinvokeArgv under the test runtime', () => {
  it('reports not-a-SEA when run as a normal node process', () => {
    expect(isSea()).toBe(false);
  });

  it('reinvokeArgv includes the entry script under plain node', () => {
    const r = reinvokeArgv('__update-refresh', ['--home', '/tmp/.aka']);
    expect(r).not.toBeNull();
    expect(r?.command).toBe(process.execPath);
    // process.argv[1] (the test runner entry) is present, then our subcommand.
    expect(r?.args.slice(-3)).toEqual(['__update-refresh', '--home', '/tmp/.aka']);
    expect(r?.args.length).toBeGreaterThan(3);
  });
});
