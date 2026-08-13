import { describe, expect, it } from 'vitest';

import {
  akaMissing,
  dashboardUrl,
  DEFAULT_PORT,
  INSTALL_HINT,
  parsePort,
  PROBE_FLAG,
  type ProbeSpawn,
  startMessage,
  unsupportedArgvMessage,
} from '../src/dashboard-launch.ts';

describe('dashboard launcher helpers', () => {
  it('parsePort: default, --port <n>, --port=<n>, and unrelated flags', () => {
    expect(parsePort([])).toBe(DEFAULT_PORT);
    expect(parsePort(['--port', '5000'])).toBe('5000');
    expect(parsePort(['--port=6001'])).toBe('6001');
    // A trailing --port with no value falls back to the default rather than undefined.
    expect(parsePort(['--port'])).toBe(DEFAULT_PORT);
    expect(parsePort(['--no-open'])).toBe(DEFAULT_PORT);
  });

  it('dashboardUrl: builds the /security URL for the chosen port', () => {
    expect(dashboardUrl(DEFAULT_PORT)).toBe('http://localhost:4319/security');
    expect(dashboardUrl('5000')).toBe('http://localhost:5000/security');
  });

  it('startMessage: names the URL and the local store', () => {
    const msg = startMessage(dashboardUrl(DEFAULT_PORT));
    expect(msg).toContain('http://localhost:4319/security');
    expect(msg).toContain('~/.aka/data');
  });

  it('install hint: points at the aka CLI when the launcher cannot find it', () => {
    expect(INSTALL_HINT).toContain('@akasecurity/cli');
    expect(INSTALL_HINT).toContain('aka');
  });
  it('unsupportedArgvMessage: explains the refusal without sending the user to reinstall', () => {
    // The two messages answer different questions and must not be confused: the
    // CLI is installed and reachable here, so INSTALL_HINT's advice would point
    // at the one place the problem is not.
    const reason = 'argument 2 contains a percent sign, which cmd.exe expands inside quotes';
    const msg = unsupportedArgvMessage(reason);
    expect(msg).toContain(reason);
    expect(msg).toContain('aka dashboard');
    expect(msg).not.toContain('npm i -g');
    expect(msg).not.toBe(INSTALL_HINT);
  });
});

describe('akaMissing', () => {
  // The launch spawns `plan.file` with `plan.options`; the probe must answer
  // about THAT spawn. Each case therefore states which path the plan took.
  const shellPlan = (resolved: string | undefined) => ({
    viaShell: true as const,
    resolved,
    file: '"aka" "dashboard"',
    options: { shell: true as const, cwd: '/anchor/home' },
  });
  const directPlan = (file: string) => ({
    viaShell: false as const,
    resolved: file,
    file,
    options: { cwd: '/anchor/home' },
  });
  const found: ProbeSpawn = () => ({});
  const enoent: ProbeSpawn = () => ({
    error: Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' }),
  });

  it('through cmd.exe: answers from RESOLUTION, because ENOENT is unreachable there', () => {
    // The interpreter is what gets spawned on that path, so it succeeds whether
    // or not `aka` exists — an ENOENT test could only ever answer "installed".
    const refuse: ProbeSpawn = () => {
      throw new Error('the shell path must not spawn a probe of its own');
    };
    expect(akaMissing(shellPlan(undefined), refuse)).toBe(true);
    expect(akaMissing(shellPlan(String.raw`C:\npm\aka.cmd`), refuse)).toBe(false);
  });

  it('shell-free: answers from the probe spawn, exactly as it always did', () => {
    expect(akaMissing(directPlan('aka'), enoent)).toBe(true);
    expect(akaMissing(directPlan('aka'), found)).toBe(false);
  });

  it('probes the plan’s own file and options, never a bare name of its own', () => {
    // A probe run under different options than the launch is the false
    // miss/false pass this shares a plan to prevent.
    const seen: { file?: string; args?: readonly string[]; options?: unknown } = {};
    const record: ProbeSpawn = (file, probeArgs, options) => {
      seen.file = file;
      seen.args = probeArgs;
      seen.options = options;
      return {};
    };
    const plan = directPlan(String.raw`C:\Program Files\aka\aka.exe`);

    akaMissing(plan, record);

    expect(seen.file).toBe(plan.file);
    expect(seen.args).toEqual([PROBE_FLAG]);
    expect(seen.options).toEqual({ stdio: 'ignore', cwd: '/anchor/home' });
  });
});
