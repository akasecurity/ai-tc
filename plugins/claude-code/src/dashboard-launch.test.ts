import { describe, expect, it } from 'vitest';

import {
  dashboardUrl,
  DEFAULT_PORT,
  INSTALL_HINT,
  parsePort,
  startMessage,
} from './dashboard-launch.ts';

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
});
