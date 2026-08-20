import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import { readWorkspaceSettings } from '@akasecurity/persistence';
import { isAttached } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  attachToControlPlane,
  detachFromControlPlane,
  saveSettings,
} from '../../app/(app)/settings/actions.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// The attach/detach pair, and the input guard in front of all three settings
// actions.
//
// WHAT THESE ACTIONS DO NOT DO is the load-bearing part: attaching writes state
// and dials nothing. This repository makes no network calls, so `endpoint` is a
// descriptor a separate distribution's transport would read — stored, never
// resolved. The vitest no-network guard is loaded for every package here, so an
// accidental connect would fail the run rather than pass quietly.
//
// Same temp-home ritual as the sibling settings suite: the actions resolve
// settings.json from `homedir()` (never process.env), and `next/cache` is
// stubbed because revalidatePath needs a Next render context vitest has not got.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// Lets a case make the STORE WRITE fail without touching the real one. The
// managed-lock branch is otherwise unreachable from a test: applyOnboarding
// decides it against a file at an absolute OS path (/etc/aka, /Library/…) that
// no temp-home redirection can reach.
const writeFailure = vi.hoisted(() => ({ error: null as Error | null }));
vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    applyOnboarding: (...args: Parameters<typeof actual.applyOnboarding>) => {
      if (writeFailure.error) throw writeFailure.error;
      return actual.applyOnboarding(...args);
    },
  };
});

let home: string;

const ENDPOINT = 'https://aka.acme.internal';

function settingsFile(): string {
  return join(home, '.aka', 'settings', 'settings.json');
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-connection-'));
  osHome.dir = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe('attachToControlPlane', () => {
  it('records the mode and the descriptor together', async () => {
    const res = await attachToControlPlane({ endpoint: ENDPOINT, label: 'Acme Prod' });
    expect(res).toEqual({ ok: true });

    const settings = readWorkspaceSettings();
    expect(settings.runMode).toBe('attached');
    expect(settings.controlPlane?.endpoint).toBe(ENDPOINT);
    expect(settings.controlPlane?.label).toBe('Acme Prod');
    // Both halves, or the machine is not attached — a mode with no descriptor
    // would show a connection that does not exist.
    expect(isAttached(settings)).toBe(true);
  });

  it('stamps attachedAt server-side rather than taking one from the caller', async () => {
    const before = Date.now();
    await attachToControlPlane({
      endpoint: ENDPOINT,
      // A caller-supplied timestamp has no path in: the input schema carries no
      // such field, and an extra key is stripped rather than trusted.
      attachedAt: '2001-01-01T00:00:00.000Z',
    });
    const stamped = readWorkspaceSettings().controlPlane?.attachedAt;
    expect(stamped).toBeDefined();
    expect(Date.parse(stamped ?? '')).toBeGreaterThanOrEqual(before);
  });

  it('omits the label rather than storing an empty one', async () => {
    await attachToControlPlane({ endpoint: ENDPOINT, label: '   ' });
    expect(readWorkspaceSettings().controlPlane).not.toHaveProperty('label');
  });

  it('refuses an empty endpoint, writing nothing', async () => {
    const res = await attachToControlPlane({ endpoint: '   ' });
    expect(res.ok).toBe(false);
    // A descriptor isAttached would accept and no transport could ever use is
    // worse than no attachment at all.
    expect(existsSync(settingsFile())).toBe(false);
  });

  it('does not resolve or normalise the endpoint it was given', async () => {
    // This tree has no opinion about what a valid endpoint looks like, and a URL
    // check here would imply it does. Stored verbatim.
    const odd = 'not-a-url-at-all';
    await attachToControlPlane({ endpoint: odd });
    expect(readWorkspaceSettings().controlPlane?.endpoint).toBe(odd);
  });
});

describe('detachFromControlPlane', () => {
  it('clears the mode AND the descriptor', async () => {
    await attachToControlPlane({ endpoint: ENDPOINT });
    const res = await detachFromControlPlane();
    expect(res).toEqual({ ok: true });

    const settings = readWorkspaceSettings();
    expect(settings.runMode).toBe('standalone');
    // The descriptor goes too. Leaving it behind would let a later hand edit of
    // runMode alone silently re-attach to a deployment the user had left.
    expect(settings.controlPlane).toBeUndefined();
    expect(isAttached(settings)).toBe(false);
  });

  it('is idempotent on a machine that was never attached', async () => {
    const res = await detachFromControlPlane();
    expect(res).toEqual({ ok: true });
    expect(isAttached(readWorkspaceSettings())).toBe(false);
  });

  it('leaves unrelated settings alone', async () => {
    await saveSettings({
      historicalAccess: 'full',
      modelJudgeConsent: false,
      vaultConsent: 'off',
      vaultInlineReveal: 'off',
    });
    await attachToControlPlane({ endpoint: ENDPOINT });
    await detachFromControlPlane();

    const settings = readWorkspaceSettings();
    expect(settings.historicalAccess).toBe('full');
    expect(settings.vaultInlineReveal).toBe('off');
  });
});

// A Server Action's parameter types are a claim its runtime never checks: the
// arguments arrive as JSON over an HTTP POST. A payload that is not an object
// throws on the first field read, and a THROWN Server Action rejects — the
// browser gets a framework error page instead of the recoverable result these
// were written to return.
// The failure branches. These were unreachable from a test until the refusal
// WORDING moved out of the 'use server' module — the managed branch needs a file
// at an absolute OS path no test can redirect — so the store call is faked here
// and the wording is asserted where it now lives (action-refusals.test.ts).
describe('write failures are reported, never thrown', () => {
  it('reports an administrative lock as a refusal rather than a fault', async () => {
    const { ManagedFieldError } = await import('@akasecurity/persistence');
    writeFailure.error = new ManagedFieldError(['runMode']);
    try {
      const res = await detachFromControlPlane();
      expect(res.ok).toBe(false);
      // Names the locked field and attributes the decision — a retry cannot help.
      expect(res.error).toContain('runMode');
      expect(res.error).toMatch(/organization/i);
      expect(res.error).not.toMatch(/try again/i);
    } finally {
      writeFailure.error = null;
    }
  });

  it('reports a store fault as a fault, distinctly', async () => {
    writeFailure.error = new Error('disk on fire');
    try {
      const res = await saveSettings({
        historicalAccess: 'full',
        modelJudgeConsent: false,
        vaultConsent: 'off',
        vaultInlineReveal: 'masked',
      });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('settings.json');
      // And it must not borrow the administrative wording — different cause,
      // different remedy.
      expect(res.error).not.toMatch(/organization/i);
      // Nor echo whatever the store threw.
      expect(res.error).not.toContain('disk on fire');
    } finally {
      writeFailure.error = null;
    }
  });

  it('reports a lock on ATTACH the same way', async () => {
    const { ManagedFieldError } = await import('@akasecurity/persistence');
    writeFailure.error = new ManagedFieldError(['runMode']);
    try {
      const res = await attachToControlPlane({ endpoint: ENDPOINT });
      expect(res.ok).toBe(false);
      expect(res.error).toMatch(/organization/i);
    } finally {
      writeFailure.error = null;
    }
  });
});

describe('untyped wire input', () => {
  const HOSTILE: [string, unknown][] = [
    ['null', null],
    ['undefined', undefined],
    ['a number', 42],
    ['a string', 'not an object'],
    ['an array', []],
    ['a boolean', true],
    [
      'an object with a throwing toString',
      {
        toString: () => {
          throw new Error('boom');
        },
      },
    ],
  ];

  describe('saveSettings', () => {
    it.each(HOSTILE)('refuses %s without throwing', async (_name, payload) => {
      const res = await saveSettings(payload);
      expect(res.ok).toBe(false);
      expect(res.error).toBeDefined();
      expect(existsSync(settingsFile())).toBe(false);
    });

    it('refuses a wrong-typed field and names the SCHEMA key', async () => {
      const res = await saveSettings({
        historicalAccess: 12345,
        modelJudgeConsent: false,
        vaultConsent: 'off',
        vaultInlineReveal: 'masked',
      });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('historicalAccess');
    });

    it('refuses a MISSING modelJudgeConsent instead of reading it as a revocation', async () => {
      // It was optional, and an absent field was treated as false — so any
      // caller that simply did not mention it silently revoked a live egress
      // grant. Required is the fix, and this is what pins it.
      const res = await saveSettings({
        historicalAccess: 'session-only',
        vaultConsent: 'off',
        vaultInlineReveal: 'masked',
      });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('modelJudgeConsent');
    });

    it('still accepts a well-formed payload', async () => {
      // The positive control. Without it, an action rewritten to refuse
      // everything satisfies every case above.
      const res = await saveSettings({
        historicalAccess: 'full',
        modelJudgeConsent: false,
        vaultConsent: 'off',
        vaultInlineReveal: 'masked',
      });
      expect(res).toEqual({ ok: true });
      expect(readWorkspaceSettings().historicalAccess).toBe('full');
    });
  });

  describe('attachToControlPlane', () => {
    it.each(HOSTILE)('refuses %s without throwing', async (_name, payload) => {
      const res = await attachToControlPlane(payload);
      expect(res.ok).toBe(false);
      expect(res.error).toBeDefined();
      expect(existsSync(settingsFile())).toBe(false);
    });

    it('refuses a non-string endpoint and names the field', async () => {
      const res = await attachToControlPlane({ endpoint: { toString: () => ENDPOINT } });
      expect(res.ok).toBe(false);
      expect(res.error).toContain('endpoint');
    });

    it('echoes no part of the value it refused', async () => {
      // A refusal names the schema's key. It must not carry anything derived
      // from the payload — a settings field can hold whatever the user typed.
      const secretish = 'Zk7QvR2mNbXt4LpW9sHyEc3JdFgA6uTi';
      const res = await attachToControlPlane({ endpoint: 1, label: secretish });
      expect(res.ok).toBe(false);
      expect(res.error).toBeDefined();
      expectNoEchoOf(res.error, secretish);
    });
  });
});
