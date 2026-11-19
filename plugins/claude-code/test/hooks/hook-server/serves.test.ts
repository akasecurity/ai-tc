import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  credentialHandlesCanBeSupplied,
  hookServerTakesToolCalls,
} from '../../../src/hooks/hook-server/serves.ts';

const CONSENT = { acknowledgedAt: '2026-11-19T00:00:00.000Z', version: VAULT_CONSENT_VERSION };

describe('credentialHandlesCanBeSupplied', () => {
  let bin: string;
  beforeEach(() => {
    bin = mkdtempSync(join(tmpdir(), 'aka-serves-'));
    const perl = join(bin, 'perl');
    writeFileSync(perl, '#!/bin/sh\n');
    chmodSync(perl, 0o755);
  });
  afterEach(() => {
    rmSync(bin, { recursive: true, force: true });
  });

  it('is true when tool calls reach the hook server', () => {
    expect(credentialHandlesCanBeSupplied({}, { PATH: bin })).toBe(true);
  });

  it('is false with the hook server switched off, without perl, or with the local vault on', () => {
    expect(credentialHandlesCanBeSupplied({}, { PATH: bin, AKA_HOOK_SERVER: '0' })).toBe(false);
    expect(credentialHandlesCanBeSupplied({}, { PATH: join(bin, 'empty') })).toBe(false);
    expect(credentialHandlesCanBeSupplied({ vaultConsent: CONSENT }, { PATH: bin })).toBe(false);
    expect(hookServerTakesToolCalls({ vaultConsent: CONSENT })).toBe(false);
  });
});
