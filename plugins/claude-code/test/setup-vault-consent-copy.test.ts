import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// The wizard's vault-consent step is the disclosure the grant rests on. These
// assertions pin its SUBSTANCE — a copy edit that drops one of these facts
// changes what the user consented to, and must fail loudly here rather than
// ship silently.
const setupMd = readFileSync(
  fileURLToPath(new URL('../commands/setup.md', import.meta.url)),
  'utf8',
);

describe('setup.md vault-consent step', () => {
  it('exists as its own step with the picker contract', () => {
    expect(setupMd).toContain('## 1b. Offer the reversible vault');
    expect(setupMd).toContain('Keep detected secrets recoverable?');
    expect(setupMd).toContain('Vault them');
    expect(setupMd).toContain('No — keep destroying them');
  });

  it('states the custody change: recoverable, encrypted, local', () => {
    expect(setupMd).toContain('encrypted,\n  recoverable copy is kept on this machine');
    expect(setupMd).toContain('AES-256-GCM');
    expect(setupMd).toContain('the vault is entirely local');
  });

  it('names the key directory and the backup exclusion', () => {
    expect(setupMd).toContain('~/.aka/keys');
    expect(setupMd).toMatch(/out of\s+backup and sync tools/);
  });

  it('states the pointer-correlation exposure', () => {
    expect(setupMd).toMatch(/which places share the\s+same secret/);
    expect(setupMd).toMatch(/anyone who can read those artifacts/);
  });

  it('states that revocation is not erasure, and names the purge', () => {
    expect(setupMd).toContain('Revoking stops future vaulting; it erases nothing');
    expect(setupMd).toMatch(/purge[\s\S]{0,120}permanently\s+unresolvable/);
  });

  it('records the grant before the backfill, on both branches', () => {
    expect(setupMd).toContain('--vault-consent grant');
    const record = setupMd.indexOf('--vault-consent grant');
    const backfill = setupMd.indexOf('backfill.js" --triage');
    expect(record).toBeGreaterThan(-1);
    expect(backfill).toBeGreaterThan(record);
    expect(setupMd).toMatch(/on both branches/i);
    // Declining writes nothing — absence is the un-consented state; the wizard
    // must never mint a "declined" marker.
    expect(setupMd).toContain('absence IS the un-consented state');
  });

  it('keeps the reveal-mode risk pointed at its own disclosure surface', () => {
    expect(setupMd).toMatch(/masked badges by default/);
    expect(setupMd).toMatch(/full inline-reveal mode exists in\s+Settings/);
  });
});
