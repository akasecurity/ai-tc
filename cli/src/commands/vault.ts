import { parseArgs } from 'node:util';

import {
  createKeyProvider,
  dataDir,
  keysDir,
  loadOrCreateFingerprintKey,
  openLocalDatabase,
  readWorkspaceSettings,
  SecretVault,
} from '@akasecurity/persistence';
import type { PointerDescriptor } from '@akasecurity/schema';
import { isVaultConsentValid, PointerToken } from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import type { Prompter } from '../lib/prompter.ts';
import { terminalPrompter } from '../lib/prompter.ts';

const VAULT_HELP = `Reveal a vaulted secret by its pointer (every reveal is audited).

Resolve a pointer:   aka vault show '[[aka:...]]'    prints the raw value

The pointer is the [[aka:...]] token that replaced a detected value. Quote it —
the double brackets are shell syntax otherwise. Each successful reveal writes an
audit row (reason: explicit-reveal) to the local store.

Flags:
  --home <dir>        alternate AKA home (default: ~/.aka)
`;

// The pointer resolved to nothing. The vault deliberately reports every
// failure the same way — a forged or tampered token, a purged entry, and
// unreadable key material are indistinguishable from out here.
const UNAVAILABLE_MESSAGE = `the pointer could not be resolved.
This means one of: the pointer is not one this machine issued (forged or
tampered), its entry was purged from the vault, or the vault key material is
unavailable. The vault does not distinguish these cases — a token nobody can
vouch for resolves to nothing.`;

// One-line badge data for the revealed value, e.g.
// "secret/aws · seen 3× · first 2026-07-27".
function descriptorLine(d: PointerDescriptor): string {
  const kind = d.provider === undefined ? d.category : `${d.category}/${d.provider}`;
  return `${kind} · seen ${String(d.occurrences)}× · first ${d.firstSeen.slice(0, 10)}`;
}

async function runShow(argv: string[], io: Prompter): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    options: { ...HOME_OPTION, help: { type: 'boolean', short: 'h' } },
    allowPositionals: true,
  });
  if (values.help) {
    io.out(VAULT_HELP);
    return;
  }
  const candidate = positionals[0]?.trim();
  if (candidate === undefined || candidate === '') {
    throw new Error(`usage: aka vault show '[[aka:...]]'`);
  }
  // Reject anything that is not pointer-shaped before it reaches the vault.
  const parsed = PointerToken.safeParse(candidate);
  if (!parsed.success) {
    throw new Error(
      'that is not a vault pointer — expected the full [[aka:...]] token (quote it in the shell)',
    );
  }

  const base = homeBase(values.home);
  const dir = dataDir(base);
  const db = openLocalDatabase(dir);
  try {
    const vault = new SecretVault({
      repo: db.secretVault,
      keys: createKeyProvider(readWorkspaceSettings(base).vaultKeyCustody, keysDir(base)),
      fingerprintKey: loadOrCreateFingerprintKey(dir),
      // Read live so a consent revocation applies to the very next call.
      isConsented: () => isVaultConsentValid(readWorkspaceSettings(base).vaultConsent),
    });
    const value = await vault.detokenize(parsed.data, {
      target: 'human',
      reason: 'explicit-reveal',
    });
    if (typeof value !== 'string') {
      throw new Error(UNAVAILABLE_MESSAGE);
    }
    // The raw value on its own line (clean for piping), then the badge line.
    io.out(`${value}\n`);
    const descriptor = await vault.describePointer(parsed.data);
    if (descriptor) io.out(`${descriptorLine(descriptor)}\n`);
  } finally {
    db.close();
  }
}

const VERBS: Record<string, (argv: string[], io: Prompter) => Promise<void>> = {
  show: runShow,
};

/**
 * `aka vault <verb>` — the terminal reveal surface for vault pointers. The io
 * seam is injectable so tests capture output; the default talks to the
 * terminal. Bare/unknown verbs print the help rather than an error.
 */
export async function runVault(argv: string[], io: Prompter = terminalPrompter()): Promise<void> {
  const [verb, ...rest] = argv;
  if (verb === undefined || verb === '-h' || verb === '--help') {
    io.out(VAULT_HELP);
    return;
  }
  const handler = VERBS[verb];
  if (!handler) {
    io.out(VAULT_HELP);
    return;
  }
  await handler(rest, io);
}
