// The vault glue over the local SQLite vault under the data directory, and
// the free functions that run over one shared instance of it. The glue itself
// lives in `vault-glue.ts`, which opens no store.
import { dirname } from 'node:path';

import type { MatchResult } from '@akasecurity/detections';
import type {
  ExceptionPolicyProvider,
  FingerprintKey,
  LocalDatabase,
} from '@akasecurity/persistence';
import {
  createKeyProvider,
  defaultDataDir,
  keysDir,
  loadOrCreateFingerprintKey,
  openLocalDatabase,
  readWorkspaceSettings,
  SecretVault,
  UserGrantPolicyProvider,
} from '@akasecurity/persistence';
import type { PointerDescriptor, WorkspaceSettings } from '@akasecurity/schema';
import { isVaultConsentValid } from '@akasecurity/schema';

import { dataDir } from './data-dir.ts';
import type { PolicyResolver } from './policy-resolver.ts';
import { shippedRegexMatchers } from './rule-packs.ts';
import type {
  DetokenizeTextOptions,
  DetokenizeTextResult,
  ModelDerefGrantResolver,
  SubstitutePointersResult,
  TokenizeTextResult,
  TokenizeValueMeta,
  VaultCore,
  VaultGlue,
} from './vault-glue.ts';
import { createInjectedVaultGlue, SecretVaultGlue } from './vault-glue.ts';

export interface CreateVaultGlueOptions {
  // The ~/.aka base; defaults to the shared layout root.
  base?: string;
  // Test seam: a vault core to use instead of opening the real store.
  vault?: VaultCore;
  // An open store to use instead of opening one. The glue never closes it.
  db?: LocalDatabase;
  // Test seam: a reveal-grant resolver to pair with an injected vault.
  revealResolver?: ModelDerefGrantResolver;
  // The reveal decision seam. Defaults to the user-driven provider (the grant
  // the user created is the decision); a different provider changes WHO
  // decides without touching any crossing site.
  policyProvider?: ExceptionPolicyProvider;
}

/**
 * Build the glue over a live vault. Opening the store or the key provider can
 * fail; when either does, the returned glue is a degraded one whose tokenize
 * destroys values one-way and whose detokenize resolves nothing — the never-throw
 * and never-leak postures `vault-glue.ts` describes, decided once at construction.
 *
 * The fingerprint key is NOT resolved here, so it cannot fail here: it is
 * needed only to write, and is loaded on the first write instead. A fault
 * there lands in `tokenizeValue`'s catch and degrades that value one-way,
 * which is the same posture on a narrower blast radius — the reads this glue
 * also serves keep working.
 */
export function createVaultGlue(options?: CreateVaultGlueOptions): VaultGlue {
  if (options?.vault) {
    return createInjectedVaultGlue(options.vault, { revealResolver: options.revealResolver });
  }
  const base = options?.base ?? defaultDataDir();
  try {
    const dir = dataDir(base);
    const db =
      options?.db ?? openLocalDatabase(dir, { shippedRegexMatchers: shippedRegexMatchers() });
    const owned = options?.db === undefined;
    const settings = readWorkspaceSettings(base);
    // Resolved before the vault so the grant verifier below can close over it.
    // An injected provider replaces the user-grant one wholesale, and the vault
    // must ask the SAME decider the resolver asks — a vault consulting the local
    // exceptions table directly would veto a crossing an injected provider had
    // just authorized.
    const provider = options?.policyProvider ?? new UserGrantPolicyProvider(db.exceptions);
    const vault = new SecretVault({
      repo: db.secretVault,
      keys: createKeyProvider(settings.vaultKeyCustody, keysDir(base)),
      // Read live so a revocation applies to the very next call, not the next
      // process.
      isConsented: () => isVaultConsentValid(readWorkspaceSettings(base).vaultConsent),
      // This is the one construction site that reveals to the model, so it is
      // the one that supplies the last gate. The decision is re-taken from the
      // ROW's identity at the moment of crossing, which closes the window
      // between resolving a grant and spending it: a grant revoked in between
      // refuses here.
      //
      // The re-decision is on the identity alone, never on the grant id
      // matching the one the resolver returned. ExceptionPolicyProvider
      // promises no id stability across calls — a provider deciding from
      // external policy may well mint a fresh id each time — so comparing ids
      // would silently refuse every crossing for such a provider while looking
      // like a security check. `allow` for this row is the whole question.
      verifyGrant: async (_grantId, identity) => {
        const decision = await provider.decideReveal(identity);
        return decision.allow;
      },
    });
    // Resolved on the first WRITE that gets past the consent gate, never at
    // construction: this glue also backs render and reveal, and a session that
    // only reads must leave the store's key footprint alone. Memoized because
    // one message can tokenize many findings, and the load re-reads the file
    // and re-tightens its mode each time.
    let fingerprintKey: FingerprintKey | undefined;
    const fingerprintKeyForWrite = (): FingerprintKey =>
      (fingerprintKey ??= loadOrCreateFingerprintKey(dir));

    // The vault core plus the sighting recorder: SecretVault owns crypto and
    // audit; where a pointer LANDED is repository bookkeeping, wired in here so
    // the glue's callers never touch the store directly.
    const vaultWithSightings: VaultCore = {
      tokenize: (raw, meta) => vault.tokenize(raw, meta, fingerprintKeyForWrite),
      detokenize: (token, opts) => vault.detokenize(token, opts),
      describePointer: (token) => vault.describePointer(token),
      resolvePointerIdentity: (token) => vault.resolvePointerIdentity(token),
      recordSighting: (pointerId, sighting) => {
        db.secretVault.recordSighting({ pointerId, ...sighting }, Date.now());
      },
      consumeGrant: (grantId) => db.exceptions.consume(grantId),
    };
    // The resolver is a thin adapter over the decision seam: pointer →
    // raw-free identity → provider decision. Anything failing along the way is
    // a refusal, never a reveal.
    const revealGrantResolver: ModelDerefGrantResolver = async (pointer) => {
      try {
        const identity = await vault.resolvePointerIdentity(pointer);
        if (identity === null) return null;
        const decision = await provider.decideReveal(identity);
        return decision.allow ? decision.grantId : null;
      } catch {
        return null;
      }
    };
    return new SecretVaultGlue(
      vaultWithSightings,
      revealGrantResolver,
      owned
        ? () => {
            db.close();
          }
        : undefined,
    );
  } catch {
    return new SecretVaultGlue(UNOPENABLE_VAULT);
  }
}

/**
 * The glue a whole-file scan vaults through, over the home `config` names, or
 * undefined without vault consent — the scan then vaults nothing. `db`, when
 * given, is the open store to vault into. The caller closes the glue.
 */
export function openScanVault(
  config: { settings: WorkspaceSettings; dataDir: string },
  db?: LocalDatabase,
): VaultGlue | undefined {
  try {
    if (!isVaultConsentValid(config.settings.vaultConsent)) return undefined;
    return createVaultGlue({ base: dirname(config.dataDir), ...(db === undefined ? {} : { db }) });
  } catch {
    return undefined;
  }
}

// The vault stand-in when the store cannot be opened at all: consent-shaped
// refusal on write (callers degrade one-way), unavailable on read.
const UNOPENABLE_VAULT: VaultCore = {
  tokenize: () => Promise.resolve(Symbol('aka.vault.unopenable')),
  detokenize: () => Promise.resolve(Symbol('aka.vault.unopenable')),
  describePointer: () => Promise.resolve(null),
  resolvePointerIdentity: () => Promise.resolve(null),
};

// The default glue the hooks use, built once per process against the shared
// ~/.aka. Hook processes are short-lived and hard-exit, so the handle is never
// explicitly closed.
let defaultGlue: VaultGlue | null = null;

function glue(): VaultGlue {
  defaultGlue ??= createVaultGlue();
  return defaultGlue;
}

/** {@link VaultGlue.tokenizeText} over the default ~/.aka vault. */
export function tokenizeText(
  text: string,
  opts?: {
    findings?: MatchResult[];
    reversible?: ReadonlySet<MatchResult>;
    resolver?: PolicyResolver;
  },
): Promise<TokenizeTextResult> {
  return glue().tokenizeText(text, opts);
}

/** {@link VaultGlue.tokenizeValue} over the default ~/.aka vault. */
export function tokenizeValue(raw: string, meta: TokenizeValueMeta): Promise<string> {
  return glue().tokenizeValue(raw, meta);
}

/** {@link VaultGlue.detokenizeText} over the default ~/.aka vault. */
export function detokenizeText(
  text: string,
  opts: DetokenizeTextOptions,
): Promise<DetokenizeTextResult> {
  return glue().detokenizeText(text, opts);
}

/** {@link VaultGlue.describePointerSafe} over the default ~/.aka vault. */
export function describePointerSafe(token: string): Promise<PointerDescriptor | null> {
  return glue().describePointerSafe(token);
}

/** {@link VaultGlue.substituteModelPointers} over the default ~/.aka vault. */
export function substituteModelPointers(
  text: string,
  opts: { resolveGrant: ModelDerefGrantResolver },
): Promise<SubstitutePointersResult> {
  return glue().substituteModelPointers(text, opts);
}
