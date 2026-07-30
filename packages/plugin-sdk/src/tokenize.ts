// Text-level glue between the hooks and the reversible vault: replace detected
// secret spans with pointers, and resolve pointers back for whoever is allowed
// to see them.
//
// Everything here sits on a hook path, so the whole surface is built around two
// rules the vault core shares:
//
//   never throw   a caller on the fail-open boundary must not be broken by a
//                 vault fault. Every public function catches everything.
//   never leak    a fault while masking must destroy the value, not pass it.
//                 A span we cannot tokenize is rewritten to the same one-way
//                 `[REDACTED:CATEGORY]` placeholder the engine emits, and a
//                 pointer we cannot resolve renders as `[unavailable]`.
//
// The two rules compose to: on any failure the session continues and the model
// sees LESS, never more.
import type { MatchResult } from '@akasecurity/detections';
import { getLoadedRules, maskMatch, scan } from '@akasecurity/detections';
import type { ExceptionPolicyProvider } from '@akasecurity/persistence';
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
import type {
  DetectionCategory,
  PointerDescriptor,
  PointerToken,
  VaultDerefReason,
  VaultSightingKind,
} from '@akasecurity/schema';
import { isVaultConsentValid, pointerTokenScanner } from '@akasecurity/schema';

import { dataDir } from './data-dir.ts';
import { dropShieldedFindings, shieldPointers } from './pointer-shield.ts';
import { registerBundledPacks } from './rule-packs.ts';

// The one-way placeholder for a span that could not (or must not) be vaulted —
// identical to the engine's redact() form so a degraded field is
// indistinguishable from a pre-vault one.
function redactedPlaceholder(category: string): string {
  return `[REDACTED:${category.toUpperCase()}]`;
}

// What an unresolvable pointer renders as on a human surface.
export const POINTER_UNAVAILABLE_TEXT = '[unavailable]';

export interface TokenizeTextResult {
  text: string;
  // The pointers now present in `text` that this call minted or re-emitted.
  pointers: PointerToken[];
  // Spans that were destroyed one-way instead of vaulted (overlap groups, stale
  // spans, vault faults, consent absent) — the truthful record a caller needs
  // before telling anyone a value is recoverable.
  degraded: { category: string }[];
}

// Human-target only, and deliberately so. This entry applies ONE option set to
// every pointer in a text, which no per-value grant can authorize — a single
// grant covers a single value, not whatever else happens to share the string.
// Model crossings go through substituteModelPointers, which decides pointer by
// pointer and spends a grant per crossing.
export interface DetokenizeTextOptions {
  target: 'human';
  reason: VaultDerefReason;
}

export interface DetokenizeTextResult {
  text: string;
  // Pointer occurrences replaced with their raw value.
  revealed: number;
}

// The slice of the vault core the glue calls. Narrow on purpose: tests inject a
// stub here to exercise the degrade branches without a real store.
export interface VaultCore {
  tokenize(
    raw: string,
    meta: { ruleId: string; category: DetectionCategory; maskedMatch: string },
  ): Promise<string | symbol>;
  detokenize(
    token: string,
    opts: {
      target: 'human' | 'model';
      reason: VaultDerefReason;
      grantId?: string | undefined;
      pointerCount?: number | undefined;
    },
  ): Promise<string | symbol>;
  describePointer(token: string): Promise<PointerDescriptor | null>;
  resolvePointerIdentity(token: string): Promise<{
    ruleId: string;
    valueFingerprint: string;
    fingerprintKeyVersion: number;
  } | null>;
  recordSighting?(pointerId: string, sighting: { location: string; kind: VaultSightingKind }): void;
  // Claim one use of a reveal grant. Called once per grant per crossing, AFTER
  // a successful de-reference — a refusal must never spend the budget.
  consumeGrant?(grantId: string): Promise<boolean>;
}

// Resolves whether a model-echoed pointer may be de-referenced back to raw for
// the model: a grant id when an active reveal grant covers the value, null
// otherwise. The default resolver always returns null, so no model de-ref ever
// happens until a real resolver is wired in.
export type ModelDerefGrantResolver = (pointer: PointerToken) => Promise<string | null>;

export interface SubstitutePointersResult {
  text: string;
  // Pointers replaced by their raw value under a grant.
  revealed: PointerToken[];
  // Pointers left literal: no grant, or the vault refused/could not resolve.
  unresolved: PointerToken[];
  // The grant ids that authorized the reveals — the caller threads these into
  // the detection scan so the same crossing's suppression does not spend a
  // second use.
  grantIds: string[];
}

export interface ProbePointersResult {
  // Distinct pointers an active grant covers, with the covering grant id.
  granted: Map<PointerToken, string>;
  // Distinct pointers no grant covers.
  ungranted: PointerToken[];
}

export interface TokenizeSighting {
  location: string;
  kind: VaultSightingKind;
}

export interface VaultGlue {
  tokenizeText(
    text: string,
    opts?: { findings?: MatchResult[]; sighting?: TokenizeSighting },
  ): Promise<TokenizeTextResult>;
  tokenizeValue(
    raw: string,
    meta: { ruleId: string; category: DetectionCategory; maskedMatch: string },
  ): Promise<string>;
  detokenizeText(text: string, opts: DetokenizeTextOptions): Promise<DetokenizeTextResult>;
  describePointerSafe(token: string): Promise<PointerDescriptor | null>;
  // Grant resolution only — no de-reference, no audit rows. The executable-field
  // deny path uses this so a mixed field never audits a 'revealed' crossing for
  // a call that is then blocked.
  probeModelPointers(
    text: string,
    opts: { resolveGrant: ModelDerefGrantResolver },
  ): Promise<ProbePointersResult>;
  substituteModelPointers(
    text: string,
    opts: { resolveGrant: ModelDerefGrantResolver },
  ): Promise<SubstitutePointersResult>;
  // The live reveal-grant lookup for this store: a grant id when an active
  // reveal-to-model exception covers the pointer's value, null otherwise.
  // Always null on a degraded glue. Resolution never spends the grant — the
  // crossing itself consumes, once per grant, after a successful de-reference,
  // whatever enforcement mode the covered rule runs under.
  revealGrantResolver: ModelDerefGrantResolver;
  /**
   * Release the store handle this glue opened. Idempotent, and a no-op on a
   * glue that opened nothing — a degraded one, or one built over an injected
   * vault.
   *
   * Hook processes need not call it: they exit, and exiting releases the
   * handle. Anything that OUTLIVES its glue must — a long-lived process leaks a
   * connection otherwise, and on Windows an open handle blocks removal of the
   * directory holding the store.
   */
  close(): void;
}

const SEVERITY_RANK: Record<string, number> = { critical: 3, high: 2, medium: 1, low: 0 };

// Disjoint replacement units over the findings of one text. Overlapping spans
// cannot each map to one vaulted value — the shared characters belong to both —
// so an overlapping group degrades to the one-way placeholder of its
// highest-severity member. Only truly disjoint spans tokenize.
interface SpanGroup {
  start: number;
  end: number;
  // Present when the group is a single finding whose span text matches its
  // rawMatch exactly; absent means one-way redaction.
  finding?: MatchResult;
  // The category of the group's highest-severity member — what the one-way
  // placeholder names when per-finding identity is lost.
  category: string;
  severity: string;
}

function groupSpans(text: string, findings: MatchResult[]): SpanGroup[] {
  const sorted = [...findings]
    .filter((f) => f.span.start >= 0 && f.span.end <= text.length && f.span.start < f.span.end)
    .sort((a, b) => a.span.start - b.span.start || b.span.end - a.span.end);

  const groups: SpanGroup[] = [];
  for (const finding of sorted) {
    const last = groups[groups.length - 1];
    if (last && finding.span.start < last.end) {
      // Overlap: widen the group and drop per-finding identity.
      last.end = Math.max(last.end, finding.span.end);
      if ((SEVERITY_RANK[finding.severity] ?? 0) > (SEVERITY_RANK[last.severity] ?? 0)) {
        last.category = finding.category;
        last.severity = finding.severity;
      }
      delete last.finding;
      continue;
    }
    groups.push({
      start: finding.span.start,
      end: finding.span.end,
      finding,
      category: finding.category,
      severity: finding.severity,
    });
  }
  return groups;
}

const NULL_RESOLVER: ModelDerefGrantResolver = () => Promise.resolve(null);

class SecretVaultGlue implements VaultGlue {
  readonly #vault: VaultCore;
  readonly revealGrantResolver: ModelDerefGrantResolver;
  // Set only when THIS glue opened the store, so a glue over an injected vault
  // never closes a handle it does not own.
  #release: (() => void) | undefined;

  constructor(
    vault: VaultCore,
    revealGrantResolver: ModelDerefGrantResolver = NULL_RESOLVER,
    release?: () => void,
  ) {
    this.#vault = vault;
    this.revealGrantResolver = revealGrantResolver;
    this.#release = release;
  }

  close(): void {
    const release = this.#release;
    // Cleared before the call so a second close is a no-op even if the first
    // throws — and a throw here is swallowed: releasing a handle is cleanup,
    // never a reason to fail the caller.
    this.#release = undefined;
    try {
      release?.();
    } catch {
      // Already unusable; nothing left to do.
    }
  }

  async tokenizeValue(
    raw: string,
    meta: { ruleId: string; category: DetectionCategory; maskedMatch: string },
  ): Promise<string> {
    try {
      const result = await this.#vault.tokenize(raw, meta);
      // Any sentinel (consent absent, or a future one) degrades one-way.
      return typeof result === 'string' ? result : redactedPlaceholder(meta.category);
    } catch {
      return redactedPlaceholder(meta.category);
    }
  }

  async tokenizeText(
    text: string,
    opts?: { findings?: MatchResult[]; sighting?: TokenizeSighting },
  ): Promise<TokenizeTextResult> {
    try {
      const findings = opts?.findings ?? this.#selfScan(text);
      // A self-scan that failed outright cannot tell secret from clean; the
      // only safe output is the blanket the mask path also emits.
      if (findings === null) return { text: '[REDACTED]', pointers: [], degraded: [] };
      if (findings.length === 0) return { text, pointers: [], degraded: [] };

      const groups = groupSpans(text, findings);
      const pointers: PointerToken[] = [];
      const degraded: { category: string }[] = [];
      let out = text;
      // Back to front, so earlier offsets stay valid as later spans change width.
      for (const group of [...groups].reverse()) {
        const original = text.slice(group.start, group.end);
        const finding = group.finding;
        let replacement: string;
        if (finding === undefined) {
          // An overlap group: per-finding identity is gone, destroy the region.
          replacement = redactedPlaceholder(group.category);
          degraded.unshift({ category: group.category });
        } else if (original !== finding.rawMatch) {
          // A span that no longer slices to its finding's rawMatch is stale;
          // vaulting the sliced text would store something detection never saw.
          replacement = redactedPlaceholder(group.category);
          degraded.unshift({ category: group.category });
        } else {
          replacement = await this.tokenizeValue(finding.rawMatch, {
            ruleId: finding.ruleId,
            category: finding.category,
            maskedMatch: maskMatch(finding.rawMatch),
          });
          if (replacement.startsWith('[[aka:')) pointers.unshift(replacement);
          else degraded.unshift({ category: finding.category });
        }
        out = out.slice(0, group.start) + replacement + out.slice(group.end);
      }
      // Where these pointers just landed — the ledger that makes pointer
      // correlation visible to the owner. Best-effort: a bookkeeping fault
      // never affects the rewrite.
      if (opts?.sighting && pointers.length > 0) {
        for (const pointer of pointers) {
          try {
            const id = pointer.split('.')[1];
            if (id !== undefined) this.#vault.recordSighting?.(id, opts.sighting);
          } catch {
            // best-effort only
          }
        }
      }
      return { text: out, pointers, degraded };
    } catch {
      // The unknown failure could have left raw spans in place; destroy them.
      return { text: '[REDACTED]', pointers: [], degraded: [] };
    }
  }

  async detokenizeText(text: string, opts: DetokenizeTextOptions): Promise<DetokenizeTextResult> {
    try {
      const matches = [...text.matchAll(pointerTokenScanner())];
      if (matches.length === 0) return { text, revealed: 0 };

      // Resolve each DISTINCT pointer once: one audit row per distinct pointer,
      // carrying how many times it occurs in this text.
      const occurrences = new Map<string, number>();
      for (const match of matches) {
        occurrences.set(match[0], (occurrences.get(match[0]) ?? 0) + 1);
      }
      const resolved = new Map<string, string | null>();
      for (const [pointer, count] of occurrences) {
        try {
          // Pinned rather than forwarded from opts, so a caller reaching past
          // the type still cannot turn this into a model crossing.
          const value = await this.#vault.detokenize(pointer, {
            target: 'human',
            reason: opts.reason,
            pointerCount: count,
          });
          resolved.set(pointer, typeof value === 'string' ? value : null);
        } catch {
          resolved.set(pointer, null);
        }
      }

      let out = text;
      let revealed = 0;
      for (const match of [...matches].reverse()) {
        const value = resolved.get(match[0]);
        const replacement = value ?? POINTER_UNAVAILABLE_TEXT;
        if (value !== null && value !== undefined) revealed += 1;
        out = out.slice(0, match.index) + replacement + out.slice(match.index + match[0].length);
      }
      return { text: out, revealed };
    } catch {
      // Leaving the pointers literal is safe — they carry no secret material.
      return { text, revealed: 0 };
    }
  }

  // Scan with the bundled packs, as the mask path does. Pointers already in the
  // text are blanked first so a pointer is never re-tokenized. Returns null
  // when the registry or the scan itself failed — the caller must then treat
  // the whole text as unclassifiable.
  #selfScan(text: string): MatchResult[] | null {
    try {
      registerBundledPacks();
      const shielded = shieldPointers(text);
      return dropShieldedFindings(scan(shielded.text, getLoadedRules()), shielded.spans);
    } catch {
      return null;
    }
  }

  async describePointerSafe(token: string): Promise<PointerDescriptor | null> {
    try {
      return await this.#vault.describePointer(token);
    } catch {
      return null;
    }
  }

  async probeModelPointers(
    text: string,
    opts: { resolveGrant: ModelDerefGrantResolver },
  ): Promise<ProbePointersResult> {
    const granted = new Map<PointerToken, string>();
    const ungranted: PointerToken[] = [];
    try {
      for (const pointer of new Set([...text.matchAll(pointerTokenScanner())].map((m) => m[0]))) {
        try {
          const grantId = await opts.resolveGrant(pointer);
          if (grantId === null) ungranted.push(pointer);
          else granted.set(pointer, grantId);
        } catch {
          ungranted.push(pointer);
        }
      }
      return { granted, ungranted };
    } catch {
      return { granted: new Map(), ungranted };
    }
  }

  async substituteModelPointers(
    text: string,
    opts: { resolveGrant: ModelDerefGrantResolver },
  ): Promise<SubstitutePointersResult> {
    try {
      const matches = [...text.matchAll(pointerTokenScanner())];
      if (matches.length === 0) return { text, revealed: [], unresolved: [], grantIds: [] };

      // Two phases: resolve every distinct pointer's grant FIRST, then
      // de-reference only the granted ones. Every model crossing — revealed or
      // refused — is audited by the vault itself; the glue adds no rows.
      const resolved = new Map<string, { value: string; grantId: string } | null>();
      for (const pointer of new Set(matches.map((m) => m[0]))) {
        try {
          const grantId = await opts.resolveGrant(pointer);
          if (grantId === null) {
            // No grant: the vault still records the refused crossing.
            await this.#vault.detokenize(pointer, { target: 'model', reason: 'model-input' });
            resolved.set(pointer, null);
            continue;
          }
          const value = await this.#vault.detokenize(pointer, {
            target: 'model',
            reason: 'model-input',
            grantId,
          });
          resolved.set(pointer, typeof value === 'string' ? { value, grantId } : null);
        } catch {
          resolved.set(pointer, null);
        }
      }

      // The crossing spends the grant — once per grant, only on success, and
      // regardless of what enforcement mode the covered rule runs under. Tying
      // consumption to a later suppression match would make a once-grant
      // unlimited whenever the rule sits at Monitor/Warn.
      const spentGrants = new Set<string>();
      for (const entry of resolved.values()) {
        if (entry === null || spentGrants.has(entry.grantId)) continue;
        spentGrants.add(entry.grantId);
        try {
          await this.#vault.consumeGrant?.(entry.grantId);
        } catch {
          // The reveal already happened; a failed claim only means the next
          // crossing re-evaluates the grant's remaining budget.
        }
      }

      let out = text;
      const revealed = new Set<string>();
      const unresolved = new Set<string>();
      for (const match of [...matches].reverse()) {
        const entry = resolved.get(match[0]);
        if (entry === null || entry === undefined) {
          unresolved.add(match[0]);
          continue;
        }
        revealed.add(match[0]);
        out = out.slice(0, match.index) + entry.value + out.slice(match.index + match[0].length);
      }
      return {
        text: out,
        revealed: [...revealed],
        unresolved: [...unresolved],
        grantIds: [...spentGrants],
      };
    } catch {
      // Pointers left literal are inert; nothing raw has been substituted.
      return { text, revealed: [], unresolved: [], grantIds: [] };
    }
  }
}

/** Whether `text` contains at least one well-formed pointer token. */
export function hasPointer(text: string): boolean {
  return pointerTokenScanner().test(text);
}

export interface CreateVaultGlueOptions {
  // The ~/.aka base; defaults to the shared layout root.
  base?: string;
  // Test seam: a vault core to use instead of opening the real store.
  vault?: VaultCore;
  // Test seam: a reveal-grant resolver to pair with an injected vault.
  revealResolver?: ModelDerefGrantResolver;
  // The reveal decision seam. Defaults to the user-driven provider (the grant
  // the user created is the decision); a different provider changes WHO
  // decides without touching any crossing site.
  policyProvider?: ExceptionPolicyProvider;
}

/**
 * Build the glue over a live vault. Opening the store, the key provider, or the
 * fingerprint key can all fail; when anything does, the returned glue is a
 * degraded one whose tokenize destroys values one-way and whose detokenize
 * resolves nothing — the two fail postures above, decided once at construction.
 */
export function createVaultGlue(options?: CreateVaultGlueOptions): VaultGlue {
  if (options?.vault) return new SecretVaultGlue(options.vault, options.revealResolver);
  const base = options?.base ?? defaultDataDir();
  try {
    const dir = dataDir(base);
    const db = openLocalDatabase(dir);
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
      fingerprintKey: loadOrCreateFingerprintKey(dir),
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
    // The vault core plus the sighting recorder: SecretVault owns crypto and
    // audit; where a pointer LANDED is repository bookkeeping, wired in here so
    // the glue's callers never touch the store directly.
    const vaultWithSightings: VaultCore = {
      tokenize: (raw, meta) => vault.tokenize(raw, meta),
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
    return new SecretVaultGlue(vaultWithSightings, revealGrantResolver, () => {
      db.close();
    });
  } catch {
    return new SecretVaultGlue(UNOPENABLE_VAULT);
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
  opts?: { findings?: MatchResult[] },
): Promise<TokenizeTextResult> {
  return glue().tokenizeText(text, opts);
}

/** {@link VaultGlue.tokenizeValue} over the default ~/.aka vault. */
export function tokenizeValue(
  raw: string,
  meta: { ruleId: string; category: DetectionCategory; maskedMatch: string },
): Promise<string> {
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
