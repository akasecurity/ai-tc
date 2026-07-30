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
import {
  createKeyProvider,
  defaultDataDir,
  keysDir,
  loadOrCreateFingerprintKey,
  openLocalDatabase,
  readWorkspaceSettings,
  SecretVault,
} from '@akasecurity/persistence';
import type {
  DetectionCategory,
  PointerDescriptor,
  PointerToken,
  VaultDerefReason,
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

export interface DetokenizeTextOptions {
  target: 'human' | 'model';
  reason: VaultDerefReason;
  grantId?: string | undefined;
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
}

export interface VaultGlue {
  tokenizeText(text: string, opts?: { findings?: MatchResult[] }): Promise<TokenizeTextResult>;
  tokenizeValue(
    raw: string,
    meta: { ruleId: string; category: DetectionCategory; maskedMatch: string },
  ): Promise<string>;
  detokenizeText(text: string, opts: DetokenizeTextOptions): Promise<DetokenizeTextResult>;
  describePointerSafe(token: string): Promise<PointerDescriptor | null>;
  substituteModelPointers(
    text: string,
    opts: { resolveGrant: ModelDerefGrantResolver },
  ): Promise<SubstitutePointersResult>;
  // The live reveal-grant lookup for this store: a grant id when an active
  // reveal-to-model exception covers the pointer's value, null otherwise.
  // Always null on a degraded glue. Deliberately does NOT consume the grant:
  // a revealed value re-enters the detection scan immediately, and the
  // suppression match there claims the use — one crossing, one use.
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
    opts?: { findings?: MatchResult[] },
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
          const value = await this.#vault.detokenize(pointer, {
            target: opts.target,
            reason: opts.reason,
            grantId: opts.grantId,
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

  async substituteModelPointers(
    text: string,
    opts: { resolveGrant: ModelDerefGrantResolver },
  ): Promise<SubstitutePointersResult> {
    try {
      const matches = [...text.matchAll(pointerTokenScanner())];
      if (matches.length === 0) return { text, revealed: [], unresolved: [] };

      // Resolve each distinct pointer once. Every model crossing — revealed or
      // refused — is audited by the vault itself; the glue adds no rows.
      const resolved = new Map<string, string | null>();
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
          resolved.set(pointer, typeof value === 'string' ? value : null);
        } catch {
          resolved.set(pointer, null);
        }
      }

      let out = text;
      const revealed = new Set<string>();
      const unresolved = new Set<string>();
      for (const match of [...matches].reverse()) {
        const value = resolved.get(match[0]);
        if (value === null || value === undefined) {
          unresolved.add(match[0]);
          continue;
        }
        revealed.add(match[0]);
        out = out.slice(0, match.index) + value + out.slice(match.index + match[0].length);
      }
      return { text: out, revealed: [...revealed], unresolved: [...unresolved] };
    } catch {
      // Pointers left literal are inert; nothing raw has been substituted.
      return { text, revealed: [], unresolved: [] };
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
    const vault = new SecretVault({
      repo: db.secretVault,
      keys: createKeyProvider(settings.vaultKeyCustody, keysDir(base)),
      fingerprintKey: loadOrCreateFingerprintKey(dir),
      // Read live so a revocation applies to the very next call, not the next
      // process.
      isConsented: () => isVaultConsentValid(readWorkspaceSettings(base).vaultConsent),
    });
    // Grant matching is exact on the identity a grant is keyed by; anything
    // failing along the way is a refusal, never a reveal.
    const revealGrantResolver: ModelDerefGrantResolver = async (pointer) => {
      try {
        const identity = await vault.resolvePointerIdentity(pointer);
        if (identity === null) return null;
        const grant = await db.exceptions.activeRevealGrant(
          identity.ruleId,
          identity.valueFingerprint,
          identity.fingerprintKeyVersion,
        );
        return grant?.id ?? null;
      } catch {
        return null;
      }
    };
    return new SecretVaultGlue(vault, revealGrantResolver, () => {
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
