// The vault core: turn a detected value into a pointer, and a pointer back into
// the value for whoever is allowed to see it.
//
// Two sentinels rather than exceptions, because every caller sits on a hook path
// that must not break a session:
//   CONSENT_ABSENT  the user has not granted vaulting — the caller falls back to
//                   one-way redaction, so the value is destroyed, not leaked.
//   UNAVAILABLE     the pointer could not be resolved, for any reason. Callers
//                   render it as such; they never see why, and never see raw.
//
// Ordering inside detokenize is deliberate and load-bearing — see the comments
// there before changing it.
import { randomBytes, randomUUID } from 'node:crypto';

import type {
  DetectionCategory,
  DetokenizeTarget,
  PointerDescriptor,
  PointerIdentity,
  VaultDerefOutcome,
  VaultDerefReason,
} from '@akasecurity/schema';
import {
  isBatchedDerefReason,
  POINTER_FORMAT_VERSION,
  POINTER_TOKEN_ANCHORED,
} from '@akasecurity/schema';

import { type FingerprintKey, fingerprintValue } from '../fingerprint.ts';
import type { SqliteSecretVaultRepository, VaultRow } from '../repositories/secret-vault.ts';
import {
  base32Decode,
  base32Encode,
  bindingInput,
  decodeKeyVersion,
  deriveSubkeys,
  encodeKeyVersion,
  formatPointer,
  NONCE_BYTES,
  open as openSealed,
  POINTER_ID_BYTES,
  seal,
  signPointer,
  verifyPointerTag,
} from './crypto.ts';
import type { KeyProvider } from './key-provider.ts';

export const CONSENT_ABSENT = Symbol('aka.vault.consentAbsent');
export const UNAVAILABLE = Symbol('aka.vault.unavailable');

export type TokenizeResult = string | typeof CONSENT_ABSENT;
export type DetokenizeResult = string | typeof UNAVAILABLE;

// A purge is recorded against this sentinel instead of a real pointer id: the
// event concerns the whole vault, and the record that entries were destroyed has
// to survive the destruction.
export const VAULT_PURGE_POINTER_ID = '*';

export interface TokenizeMeta {
  ruleId: string;
  // The category the DETECTING rule proposes. It is only a proposal: a value
  // already in the vault keeps the category it was minted with, so one value
  // always yields exactly one wire token.
  category: DetectionCategory;
  maskedMatch: string;
  provider?: string | undefined;
}

export interface DetokenizeOptions {
  target: DetokenizeTarget;
  reason: VaultDerefReason;
  // Required for a model-target crossing. Absent → refused.
  grantId?: string | undefined;
  // How many pointers one batched render resolved. Ignored for reasons that are
  // never batched.
  pointerCount?: number | undefined;
}

interface ParsedPointerToken {
  category: string;
  keyVersion: number;
  pointerId: Buffer;
  tag: Buffer;
}

/** Shape-only parse. Proves nothing about authenticity — the tag check does that. */
function parsePointer(token: string): ParsedPointerToken | null {
  if (!POINTER_TOKEN_ANCHORED.test(token)) return null;
  const body = token.slice('[[aka:'.length, -']]'.length);
  const colon = body.indexOf(':');
  if (colon < 0) return null;
  const category = body.slice(0, colon);
  const [kv, id, tag] = body.slice(colon + 1).split('.');
  if (kv === undefined || id === undefined || tag === undefined) return null;
  try {
    const keyVersion = decodeKeyVersion(kv);
    const pointerId = base32Decode(id);
    const tagBytes = base32Decode(tag);
    // Canonical-form check: base32 decoding discards trailing sub-byte bits and
    // the key-version decoder tolerates leading zero bytes, so several distinct
    // strings can decode to the same segments. Only the exact spelling this
    // vault emits counts as a pointer — anything else is not a pointer at all,
    // so the audit and dedup keys never fragment across spellings.
    if (
      encodeKeyVersion(keyVersion) !== kv ||
      base32Encode(pointerId) !== id ||
      base32Encode(tagBytes) !== tag
    ) {
      return null;
    }
    return { category, keyVersion, pointerId, tag: tagBytes };
  } catch {
    return null;
  }
}

export interface SecretVaultDeps {
  repo: SqliteSecretVaultRepository;
  keys: KeyProvider;
  // The exception-key epoch a value's fingerprint is derived under. This is a
  // different key from the vault's, with different rotation semantics.
  fingerprintKey: FingerprintKey;
  // Read live on every call, so revoking consent takes effect immediately
  // rather than at the next process start.
  isConsented: () => boolean;
  // Vault-side grant check for a model-target de-reference: does `grantId`
  // actively cover the ROW's identity right now? The vault is the last gate
  // before raw leaves the store, so a caller-provided grant id is never taken
  // on trust — a false, or a throw, refuses the crossing.
  //
  // OMITTING THIS BUILDS A VAULT WITH NO MODEL ROAD: every `target: 'model'`
  // de-reference refuses. That is the useful default, because most construction
  // sites are owner surfaces that only ever read for a human, and it makes them
  // structurally incapable of a crossing rather than merely not attempting one.
  // Only a site that genuinely reveals to the model supplies a verifier, and
  // supplying one is what opens the road.
  verifyGrant?: ((grantId: string, identity: PointerIdentity) => Promise<boolean>) | undefined;
  now?: () => number;
}

export class SecretVault {
  readonly #repo: SqliteSecretVaultRepository;
  readonly #keys: KeyProvider;
  readonly #fingerprintKey: FingerprintKey;
  readonly #isConsented: () => boolean;
  readonly #verifyGrant:
    ((grantId: string, identity: PointerIdentity) => Promise<boolean>) | undefined;
  readonly #now: () => number;

  constructor(deps: SecretVaultDeps) {
    this.#repo = deps.repo;
    this.#keys = deps.keys;
    this.#fingerprintKey = deps.fingerprintKey;
    this.#isConsented = deps.isConsented;
    this.#verifyGrant = deps.verifyGrant;
    this.#now = deps.now ?? ((): number => Date.now());
  }

  /**
   * Store a value and return the pointer that stands for it. The same value
   * always yields the same pointer on this machine — one row, one pointer id,
   * one category — which is what makes dedup and reuse counting work.
   */
  async tokenize(raw: string, meta: TokenizeMeta): Promise<TokenizeResult> {
    if (!this.#isConsented()) return CONSENT_ABSENT;

    const valueFingerprint = fingerprintValue(this.#fingerprintKey, raw);
    const existing = this.#repo.byValueFingerprint(valueFingerprint);
    const now = this.#now();

    if (existing) {
      // Re-detection: bump the count, keep every minted property. The token is
      // re-emitted under the row's current epoch, which is also the epoch its
      // ciphertext is sealed under.
      this.#repo.upsert({ ...existing, provider: existing.provider ?? undefined }, now);
      return await this.#emitToken(existing.keyVersion, existing.pointerId, existing.category);
    }

    const { material, version } = await this.#keys.loadOrCreate();
    const subkeys = deriveSubkeys(material);
    const pointerId = randomBytes(POINTER_ID_BYTES);
    const aad = bindingInput(version, pointerId, meta.category, POINTER_FORMAT_VERSION);
    const sealed = seal(subkeys.enc, raw, aad, randomBytes(NONCE_BYTES));

    const { row } = this.#repo.upsert(
      {
        pointerId: base32Encode(pointerId),
        valueFingerprint,
        fingerprintKeyVersion: this.#fingerprintKey.version,
        keyVersion: version,
        // Recorded so the row stays OPENABLE if the wire-format constant ever
        // moves: it is part of this row's AEAD AAD. It is not a tag input —
        // tags are pinned to the constant on both sides.
        formatVersion: POINTER_FORMAT_VERSION,
        category: meta.category,
        ruleId: meta.ruleId,
        maskedMatch: meta.maskedMatch,
        provider: meta.provider,
        ciphertext: sealed.ciphertext.toString('base64'),
        nonce: sealed.nonce.toString('base64'),
        authTag: sealed.authTag.toString('base64'),
      },
      now,
    );

    // A concurrent writer may have won the unique index between the lookup and
    // the insert; the returned row is authoritative either way.
    return await this.#emitToken(row.keyVersion, row.pointerId, row.category);
  }

  /**
   * Resolve a pointer back to its value, for a human or (with a grant) for the
   * model. Every call that gets as far as an identified row writes an audit row.
   */
  async detokenize(token: string, opts: DetokenizeOptions): Promise<DetokenizeResult> {
    const parsed = parsePointer(token);
    if (!parsed) return UNAVAILABLE;

    // Verify BEFORE touching the store or any ciphertext. A forged or tampered
    // token is unattributable — it names no one and nothing — so it writes no
    // audit row; only a token we can attribute to a real entry does.
    //
    // The tag is checked under the CURRENT wire-format version, and signing
    // uses the same constant, so the two cannot disagree about a row. That
    // pinning is forced by the ordering above: the row is not in hand yet, so
    // its recorded generation is not knowable here. A format bump must bring a
    // verification story for stored rows' tags — see POINTER_FORMAT_VERSION;
    // the frozen golden vector in crypto.test.ts exists to force that.
    let signKey: Buffer;
    try {
      const epoch = await this.#keys.materialFor(parsed.keyVersion);
      signKey = deriveSubkeys(epoch.material).sign;
    } catch {
      return UNAVAILABLE;
    }
    if (
      !verifyPointerTag(signKey, parsed.keyVersion, parsed.pointerId, parsed.category, parsed.tag)
    ) {
      return UNAVAILABLE;
    }

    const pointerId = base32Encode(parsed.pointerId);
    const row = this.#repo.byPointerId(pointerId);
    if (!row) {
      this.#audit(pointerId, opts, 'unavailable');
      return UNAVAILABLE;
    }

    // Defence in depth behind the tag: a token whose category disagrees with its
    // row is treated exactly like a forgery — silent, no audit row — so a
    // mismatch can never masquerade as a legitimate refused crossing.
    if (row.category !== parsed.category) return UNAVAILABLE;

    // The grant gate sits AFTER the row lookup so the check above can stay
    // silent. Consequence: a purged pointer with no grant audits `unavailable`
    // rather than `refused`, which is the truthful outcome anyway.
    if (opts.target === 'model') {
      const grantId = opts.grantId;
      // No verifier means this vault has no model road at all. Refusing here
      // rather than trusting the id keeps an owner-surface vault incapable of a
      // crossing even if a caller asks for one.
      const verify = this.#verifyGrant;
      if (verify === undefined || grantId === undefined || grantId === '') {
        this.#audit(pointerId, opts, 'refused');
        return UNAVAILABLE;
      }
      // Last gate: the grant id must actively cover THIS row's identity, so a
      // fabricated or stale id refuses the crossing instead of being audited as
      // if it authorized it. A verifier fault also refuses — at this gate an
      // error must never widen into a reveal.
      let covered: boolean;
      try {
        covered = await verify(grantId, {
          ruleId: row.ruleId,
          valueFingerprint: row.valueFingerprint,
          fingerprintKeyVersion: row.fingerprintKeyVersion,
        });
      } catch {
        covered = false;
      }
      if (!covered) {
        this.#audit(pointerId, opts, 'refused');
        return UNAVAILABLE;
      }
    }

    let raw: string | null;
    try {
      const epoch = await this.#keys.materialFor(row.keyVersion);
      raw = openSealed(
        deriveSubkeys(epoch.material).enc,
        {
          ciphertext: Buffer.from(row.ciphertext, 'base64'),
          nonce: Buffer.from(row.nonce, 'base64'),
          authTag: Buffer.from(row.authTag, 'base64'),
        },
        // Sealed under the ROW's epoch and format version. Rotation may have
        // moved the epoch past the one this token names, and a format bump may
        // have moved the constant past the generation this row was sealed
        // under — the AAD follows the row in both cases, never the token.
        bindingInput(row.keyVersion, parsed.pointerId, row.category, row.formatVersion),
      );
    } catch {
      raw = null;
    }

    if (raw === null) {
      this.#audit(pointerId, opts, 'unavailable');
      return UNAVAILABLE;
    }

    this.#audit(pointerId, opts, 'revealed');
    return raw;
  }

  /**
   * Owner-surface reveal by row id: the dashboard shows a row the owner can
   * already see and asks for its value. There is no wire token here to verify —
   * the tag exists to stop FORGED tokens arriving in untrusted text, and a row
   * id selected server-side from the owner's own store is not that — so this
   * loads the row directly, opens its ciphertext under the row's epoch, and
   * audits exactly like a human-target de-reference. Never callable with
   * target 'model': the wire-token path with its grant gate is the only road
   * raw travels toward the model.
   */
  async revealEntry(
    pointerId: string,
    opts: { reason: 'explicit-reveal' | 'view-render' },
  ): Promise<DetokenizeResult> {
    const row = this.#repo.byPointerId(pointerId);
    if (!row) {
      this.#audit(pointerId, { target: 'human', reason: opts.reason }, 'unavailable');
      return UNAVAILABLE;
    }
    const raw = await this.#openRow(row);
    if (raw === null) {
      this.#audit(pointerId, { target: 'human', reason: opts.reason }, 'unavailable');
      return UNAVAILABLE;
    }
    this.#audit(pointerId, { target: 'human', reason: opts.reason }, 'revealed');
    return raw;
  }

  /** Badge and listing data. No raw value, no fingerprint, and no audit row. */
  async describePointer(token: string): Promise<PointerDescriptor | null> {
    const row = await this.#rowFor(token);
    if (!row) return null;
    return {
      category: row.category as DetectionCategory,
      ...(row.provider === undefined ? {} : { provider: row.provider }),
      maskedMatch: row.maskedMatch,
      occurrences: row.occurrenceCount,
      firstSeen: new Date(row.firstSeen).toISOString(),
      lastSeen: new Date(row.lastSeen).toISOString(),
    };
  }

  /**
   * The raw-free row identity a reveal grant matches on. Deliberately not fed to
   * view surfaces: the keyed fingerprint is a correlation key and must not reach
   * a presentation layer.
   */
  async resolvePointerIdentity(token: string): Promise<PointerIdentity | null> {
    const row = await this.#rowFor(token);
    if (!row) return null;
    return {
      ruleId: row.ruleId,
      valueFingerprint: row.valueFingerprint,
      fingerprintKeyVersion: row.fingerprintKeyVersion,
    };
  }

  /**
   * Mint the next vault key epoch and re-encrypt every entry under it. Pointers
   * already emitted keep verifying: their tag is checked against the historical
   * epoch they name, which the key provider retains.
   *
   * Safe to interrupt — each row carries the epoch its ciphertext is sealed
   * under, so a half-finished pass leaves every row openable.
   *
   * The rotation lock covers only the keyring mint inside `rotate()`; the
   * re-seal pass below runs unlocked. Two concurrent rotations therefore
   * serialize on the keyring but interleave over the rows, so a slower pass can
   * re-seal a row back to an epoch a faster one already moved past, and
   * `reEncrypted` can double-count. No value is lost either way — every epoch is
   * retained and every row stays openable — but "after rotation every row sits
   * at the newest epoch" does not hold under concurrency. Holding the lock
   * across the whole pass requires an async-aware lock, since a callback that
   * awaits would release the lock at its first suspension.
   */
  async rotateVaultKey(): Promise<{ version: number; reEncrypted: number }> {
    const next = await this.#keys.rotate();
    const nextEnc = deriveSubkeys(next.material).enc;
    let reEncrypted = 0;

    for (const row of this.#repo.listAll()) {
      if (row.keyVersion === next.version) continue;
      const pointerId = base32Decode(row.pointerId);
      let raw: string | null;
      try {
        const epoch = await this.#keys.materialFor(row.keyVersion);
        raw = openSealed(
          deriveSubkeys(epoch.material).enc,
          {
            ciphertext: Buffer.from(row.ciphertext, 'base64'),
            nonce: Buffer.from(row.nonce, 'base64'),
            authTag: Buffer.from(row.authTag, 'base64'),
          },
          bindingInput(row.keyVersion, pointerId, row.category, row.formatVersion),
        );
      } catch {
        raw = null;
      }
      // An entry we cannot open is left exactly as it is. Overwriting it with
      // anything would destroy a value we might still recover.
      if (raw === null) continue;

      // Key rotation moves the epoch, not the format generation: the row's
      // format version is preserved so its ciphertext stays bound to the AAD it
      // was sealed under. Outstanding tokens are unaffected either way — a tag
      // never carries the row's generation.
      const sealed = seal(
        nextEnc,
        raw,
        bindingInput(next.version, pointerId, row.category, row.formatVersion),
        randomBytes(NONCE_BYTES),
      );
      this.#repo.replaceCiphertext(row.pointerId, {
        keyVersion: next.version,
        ciphertext: sealed.ciphertext.toString('base64'),
        nonce: sealed.nonce.toString('base64'),
        authTag: sealed.authTag.toString('base64'),
      });
      reEncrypted += 1;
    }

    return { version: next.version, reEncrypted };
  }

  /**
   * Re-key every entry's value fingerprint after the exception key rotates,
   * PRESERVING each pointer id. Unlike grants — where rotation is invalidation,
   * because the raw values are gone — the vault still holds the values, so
   * determinism, dedup, and every outstanding pointer survive the rotation.
   *
   * Every fingerprint-key rotation must run this: a row left at the old epoch
   * still resolves, but the same value detected again fingerprints under the
   * NEW key, misses the dedup lookup, and mints a second row and a second
   * pointer — one value, two tokens in circulation.
   *
   * Per-row best-effort: a row that cannot open, or whose refreshed
   * fingerprint collides with a row already refreshed, is skipped rather than
   * aborting the pass — one damaged entry must not strand the re-key of every
   * other. A skipped row keeps resolving under its old fingerprint epoch.
   */
  async refreshFingerprints(next: FingerprintKey): Promise<number> {
    let refreshed = 0;
    for (const row of this.#repo.listAll()) {
      try {
        const raw = await this.#openRow(row);
        if (raw === null) continue;
        this.#repo.refreshFingerprint(row.pointerId, {
          valueFingerprint: fingerprintValue(next, raw),
          fingerprintKeyVersion: next.version,
        });
        refreshed += 1;
      } catch {
        continue;
      }
    }
    return refreshed;
  }

  /**
   * Destroy every entry, making all outstanding pointers permanently
   * unresolvable.
   *
   * The count comes from `purgeAll` rather than a separate `countEntries` —
   * `purgeAll` counts inside the same transaction that deletes, so the audit row
   * reports what was actually destroyed. Counting beforehand would let a
   * concurrent write land between the two statements and put a number in the
   * durable record that never matched reality.
   */
  purgeVault(): number {
    const destroyed = this.#repo.purgeAll();
    this.#repo.recordDeref({
      id: randomUUID(),
      pointerId: VAULT_PURGE_POINTER_ID,
      at: this.#now(),
      target: 'human',
      reason: 'purge',
      outcome: 'unavailable',
      pointerCount: Math.max(destroyed, 1),
    });
    return destroyed;
  }

  // Sign under the epoch the token names — which for a re-detected value is the
  // epoch its row currently sits at rather than whatever is current.
  //
  // The row's format version is NOT a tag input. It binds the row's ciphertext
  // (it is part of the AEAD AAD, so an old row stays openable) but never the
  // wire tag, which verification checks against POINTER_FORMAT_VERSION without
  // knowing any row. Signing a token here under a row's own generation is what
  // would make the vault emit tokens it then refuses.
  async #emitToken(keyVersion: number, pointerIdB32: string, category: string): Promise<string> {
    const pointerId = base32Decode(pointerIdB32);
    const epoch = await this.#keys.materialFor(keyVersion);
    const signKey = deriveSubkeys(epoch.material).sign;
    return formatPointer(
      category,
      keyVersion,
      pointerId,
      signPointer(signKey, keyVersion, pointerId, category),
    );
  }

  async #openRow(row: VaultRow): Promise<string | null> {
    try {
      const epoch = await this.#keys.materialFor(row.keyVersion);
      return openSealed(
        deriveSubkeys(epoch.material).enc,
        {
          ciphertext: Buffer.from(row.ciphertext, 'base64'),
          nonce: Buffer.from(row.nonce, 'base64'),
          authTag: Buffer.from(row.authTag, 'base64'),
        },
        bindingInput(row.keyVersion, base32Decode(row.pointerId), row.category, row.formatVersion),
      );
    } catch {
      return null;
    }
  }

  // Shared lookup for the read-only surfaces. It verifies the tag exactly as
  // detokenize does: a descriptor is not raw, but a token nobody can vouch for
  // should not resolve to anything at all — otherwise a fabricated pointer, or a
  // lookalike planted in a file, would still yield a category and a masked
  // preview. Verifying needs the historical epoch's key, which is why these
  // surfaces are async.
  async #rowFor(token: string): Promise<VaultRow | null> {
    const parsed = parsePointer(token);
    if (!parsed) return null;

    try {
      const epoch = await this.#keys.materialFor(parsed.keyVersion);
      const signKey = deriveSubkeys(epoch.material).sign;
      if (
        !verifyPointerTag(signKey, parsed.keyVersion, parsed.pointerId, parsed.category, parsed.tag)
      ) {
        return null;
      }
    } catch {
      return null;
    }

    const row = this.#repo.byPointerId(base32Encode(parsed.pointerId));
    if (row?.category !== parsed.category) return null;
    return row;
  }

  #audit(pointerId: string, opts: DetokenizeOptions, outcome: VaultDerefOutcome): void {
    this.#repo.recordDeref({
      id: randomUUID(),
      pointerId,
      at: this.#now(),
      target: opts.target,
      reason: opts.reason,
      outcome,
      ...(opts.grantId === undefined ? {} : { grantId: opts.grantId }),
      // Only the batched reasons carry a count above one; a model crossing is
      // always its own row.
      pointerCount: isBatchedDerefReason(opts.reason) ? (opts.pointerCount ?? 1) : 1,
    });
  }
}
