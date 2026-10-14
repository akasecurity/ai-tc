import type {
  LocalDatabase,
  PointerDigest,
  SightingKey,
  SightingKeys,
} from '@akasecurity/persistence';
import {
  createKeyProvider,
  dataDir as dataDirOf,
  keyedCaptureWireId,
  keysDir,
  loadOrCreateFingerprintKey,
  openLocalDatabase,
  readSightingKeys,
  readSightingSharing,
  readWorkspaceSettings,
  SecretVault,
  sightingToken,
} from '@akasecurity/persistence';
import type {
  BoundedScanRequest,
  GuardedScanPartition,
  SecretSpan,
  SecretSpanScanner,
} from '@akasecurity/plugin-sdk';
import {
  bundledDetections,
  contentHashOf,
  createSecretSpanScanner,
  secretRulePartition,
} from '@akasecurity/plugin-sdk';
import type { CaptureSighting, IngestEvent, Rule } from '@akasecurity/schema';
import { pointerTokenScanner } from '@akasecurity/schema';

import { StandaloneDataGateway } from '../standalone-gateway.ts';
import { createPolicyStore } from './policy-store.ts';

/** What a secret span becomes when it cannot be turned into a sighting token. */
export const FAIL_CLOSED_MARKER = '[REDACTED:SECRET]';

const SECRET_POINTER_PREFIX = '[[aka:secret:';

/** The slice of the vault the encoder uses: a pointer's digest, never its value. */
export interface PointerFingerprinter {
  fingerprintPointer(
    pointer: string,
    digest: (raw: string) => string,
  ): Promise<PointerDigest | symbol>;
}

export interface OutboundEncoderDeps {
  readKeys: () => SightingKeys | undefined;
  /** Opened only for content holding a secret pointer, and closed after it. */
  openVault: () => { vault: PointerFingerprinter; close(): void };
  /**
   * The machine's effective detection rules beyond the compiled-in packs; its
   * secret-category rules are scanned with the bundled ones. A rejection holds
   * the capture.
   */
  loadRules: () => Promise<readonly Rule[]>;
  createScanner?: (partition: GuardedScanPartition) => SecretSpanScanner;
  /**
   * Whether credential sightings may leave this machine now. Asked on every
   * capture; while it answers false, or throws, every secret span is sent as
   * {@link FAIL_CLOSED_MARKER} with no token and no sightings.
   */
  readSharing: () => boolean;
  /**
   * A secret that never leaves this machine, keying the wire id of a capture
   * whose content was encoded. A throw holds the capture.
   */
  readIdKey: () => Buffer;
}

/** The inputs a capture's wire id is derived from, beside its content hash. */
export interface CaptureIdentity {
  sessionId: string | null;
  filePath: string | null;
}

export interface EncodedContent {
  content: string;
  sightings: CaptureSighting[];
}

export interface OutboundEncoder {
  /** Undefined when the capture must be held rather than sent. */
  encodeContent(content: string): Promise<EncodedContent | undefined>;
  /**
   * The event to send: encoded content, its sightings, the hash of the encoded
   * content, and a wire id keyed over the stored row's identity: `identity`
   * (by default the event's own session and file path) and the event's own
   * content hash. `event` itself when nothing changes; undefined when the
   * capture must be held rather than sent.
   */
  encodeEvent(event: IngestEvent, identity?: CaptureIdentity): Promise<IngestEvent | undefined>;
  /** Releases the scan worker, if one was started. */
  close(): Promise<void>;
}

/**
 * The wire id of a capture whose content was encoded, from the stored row's
 * identity: `contentHash` is the hash of the content as stored, not as sent.
 * Two captures whose secrets encode alike, as every secret does while sharing
 * is off, keep two ids, and a capture keeps its id however often it is sent.
 */
export function encodedWireId(
  idKey: Buffer,
  sessionId: string | null,
  contentHash: string,
  filePath: string | null,
): string {
  return keyedCaptureWireId(idKey, sessionId, contentHash, filePath);
}

interface Replacement {
  start: number;
  end: number;
  resolve(): Promise<{ text: string; sighting?: CaptureSighting }>;
}

const failClosed = { text: FAIL_CLOSED_MARKER };

function currentKey(deps: OutboundEncoderDeps): SightingKey | undefined {
  try {
    if (!deps.readSharing()) return undefined;
    return deps.readKeys()?.current;
  } catch {
    return undefined;
  }
}

function valueReplacement(span: SecretSpan, key: SightingKey | undefined): Replacement {
  return {
    start: span.start,
    end: span.end,
    resolve: () => {
      if (key === undefined || span.value === undefined) return Promise.resolve(failClosed);
      const fp = sightingToken(key, span.value);
      return Promise.resolve({
        text: fp,
        sighting: { token: fp, ruleId: span.ruleId, category: span.category },
      });
    },
  };
}

/**
 * Every secret-category span in outgoing capture content becomes its sighting
 * token, `[[aka:fp:v<keyVersion>.<fingerprint>]]`, under the current sighting
 * key. Values are found by scanning the content itself, so a capture encodes the
 * same way whichever path sends it. A secret vault pointer is resolved through
 * the vault's audited fingerprint path to the token of its value.
 *
 * Fails closed and never throws: with no key, or on a fault resolving one span,
 * that span becomes {@link FAIL_CLOSED_MARKER}. When the effective rules cannot
 * be loaded, or the scan cannot start or finish, the capture is held instead.
 */
export function createOutboundEncoder(deps: OutboundEncoderDeps): OutboundEncoder {
  const createScanner = deps.createScanner ?? ((p) => createSecretSpanScanner(p));
  // One scanner, and so at most one worker, for the encoder's whole life.
  let scanner: SecretSpanScanner | undefined;

  async function loadScanner(): Promise<SecretSpanScanner | undefined> {
    try {
      scanner ??= createScanner(secretRulePartition(await deps.loadRules()));
      return scanner;
    } catch {
      return undefined;
    }
  }

  async function findSpans(content: string): Promise<SecretSpan[] | undefined> {
    const loaded = await loadScanner();
    if (loaded === undefined) return undefined;
    try {
      return await loaded.find(content);
    } catch {
      return undefined;
    }
  }

  async function encodeContent(content: string): Promise<EncodedContent | undefined> {
    const spans = await findSpans(content);
    if (spans === undefined) return undefined;
    try {
      const key = currentKey(deps);
      const replacements: Replacement[] = spans.map((span) => valueReplacement(span, key));

      const pointers = [...content.matchAll(pointerTokenScanner())].filter((m) =>
        m[0].startsWith(SECRET_POINTER_PREFIX),
      );
      let opened: ReturnType<OutboundEncoderDeps['openVault']> | undefined;
      const digests = new Map<string, Promise<{ text: string; sighting?: CaptureSighting }>>();
      const resolvePointer = async (
        pointer: string,
      ): Promise<{ text: string; sighting?: CaptureSighting }> => {
        if (key === undefined) return failClosed;
        opened ??= deps.openVault();
        const result = await opened.vault.fingerprintPointer(pointer, (raw) =>
          sightingToken(key, raw),
        );
        if (typeof result !== 'object') return failClosed;
        return {
          text: result.digest,
          sighting: { token: result.digest, ruleId: result.ruleId, category: 'secret' },
        };
      };
      for (const match of pointers) {
        const pointer = match[0];
        replacements.push({
          start: match.index,
          end: match.index + pointer.length,
          resolve: () => {
            let pending = digests.get(pointer);
            if (pending === undefined) {
              pending = resolvePointer(pointer).catch(() => failClosed);
              digests.set(pointer, pending);
            }
            return pending;
          },
        });
      }
      if (replacements.length === 0) return { content, sightings: [] };

      replacements.sort((a, b) => a.start - b.start);
      const sightings = new Map<string, CaptureSighting>();
      let out = '';
      let at = 0;
      try {
        for (const replacement of replacements) {
          let resolved: { text: string; sighting?: CaptureSighting };
          try {
            resolved = await replacement.resolve();
          } catch {
            resolved = failClosed;
          }
          out += content.slice(at, replacement.start) + resolved.text;
          at = replacement.end;
          const { sighting } = resolved;
          if (sighting !== undefined) {
            sightings.set(`${sighting.token} ${sighting.ruleId}`, sighting);
          }
        }
      } finally {
        try {
          opened?.close();
        } catch {
          // Releasing the handle is cleanup; the encoded content stands.
        }
      }
      return { content: out + content.slice(at), sightings: [...sightings.values()] };
    } catch {
      return { content: FAIL_CLOSED_MARKER, sightings: [] };
    }
  }

  return {
    encodeContent,
    async close() {
      try {
        await scanner?.close();
      } catch {
        // The worker is unreferenced; a failed release costs nothing further.
      }
    },
    async encodeEvent(event, identity) {
      const encoded = await encodeContent(event.content);
      if (encoded === undefined) return undefined;
      const { content, sightings } = encoded;
      const carried = event.metadata?.sightings !== undefined;
      if (content === event.content && sightings.length === 0 && !carried) return event;
      let idKey: Buffer;
      try {
        idKey = deps.readIdKey();
      } catch {
        return undefined;
      }
      // The hash sent is of the encoded content; the id is keyed over the
      // stored row's identity, so neither lets the receiver test a raw value.
      const contentHash = contentHashOf(content);
      const { sessionId, filePath } = identity ?? {
        sessionId: event.metadata?.sessionId ?? null,
        filePath: event.metadata?.filePath ?? null,
      };
      const id = encodedWireId(idKey, sessionId, event.contentHash, filePath);
      const rest = { ...event.metadata };
      delete rest.sightings;
      const metadata = sightings.length === 0 ? rest : { ...rest, sightings };
      const keepsNoMetadata = event.metadata === undefined && sightings.length === 0;
      return {
        ...event,
        id,
        contentHash,
        content,
        ...(keepsNoMetadata ? {} : { metadata }),
      };
    },
  };
}

/** A vault over an open store, able only to resolve pointers it already holds. */
export function storeVault(db: LocalDatabase, base: string): PointerFingerprinter {
  return new SecretVault({
    repo: db.secretVault,
    keys: createKeyProvider(readWorkspaceSettings(base).vaultKeyCustody, keysDir(base)),
    isConsented: () => false,
  });
}

/**
 * The encoder over this machine's own sighting key and vault, read from the
 * `~/.aka` root `base`. The store is opened only for content holding a secret
 * pointer, unless `db` is an already-open store to use instead.
 */
export function createStoreOutboundEncoder(
  base: string,
  opts: {
    loadRules: () => Promise<readonly Rule[]>;
    db?: LocalDatabase | undefined;
    scanBound?: BoundedScanRequest | undefined;
    readSharing?: (() => boolean) | undefined;
  },
): OutboundEncoder {
  const { db, scanBound } = opts;
  let idKey: Buffer | undefined;
  return createOutboundEncoder({
    loadRules: opts.loadRules,
    ...(scanBound === undefined
      ? {}
      : { createScanner: (p: GuardedScanPartition) => createSecretSpanScanner(p, scanBound) }),
    readKeys: () => readSightingKeys(base),
    readSharing: opts.readSharing ?? (() => readSightingSharing(base).sharing),
    readIdKey: () => (idKey ??= loadOrCreateFingerprintKey(dataDirOf(base)).material),
    openVault: () => {
      if (db !== undefined) return { vault: storeVault(db, base), close: () => undefined };
      const opened = openLocalDatabase(dataDirOf(base));
      try {
        return {
          vault: storeVault(opened, base),
          close: () => {
            opened.close();
          },
        };
      } catch (err) {
        opened.close();
        throw err;
      }
    },
  });
}

/**
 * The effective rules beyond the compiled-in packs, read as the attached
 * gateway composes them: the local store's installed snapshot first, then the
 * cached organization bundle.
 */
export async function storeEffectiveRules(dataDir: string): Promise<readonly Rule[]> {
  const local = new StandaloneDataGateway(dataDir, bundledDetections());
  try {
    const bundle = await local.getPolicyBundle();
    const cached = await createPolicyStore(dataDir).read();
    return [...(bundle.rules ?? []), ...(cached?.bundle.rules ?? [])];
  } finally {
    await local.close();
  }
}
