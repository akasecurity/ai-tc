import type {
  LocalDatabase,
  PointerDigest,
  SightingKey,
  SightingKeys,
} from '@akasecurity/persistence';
import {
  createKeyProvider,
  dataDir as dataDirOf,
  keysDir,
  openLocalDatabase,
  readSightingKeys,
  readWorkspaceSettings,
  SecretVault,
  sightingToken,
} from '@akasecurity/persistence';
import type { SecretSpan } from '@akasecurity/plugin-sdk';
import { findSecretSpans } from '@akasecurity/plugin-sdk';
import type { CaptureSighting, IngestEvent } from '@akasecurity/schema';
import { pointerTokenScanner } from '@akasecurity/schema';

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
  findSpans?: (text: string) => SecretSpan[];
}

export interface EncodedContent {
  content: string;
  sightings: CaptureSighting[];
}

export interface OutboundEncoder {
  encodeContent(content: string): Promise<EncodedContent>;
  /** `event` itself when nothing changes; otherwise a copy with encoded content and sightings. */
  encodeEvent(event: IngestEvent): Promise<IngestEvent>;
}

interface Replacement {
  start: number;
  end: number;
  resolve(): Promise<{ text: string; sighting?: CaptureSighting }>;
}

const failClosed = { text: FAIL_CLOSED_MARKER };

function currentKey(deps: OutboundEncoderDeps): SightingKey | undefined {
  try {
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
 * Fails closed and never throws: with no key, or on any fault, a span becomes
 * {@link FAIL_CLOSED_MARKER}, and a failed scan replaces the whole content with it.
 */
export function createOutboundEncoder(deps: OutboundEncoderDeps): OutboundEncoder {
  const findSpans = deps.findSpans ?? findSecretSpans;

  async function encodeContent(content: string): Promise<EncodedContent> {
    try {
      const key = currentKey(deps);
      const replacements: Replacement[] = findSpans(content).map((span) =>
        valueReplacement(span, key),
      );

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
            sightings.set(`${sighting.token}\u0000${sighting.ruleId}`, sighting);
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
    async encodeEvent(event) {
      const { content, sightings } = await encodeContent(event.content);
      const carried = event.metadata?.sightings !== undefined;
      if (content === event.content && sightings.length === 0 && !carried) return event;
      const rest = { ...event.metadata };
      delete rest.sightings;
      const metadata = sightings.length === 0 ? rest : { ...rest, sightings };
      return { ...event, content, metadata };
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
export function createStoreOutboundEncoder(base: string, db?: LocalDatabase): OutboundEncoder {
  return createOutboundEncoder({
    readKeys: () => readSightingKeys(base),
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
