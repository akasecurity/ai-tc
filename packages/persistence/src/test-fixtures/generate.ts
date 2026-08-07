/**
 * Deterministic corpus generation for the benchmark harness.
 *
 * The sibling seeders in this directory are FIXED datasets: a hand-authored
 * store shaped to exercise a read surface. A benchmark needs the other kind —
 * a store of a stated SIZE, and the sizes that matter (100k events, 1M events)
 * cannot live in git at any fidelity. So this generates one from a seed
 * instead: same seed, same rows, byte for byte, on every machine and every run.
 *
 * Three properties are load-bearing.
 *
 * **It writes through the PRODUCT's write path, not a copy of it.** Every row
 * lands via the caller's `recordCapture`, so the corpus is whatever
 * `recordCapture` produces — session roots, content-addressed capture ids,
 * definition upserts, both dedup gates. A generator that INSERTed the rows
 * itself would be a second model of that mapping, free to drift from it, and a
 * benchmark reading the drifted store would report a number about a shape the
 * product never writes.
 *
 * **The whole corpus is ONE transaction.** In autocommit each `recordCapture`
 * commits on its own, and on a file-backed store every commit is a separate
 * flush — the same cost `index.ts` explains for the fixed seeders, except a
 * benchmark corpus is three orders of magnitude larger. Measured on the real
 * write path inside one enclosing transaction: 0.029 ms/event at 1k, 0.035 at
 * 10k, 0.039 at 50k. That near-flat per-event cost is what makes a
 * six-figure corpus a setup step rather than the benchmark.
 *
 * **It verifies what LANDED.** `recordCapture` is fail-open by design — a
 * locked, full or read-only store swallows the write and returns. A benchmark
 * has no assertions, so a generator that trusted its own calls would hand back
 * an EMPTY store and every downstream measurement would be a timing of nothing,
 * reported as a fast one. `generateCaptureCorpus` counts the rows it asked for
 * and throws when they are not there. That check is the harness's positive
 * control and must not be softened into a warning.
 *
 * Determinism means no ambient entropy: no `Math.random`, no `randomUUID`, no
 * `Date.now`. Ids come from the seeded PRNG and timestamps from a fixed epoch,
 * so two runs of the same options produce identical bytes.
 *
 * TEST AND BENCHMARK FIXTURES ONLY, like the rest of this directory — imported
 * by `*.test.ts` and `*.bench.ts`, never by shipped code.
 */
import type { DatabaseSync } from 'node:sqlite';

import type { DetectedFinding, EventKind, IngestEvent, SourceTool } from '@akasecurity/schema';
import { CAPTURE_EVENT_TYPES_SQL } from '@akasecurity/schema';

import { withTransaction } from '../internal/transactions.ts';

/**
 * What the generator needs of a store, and nothing more.
 *
 * Deliberately NOT `LocalDatabase`. Its connection is reachable only through
 * the symbol-keyed test-only seam on that interface, and
 * `packages/eslint-config/test/test-only-seam.test.js` fails CI on any shipped
 * source that so much as names it — which this file is by that audit's
 * reckoning, since nothing marks it as test code even though nothing bundles it
 * either. Taking the two pieces as parameters keeps the read on the caller's
 * side, under `test/`, where the audit already permits it.
 * `test/helpers/corpus.ts` is that caller.
 */
export interface CaptureCorpusTarget {
  /** The product write path. One capture event plus its already-masked findings. */
  readonly recordCapture: (event: IngestEvent, findings: DetectedFinding[]) => void;
  /**
   * The SAME connection `recordCapture` writes through — not a second handle on
   * the same file. A second handle carries none of the enclosing transaction, so
   * the per-call commits come back and the corpus takes minutes instead of
   * seconds.
   */
  readonly connection: DatabaseSync;
}

export interface CaptureCorpusOptions {
  /** How many capture events to write. */
  readonly events: number;
  /** The PRNG seed. Same seed, same corpus. */
  readonly seed?: number;
  /** How many sessions to spread the events across. */
  readonly sessions?: number;
  /**
   * Fraction of events (0..1) that carry one finding. Findings dedup on
   * `(ruleId, maskedMatch, sessionId)`, so each generated finding varies its
   * masked preview and all of them land.
   */
  readonly findingRate?: number;
}

export interface GeneratedCaptureCorpus {
  readonly seed: number;
  /** Capture events that landed — asserted equal to the requested count. */
  readonly events: number;
  readonly sessions: number;
  /** Findings that landed. */
  readonly findings: number;
}

const DEFAULT_SEED = 1;
const DEFAULT_SESSIONS = 50;
const DEFAULT_FINDING_RATE = 0.1;

/**
 * A fixed epoch for every generated timestamp: 2024-01-01T00:00:00.000Z.
 *
 * Not `Date.now()`. A corpus whose timestamps move with the wall clock is a
 * corpus whose date-windowed reads return a different row count every day,
 * which turns a query benchmark's own input into a variable.
 */
const EPOCH_MS = 1_704_067_200_000;

/** One second between consecutive events — dense enough that a large corpus stays inside a plausible window. */
const EVENT_SPACING_MS = 1_000;

/**
 * mulberry32: 32 bits of state, uniform output, and identical on every engine
 * because every step is an explicit 32-bit integer operation. Chosen over
 * anything from the platform precisely because the platform is free to change
 * its generator between releases; this one cannot.
 */
export function createSeededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

/** `n` hex digits from the seeded stream. */
function hex(rng: () => number, n: number): string {
  let out = '';
  for (let i = 0; i < n; i += 1) out += Math.floor(rng() * 16).toString(16);
  return out;
}

/**
 * A v4-SHAPED guid from the seeded stream — real version and variant nibbles,
 * not merely 32 hex characters. `Event.id` is `z.guid()`, and a store seeded
 * with ids the schema would reject is a store no product path could have
 * written.
 */
function seededGuid(rng: () => number): string {
  const variant = '89ab'[Math.floor(rng() * 4)] ?? '8';
  return `${hex(rng, 8)}-${hex(rng, 4)}-4${hex(rng, 3)}-${variant}${hex(rng, 3)}-${hex(rng, 12)}`;
}

/**
 * Ordinary prose the detection engine finds nothing in.
 *
 * This repository is public, so no generated content may be secret-SHAPED —
 * not even a fake one. A benchmark that wants findings gets them from the
 * `findingRate` option, which writes already-masked previews through the same
 * path the SDK does, rather than from planted raw values in the text.
 */
const WORDS = [
  'refactor',
  'the',
  'session',
  'handler',
  'so',
  'a',
  'retry',
  'never',
  'reopens',
  'store',
  'and',
  'move',
  'walk',
  'off',
  'thread',
  'before',
  'deadline',
  'returns',
];

/** Deterministic prose of roughly `chars` characters. */
function seededText(rng: () => number, chars: number): string {
  const parts: string[] = [];
  let length = 0;
  while (length < chars) {
    const word = WORDS[Math.floor(rng() * WORDS.length)] ?? 'the';
    parts.push(word);
    length += word.length + 1;
  }
  return parts.join(' ');
}

const KINDS: EventKind[] = ['prompt', 'response', 'code_change', 'tool_use'];
const TOOLS: SourceTool[] = ['claude-code', 'codex', 'antigravity', 'cli'];

/** Bytes of `content` per generated event — a plausible prompt, not a stress input. */
const CONTENT_CHARS = 240;

/**
 * Write `options.events` capture events (and their findings) through the
 * target's own `recordCapture`, in one transaction, and return what landed.
 *
 * @throws if fewer capture events are on disk afterwards than were requested —
 * see the fail-open note in this module's header.
 */
export function generateCaptureCorpus(
  target: CaptureCorpusTarget,
  options: CaptureCorpusOptions,
): GeneratedCaptureCorpus {
  const { events } = options;
  const seed = options.seed ?? DEFAULT_SEED;
  const sessions = options.sessions ?? DEFAULT_SESSIONS;
  const findingRate = options.findingRate ?? DEFAULT_FINDING_RATE;

  if (!Number.isInteger(events) || events < 0) {
    throw new TypeError(
      `generateCaptureCorpus: events must be a non-negative integer, got ${String(events)}`,
    );
  }
  if (!Number.isInteger(sessions) || sessions < 1) {
    throw new TypeError(
      `generateCaptureCorpus: sessions must be a positive integer, got ${String(sessions)}`,
    );
  }
  if (findingRate < 0 || findingRate > 1) {
    throw new RangeError(
      `generateCaptureCorpus: findingRate must be within 0..1, got ${String(findingRate)}`,
    );
  }

  const rng = createSeededRandom(seed);

  // Session ids are drawn FIRST and reused, so the same seed produces the same
  // session set whatever the event count is — a 10k corpus is the 1k corpus
  // plus more events in the same sessions, which is what makes two scales
  // comparable.
  const sessionIds = Array.from({ length: sessions }, () => seededGuid(rng));

  const baseline = countCaptureEvents(target.connection);
  let findings = 0;

  withTransaction(target.connection, () => {
    for (let i = 0; i < events; i += 1) {
      const sessionId = sessionIds[i % sessions] ?? sessionIds[0] ?? seededGuid(rng);
      const kind = KINDS[Math.floor(rng() * KINDS.length)] ?? 'prompt';
      const event: IngestEvent = {
        id: seededGuid(rng),
        sourceTool: TOOLS[Math.floor(rng() * TOOLS.length)] ?? 'claude-code',
        kind,
        occurredAt: new Date(EPOCH_MS + i * EVENT_SPACING_MS).toISOString(),
        // The capture row is content-addressed on (sessionId, contentHash,
        // filePath), so a shared hash would collapse every event in a session
        // onto ONE row and the corpus would silently be `sessions` rows deep
        // however many events were asked for. The index makes it unique by
        // construction rather than by luck.
        contentHash: `corpus-${String(seed)}-${String(i)}`,
        content: seededText(rng, CONTENT_CHARS),
        metadata: { sessionId },
      };

      const detected: DetectedFinding[] = [];
      if (rng() < findingRate) {
        detected.push({
          id: seededGuid(rng),
          eventId: event.id,
          ruleId: 'secrets/aws-access-key',
          category: 'secret',
          severity: 'critical',
          span: { start: 0, end: 8 },
          // Half the finding-level session dedup key. A constant here would
          // make every finding after the first in a session land as zero rows
          // BY DESIGN, so the corpus would carry `sessions` findings whatever
          // the rate said — the same trap `test/helpers/capture-fixtures.ts`
          // documents, at corpus scale.
          maskedMatch: `A***${String(i)}`,
          actionTaken: 'block',
          confidence: 0.9,
        });
        findings += 1;
      }

      target.recordCapture(event, detected);
    }
  });

  const landed = countCaptureEvents(target.connection) - baseline;
  if (landed !== events) {
    throw new Error(
      `generateCaptureCorpus wrote ${String(landed)} capture events, expected ${String(events)}. ` +
        'recordCapture is fail-open, so a locked, full or read-only store swallows the write and ' +
        'returns — a benchmark reading this store would have measured an empty one.',
    );
  }

  return { seed, events: landed, sessions, findings };
}

/**
 * Capture rows only. `audit_events` also holds the structural rows
 * `recordCapture` plants (a session root per session), so counting the whole
 * table would report more than was asked for and the check above would fail on
 * a corpus that was written perfectly. The kind list is interpolated from the
 * schema's own derived constant, never spelled here.
 */
function countCaptureEvents(connection: DatabaseSync): number {
  const row = connection
    .prepare(
      `SELECT COUNT(*) AS c FROM audit_events WHERE event_type IN (${CAPTURE_EVENT_TYPES_SQL})`,
    )
    .get() as { c: number } | undefined;
  return row?.c ?? 0;
}
