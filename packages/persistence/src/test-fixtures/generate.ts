/**
 * Deterministic corpus generation for the benchmark harness.
 *
 * The sibling seeders in this directory are FIXED datasets: a hand-authored
 * store shaped to exercise a read surface. A benchmark needs the other kind —
 * a store of a stated SIZE, and the sizes that matter (100k events, 1M events)
 * cannot live in git at any fidelity. So this generates one from a seed
 * instead: same seed, same rows, byte for byte, on every machine and every run.
 *
 * Five properties are load-bearing.
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
 * benchmark corpus is three orders of magnitude larger.
 *
 * **The per-event cost is NOT flat, and a caller has to budget for that.**
 * Measured on the real write path inside one enclosing transaction, on arm64
 * macOS / Node 24: 0.054 ms/event at 5k, 0.096 at 100k (9.6 s for the corpus),
 * and 0.639 at 1M — the 10.7 minutes the bench files quote. So a corpus
 * is a setup step at four figures and a substantial one at six; anything
 * seeding 100k or more belongs in a `beforeAll`, where it is charged to the
 * hook budget rather than to a test's own timeout.
 *
 * **A corpus is realistic on the axes a READ is sensitive to, or it measures
 * the wrong store.** Four of them, and every one has cost a wrong number:
 * `spacingMs` (density — at 1 s a million events span 11.6 days, so a 30-day
 * window holds the whole store and a windowed read costs what an unwindowed one
 * does), `findingRate` (three of `/security`'s reads are linear in findings
 * rather than events), whether a finding carries a `finding_key` (every read
 * that branches on trackability returns nothing without one, while still
 * running and still reporting a plan), and `resolutionRate` (an empty
 * `finding_resolution` is the cheapest path through the three reads that join
 * it). The first two are options with measured defaults; the third is not an
 * option at all, because the product decides it (see the note at the `findingKey`
 * assignment); the fourth is an option whose measured
 * default is zero, which is why a caller that needs it non-trivial has to say so.
 *
 * **It verifies what LANDED.** `recordCapture` is fail-open by design — a
 * locked, full or read-only store swallows the write and returns. A benchmark
 * has no assertions, so a generator that trusted its own calls would hand back
 * an EMPTY store and every downstream measurement would be a timing of nothing,
 * reported as a fast one. `generateCaptureCorpus` counts the rows it asked for
 * — capture events, findings, TRACKABLE findings and resolutions, four counts
 * because none of them implies another: a corpus can land every event and no
 * finding (a changed dedup key), every finding and no key (a dropped
 * `findingKey`), or every key and no resolution row (a second repository
 * writing to a table with no foreign key onto findings). Each of those leaves a
 * different read measuring nothing while still reporting a number. All four
 * throw rather than warn.
 *
 * Determinism means no ambient entropy: no `Math.random`, no `randomUUID`, no
 * `Date.now`. Ids come from the seeded PRNG and timestamps from a fixed epoch,
 * so two runs of the same options produce identical bytes. That reaches through
 * `SqliteResolutionsRepository` too, which mints an id and stamps `created_at`
 * on every write — both are constructor seams, and this module supplies both
 * rather than letting either default fire.
 *
 * One axis is deliberately NOT modelled, and the gap is stated rather than
 * papered over: `KINDS` is sampled uniformly, so about a quarter of captures are
 * `code_change` and therefore about a quarter of findings are trackable. The
 * real store measured ~40% (2,149 of 5,410), because findings do not land evenly
 * across event kinds there. Fitting per-kind rates to one install would be
 * over-fitting a sample of one; what these reads are sensitive to is that
 * trackable findings are a MINORITY of a known size, which holds either way.
 *
 * TEST AND BENCHMARK FIXTURES ONLY, like the rest of this directory. It is
 * reached from `test/helpers/corpus.ts` — by suites under `test/` and by the
 * benchmarks alike — and never by shipped code.
 */
import type { DatabaseSync } from 'node:sqlite';

import type { DetectedFinding, EventKind, IngestEvent, SourceTool } from '@akasecurity/schema';
import { SOURCE_TOOL } from '@akasecurity/schema';
import { CAPTURE_EVENT_TYPES_SQL } from '@akasecurity/schema';

import { withTransaction } from '../internal/transactions.ts';
import { SqliteResolutionsRepository } from '../repositories/resolutions.ts';

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
  /**
   * Milliseconds between consecutive events. Defaults to
   * `CORPUS_EVENT_SPACING_MS`.
   *
   * This is the corpus's DENSITY, and for any windowed read it is as
   * load-bearing as the event count. At the 1 s default a million events span
   * 11.6 days, so a 30-day window contains the whole store and a windowed
   * aggregation costs the same as an unwindowed one — which flatters nothing,
   * but does mean the measurement no longer describes a real install. Real
   * usage spreads a million events over months or years. Set this when the
   * property under test is what a windowed read costs.
   */
  readonly spacingMs?: number;
  /**
   * Fraction (0..1) of TRACKABLE findings that also carry a
   * `finding_resolution` row. Defaults to `DEFAULT_RESOLUTION_RATE`.
   *
   * Only a trackable finding can have one: the lifecycle is keyed by
   * `finding_key`, and an in-flight finding has none (see the invariant note at
   * the `findingKey` assignment below). So this is a fraction of the trackable
   * subset, not of every finding.
   *
   * It exists because `finding_resolution` being EMPTY is not a neutral
   * starting point for a measurement — it is the cheapest path through three
   * of `/security`'s reads. `severitySummary`'s caught/open-at-rest buckets,
   * `mttrTrend` and `recentlyResolved` all read the latest resolution per key,
   * and the derived table they read it through
   * (`LATEST_RESOLUTION_BY_KEY_SQL`) is materialized and sorted per call. On an
   * empty table all of that is free, so a corpus with no resolutions measures
   * those three reads on an input no store carrying resolution history
   * presents. A measurement that needs them non-trivial passes a rate here and
   * says why.
   */
  readonly resolutionRate?: number;
}

export interface GeneratedCaptureCorpus {
  readonly seed: number;
  /** Capture events that landed — asserted equal to the requested count. */
  readonly events: number;
  readonly sessions: number;
  /** Findings that landed — asserted equal to the number generated. */
  readonly findings: number;
  /**
   * Of `findings`, how many carry a `finding_key` — asserted on disk.
   *
   * Reported separately because it is the number three of `/security`'s reads
   * are actually linear in, and it is NOT derivable from `findings` and a
   * rate: which findings are trackable follows from the event kind they landed
   * on, which the seeded stream chooses.
   */
  readonly trackableFindings: number;
  /** `finding_resolution` rows that landed — asserted equal to the number generated. */
  readonly resolutions: number;
  /**
   * The instant just past the last generated event, in epoch milliseconds.
   *
   * The clock a windowed read must be driven with. Deriving it caller-side from
   * the two constants below is the same arithmetic written a sixth time, and a
   * copy that stops matching the generator is invisible: the reads still run,
   * still return a plan, and match nothing.
   */
  readonly endsAt: number;
  /** Milliseconds between consecutive events, as used. */
  readonly spacingMs: number;
}

const DEFAULT_SEED = 1;
const DEFAULT_SESSIONS = 50;

/**
 * Findings per capture event.
 *
 * MEASURED, not chosen. Read off a real `~/.aka/data/aka.db` with 16,390
 * capture events carrying 5,410 findings on them — 0.330 — as counts only, no
 * content. That is a single install and a heavy one (its operator develops the
 * detection rules, so it detects more than a typical user would), so read it as
 * an upper-ish bound on a real rate rather than a population mean. It is still
 * the only number here taken from a real store rather than picked, and it is
 * the axis the reads that dominate `/security` are linear in.
 *
 * The value it replaced was 0.1. Anything sizing work against this constant
 * should re-measure rather than trusting the figure to have aged well — a rate
 * is a property of how a user works, and one install cannot establish it.
 */
const DEFAULT_FINDING_RATE = 0.33;

/**
 * Of the trackable findings, how many carry a resolution row.
 *
 * MEASURED at 0 — the same real store holds 24,492 findings, 2,149 of them
 * trackable, and ZERO `finding_resolution` rows, because nothing writes that
 * table until a user runs the at-rest remediation flow. So the honest default
 * is the empty table.
 *
 * That makes the default corpus the cheap path for the three resolution-reading
 * aggregations, which is exactly the trap `resolutionRate` exists to let a
 * caller step out of. Deliberately NOT defaulted to a made-up non-zero rate:
 * this repository does not state an estimated number as a measured one, and a
 * plausible-looking constant here would be read as realism by everything
 * downstream. A measurement that needs the resolution join to cost something
 * passes an explicit rate and states that as its reason.
 */
const DEFAULT_RESOLUTION_RATE = 0;

/** Deterministic file paths for `code_change` captures — a repo's worth of files, reused. */
const CORPUS_FILE_COUNT = 400;

/**
 * A fixed epoch for every generated timestamp: 2024-01-01T00:00:00.000Z.
 *
 * Not `Date.now()`. A corpus whose timestamps move with the wall clock is a
 * corpus whose date-windowed reads return a different row count every day,
 * which turns a query benchmark's own input into a variable.
 *
 * Exported because every windowed read driven against a corpus has to be given
 * this clock rather than the wall clock, and a consumer that spells the literal
 * itself is a copy that goes stale silently — the reads keep running and match
 * nothing. Prefer `GeneratedCaptureCorpus.endsAt`, which is this applied to the
 * corpus actually written.
 */
export const CORPUS_EPOCH_MS = 1_704_067_200_000;

/** One second between consecutive events — dense enough that a large corpus stays inside a plausible window. */
export const CORPUS_EVENT_SPACING_MS = 1_000;

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

/**
 * `sessionIds[index]`, with the in-bounds invariant CHECKED rather than
 * asserted away.
 *
 * `sessions >= 1` is enforced before the loop, so `i % sessions` always indexes
 * an element and this can only throw if that guard is removed — at which point
 * throwing is the right answer. The two shorter spellings are both worse: a
 * non-null assertion is banned outright here, and a `??` fallback reads as
 * defensive while being the opposite, since any arm that drew a fresh guid
 * would consume from the PRNG mid-loop and desynchronise the stream every
 * determinism claim in this file rests on.
 */
function sessionAt(sessionIds: readonly string[], index: number): string {
  const id = sessionIds[index];
  if (id === undefined) {
    throw new RangeError(`generateCaptureCorpus: no session at index ${String(index)}`);
  }
  return id;
}

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
const TOOLS: SourceTool[] = [
  SOURCE_TOOL.ClaudeCode,
  SOURCE_TOOL.Codex,
  SOURCE_TOOL.Antigravity,
  SOURCE_TOOL.Cli,
];

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
  const spacingMs = options.spacingMs ?? CORPUS_EVENT_SPACING_MS;
  const resolutionRate = options.resolutionRate ?? DEFAULT_RESOLUTION_RATE;

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
  if (!Number.isInteger(spacingMs) || spacingMs < 1) {
    throw new TypeError(
      `generateCaptureCorpus: spacingMs must be a positive integer, got ${String(spacingMs)}`,
    );
  }
  if (!Number.isInteger(seed)) {
    throw new TypeError(`generateCaptureCorpus: seed must be an integer, got ${String(seed)}`);
  }
  // `Number.isFinite` first, and it is not belt-and-braces: NaN fails BOTH
  // comparisons, so a range check alone admits it. It then makes every
  // `rng() < findingRate` false and the corpus carries no findings at all —
  // silently, which is the one outcome this whole module exists to refuse.
  if (!Number.isFinite(findingRate) || findingRate < 0 || findingRate > 1) {
    throw new RangeError(
      `generateCaptureCorpus: findingRate must be a finite number within 0..1, got ${String(findingRate)}`,
    );
  }
  // Same `Number.isFinite` first, same reason: NaN fails both comparisons, so a
  // bare range check admits it and then makes every `rng() < resolutionRate`
  // false — a corpus silently carrying no resolutions, which is the input this
  // option exists to stop a measurement being taken on.
  if (!Number.isFinite(resolutionRate) || resolutionRate < 0 || resolutionRate > 1) {
    throw new RangeError(
      `generateCaptureCorpus: resolutionRate must be a finite number within 0..1, got ${String(resolutionRate)}`,
    );
  }

  const rng = createSeededRandom(seed);

  // Session ids are drawn FIRST and reused, so the same seed produces the same
  // session set whatever the event count is — a 10k corpus is the 1k corpus
  // plus more events in the same sessions, which is what makes two scales
  // comparable.
  const sessionIds = Array.from({ length: sessions }, () => seededGuid(rng));

  const baseline = countCaptureEvents(target.connection);
  const findingsBaseline = countFindings(target.connection);
  const trackableBaseline = countTrackableFindings(target.connection);
  const resolutionsBaseline = countResolutions(target.connection);
  let generated = 0;
  let generatedResolutions = 0;
  // The trackable keys THIS call minted, which is not the same set as the
  // trackable keys on disk — see `landedTrackableFindings`.
  const mintedKeys = new Set<string>();

  // Resolutions go through the product's own writer, like the captures — see
  // this module's header. Both of its entropy seams are supplied so the rows
  // stay byte-identical run to run: the id from the seeded stream, and
  // `created_at` from the corpus clock rather than the wall clock. Constructed
  // outside the transaction because its constructor only prepares statements.
  const resolutions = new SqliteResolutionsRepository(
    target.connection,
    () => CORPUS_EPOCH_MS,
    () => seededGuid(rng),
  );

  withTransaction(target.connection, () => {
    for (let i = 0; i < events; i += 1) {
      const sessionId = sessionAt(sessionIds, i % sessions);
      const kind = KINDS[Math.floor(rng() * KINDS.length)] ?? 'prompt';
      // Only a code_change capture carries one, which is what the product does
      // and what makes its findings trackable. It is also half of captureId's
      // content-addressing and the key of the partial index
      // `idx_audit_code_change_path`, so a corpus that left it null would drive
      // the at-rest path reads against an index holding nothing.
      const filePath =
        kind === 'code_change'
          ? `src/module-${String(Math.floor(rng() * CORPUS_FILE_COUNT))}.ts`
          : undefined;
      const occurredAtMs = CORPUS_EPOCH_MS + i * spacingMs;
      const event: IngestEvent = {
        id: seededGuid(rng),
        sourceTool: TOOLS[Math.floor(rng() * TOOLS.length)] ?? SOURCE_TOOL.ClaudeCode,
        kind,
        occurredAt: new Date(occurredAtMs).toISOString(),
        // The capture row is content-addressed on (sessionId, contentHash,
        // filePath), so a shared hash would collapse every event in a session
        // onto ONE row and the corpus would silently be `sessions` rows deep
        // however many events were asked for. The index makes it unique by
        // construction rather than by luck.
        contentHash: `corpus-${String(seed)}-${String(i)}`,
        content: seededText(rng, CONTENT_CHARS),
        metadata: { sessionId, ...(filePath === undefined ? {} : { filePath }) },
      };

      const detected: DetectedFinding[] = [];
      if (rng() < findingRate) {
        // TRACKABLE EXACTLY WHEN THE PRODUCT WOULD MAKE IT SO, which is why the
        // condition is `filePath` and not a knob. `@akasecurity/plugin-sdk`'s
        // runtime sets `isAtRest = kind === 'code_change' && filePath !== undefined`
        // and keys those findings and no others; here only a `code_change` capture
        // is given a path, so the two conditions coincide. Confirmed against the
        // real store, where the split is exact — every one of its 2,149
        // `code_change` findings carries a key, and all 22,343 findings on every
        // other event type carry none.
        //
        // A corpus free to key an in-flight finding could produce a store no
        // product path can write, and every read branching on
        // `finding_key IS NOT NULL` would then be measured against a shape that
        // cannot occur — so this deliberately has no option governing it.
        //
        // The key's VALUE is opaque to every read (all of them test it for null or
        // join on it), so it comes from the seeded stream rather than being
        // recomputed with the plugin's own hash, which sits behind a package wall
        // this one may not cross.
        const findingKey =
          filePath === undefined ? undefined : `corpus-key-${String(seed)}-${String(i)}`;
        detected.push({
          id: seededGuid(rng),
          eventId: event.id,
          ruleId: 'secrets/aws-access-key',
          category: 'secret',
          severity: 'critical',
          span: { start: 0, end: 8 },
          ...(findingKey === undefined ? {} : { findingKey }),
          // Half the finding-level session dedup key. A constant here would
          // make every finding after the first in a session land as zero rows
          // BY DESIGN, so the corpus would carry `sessions` findings whatever
          // the rate said — the same trap `test/helpers/capture-fixtures.ts`
          // documents, at corpus scale.
          maskedMatch: `A***${String(i)}`,
          actionTaken: 'block',
          confidence: 0.9,
        });
        generated += 1;
        if (findingKey !== undefined) mintedKeys.add(findingKey);
      }

      target.recordCapture(event, detected);
    }

    // Resolutions are written from the keys that LANDED, read back out of the
    // store, rather than from the keys the loop above asked for. That is the
    // same argument as the two count checks below, applied to the selection
    // rather than to the tally: recordCapture is fail-open and drops a finding
    // that trips either dedup gate, so a rate applied to the REQUESTED keys
    // would write resolution rows against keys with no finding — orphans no
    // product path can produce, and ones that would then be invisible to every
    // read here, since all of them reach resolutions THROUGH a finding.
    //
    // Still inside the enclosing transaction: this is thousands of inserts at
    // corpus scale, and the per-commit flush is what this module's header
    // explains it cannot afford.
    if (resolutionRate > 0) {
      for (const row of landedTrackableFindings(target.connection, mintedKeys)) {
        if (rng() >= resolutionRate) continue;
        // Resolved AFTER first detection, by a spread of the corpus's own
        // spacing. MTTR is `resolved_at - first_detected_at` and the read clamps
        // a negative to zero, so a resolution stamped before its detection would
        // be counted as an instant fix rather than rejected — a wrong number,
        // not a missing one.
        const resolvedAt = row.first_detected_at + Math.floor(rng() * 30 * spacingMs) + spacingMs;
        resolutions.insertResolution({
          findingKey: row.finding_key,
          status: 'resolved',
          method: 'fixed-at-source',
          resolvedAt,
          evidence: 'corpus',
        });
        generatedResolutions += 1;
      }
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

  // Findings are counted the same way and for the same reason. The event check
  // above says nothing about them: a change to the finding-level dedup key, or
  // a fail-open swallow on that insert, leaves every capture row in place and
  // every finding gone — and the returned tally, if it were the generator's own
  // count of what it ASKED for, would report the corpus as complete.
  const findings = countFindings(target.connection) - findingsBaseline;
  if (findings !== generated) {
    throw new Error(
      `generateCaptureCorpus wrote ${String(findings)} findings, expected ${String(generated)}. ` +
        'recordCapture is fail-open and its finding-level dedup key is (ruleId, maskedMatch, ' +
        'sessionId) — a corpus that lost its findings measures a different store from the one asked for.',
    );
  }

  // Trackable findings and resolutions get their own checks for the same reason
  // the two above exist, and they are not implied by either. The findings tally
  // says nothing about how many carry a key: drop `findingKey` from the insert
  // and every finding still lands, while three of `/security`'s reads quietly
  // go back to matching nothing. And a resolution row is written through a
  // second repository against a table with no foreign key onto findings, so
  // every one of them could fail to land with the findings check still green.
  const trackableFindings = countTrackableFindings(target.connection) - trackableBaseline;
  if (trackableFindings !== mintedKeys.size) {
    throw new Error(
      `generateCaptureCorpus wrote ${String(trackableFindings)} trackable findings, expected ` +
        `${String(mintedKeys.size)}. A finding is trackable exactly when its capture is a ` +
        'code_change carrying a file path; a corpus with none measures every finding_key read ' +
        'against an empty result.',
    );
  }
  const resolutionsWritten = countResolutions(target.connection) - resolutionsBaseline;
  if (resolutionsWritten !== generatedResolutions) {
    throw new Error(
      `generateCaptureCorpus wrote ${String(resolutionsWritten)} resolutions, expected ` +
        `${String(generatedResolutions)}. The three reads that join finding_resolution are at ` +
        'their cheapest against an empty table, so a corpus that lost them reports those reads ' +
        'as fast rather than as unmeasured.',
    );
  }

  return {
    seed,
    events: landed,
    sessions,
    findings,
    trackableFindings,
    resolutions: resolutionsWritten,
    endsAt: CORPUS_EPOCH_MS + events * spacingMs,
    spacingMs,
  };
}

/**
 * Trackable findings on disk — those carrying a `finding_key`.
 *
 * No event-type predicate, deliberately. The product only ever keys a
 * `code_change` finding, so a key appearing on any other kind is a defect this
 * count must SEE rather than filter out.
 */
function countTrackableFindings(connection: DatabaseSync): number {
  const row = connection
    .prepare('SELECT COUNT(*) AS c FROM inspection_findings WHERE finding_key IS NOT NULL')
    .get() as { c: number } | undefined;
  return row?.c ?? 0;
}

/** `finding_resolution` rows on disk. */
function countResolutions(connection: DatabaseSync): number {
  const row = connection.prepare('SELECT COUNT(*) AS c FROM finding_resolution').get() as
    { c: number } | undefined;
  return row?.c ?? 0;
}

/**
 * The trackable findings THIS call minted that actually landed, with each one's
 * preserved first-detection time, in a deterministic order.
 *
 * Read from the store rather than from the loop — the point of the read is to
 * see what survived `recordCapture`'s dedup gates — but intersected with
 * `minted`, and the intersection is load-bearing rather than tidiness. The
 * generator is ADDITIVE by design (`adds to a store that already holds a corpus
 * rather than counting it twice`), so a bare read returns every trackable
 * finding in the store, including every earlier corpus's. A second
 * `seedCaptureCorpus(db, { resolutionRate: r })` would then write resolutions
 * against keys it never created, and the landed-row check could not see it: that
 * check is a DELTA, and rows written for older keys land inside the delta just
 * the same. Measured before this filter existed — a second 1,000-event corpus
 * added 76 trackable findings and wrote 148 resolutions, 72 of them against the
 * first corpus's keys, and reported success.
 *
 * Ordered by `finding_key` rather than by rowid: the selection walks this
 * consuming from the seeded stream per row, so the order decides WHICH keys get
 * a resolution. A rowid order is insertion order, which is stable today and is
 * not a property SQLite promises, whereas the key is unique and self-ordering.
 */
function landedTrackableFindings(
  connection: DatabaseSync,
  minted: ReadonlySet<string>,
): { finding_key: string; first_detected_at: number }[] {
  const rows = connection
    .prepare(
      `SELECT f.finding_key AS finding_key,
              COALESCE(f.first_detected_at, e.started_at) AS first_detected_at
         FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
        WHERE f.finding_key IS NOT NULL
        ORDER BY f.finding_key`,
    )
    .all() as { finding_key: string; first_detected_at: number }[];
  return rows.filter((r) => minted.has(r.finding_key));
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

/** Findings rows, for the landed-findings check above. */
function countFindings(connection: DatabaseSync): number {
  const row = connection.prepare(`SELECT COUNT(*) AS c FROM inspection_findings`).get() as
    { c: number } | undefined;
  return row?.c ?? 0;
}
