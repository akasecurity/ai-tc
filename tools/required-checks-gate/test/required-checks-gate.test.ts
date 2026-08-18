import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  annotations,
  buildSummary,
  compare,
  GateConfigError,
  type GateIo,
  type GateRow,
  isFailure,
  parseGateTable,
  parsePrResponse,
  parseRollupResponse,
  prCandidatesQuery,
  type PrNode,
  readRollup,
  type RollupContext,
  rollupQuery,
  runGate,
  selectPr,
} from '../src/lib.ts';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

const table = (...rows: string[]): string =>
  [
    '### Checks that gate `main`',
    '',
    '| Check | Workflow | Enforced |',
    '| --- | --- | --- |',
    ...rows,
    '',
    '```bash',
    'gh api graphql …',
    '```',
  ].join('\n');

const row = (check: string, file = 'ci.yml', mark = '✅'): string =>
  `| \`${check}\` | \`${file}\` | ${mark} |`;

const gateRow = (check: string, enforced: boolean): GateRow => ({
  check,
  file: 'ci.yml',
  enforced,
});

describe('parseGateTable', () => {
  it('reads the check, the workflow and the enforced mark', () => {
    expect(parseGateTable(table(row('A'), row('B', 'audit.yml', '⛔')))).toEqual([
      { check: 'A', file: 'ci.yml', enforced: true },
      { check: 'B', file: 'audit.yml', enforced: false },
    ]);
  });

  // The vacuity guard, and the reason it throws rather than returning []. Every
  // comparison below is over set membership, so an empty intended set satisfies
  // all of them at once: nothing is missing from a pin of nothing, so the job
  // would report a clean bill of health having read no table at all.
  it('refuses a section it cannot find rather than reporting no rows', () => {
    expect(() => parseGateTable('# CONTRIBUTING\n\nnothing here\n')).toThrow(GateConfigError);
  });

  it('refuses a section whose rows do not parse', () => {
    expect(() => parseGateTable(table('| not | a | row |'))).toThrow(GateConfigError);
  });

  // A mark nobody recognises is a configuration error, not a `false`. Read as
  // "not enforced" it would silently downgrade a row that says the opposite —
  // and a downgraded row is exactly what stops this gate failing on a
  // regression.
  it('refuses an unrecognised enforced mark', () => {
    expect(() => parseGateTable(table(row('A', 'ci.yml', '?')))).toThrow(/neither/);
  });

  // The real file, so the shipped table and the reader cannot drift apart.
  it('reads the repository’s own table', () => {
    const rows = parseGateTable(readFileSync(`${REPO_ROOT}/CONTRIBUTING.md`, 'utf8'));
    expect(rows).toHaveLength(8);
    expect(rows.filter((r) => r.enforced).map((r) => r.check)).toEqual([
      'Lint · Typecheck · Test · Build',
      'Windows · Unit tests (shipped surface)',
    ]);
  });
});

describe('readRollup', () => {
  it('reads both context shapes', () => {
    const live = readRollup([
      { name: 'a-check-run', isRequired: true },
      { context: 'a-status-context', isRequired: false },
    ]);
    expect(live.get('a-check-run')).toBe('required');
    expect(live.get('a-status-context')).toBe('not-required');
  });

  // Keying an unnamed context on `undefined` would collide every one of them
  // onto a single entry, and that entry's state is then whichever came last.
  it('skips a context carrying no name at all', () => {
    expect(readRollup([{ isRequired: true }]).size).toBe(0);
  });

  // A rerun can report the same name twice. `required` has to win, because the
  // other order reports a regression that is not one — and this gate's whole
  // value is that its red means something.
  it('lets required win over a duplicate that says otherwise', () => {
    expect(
      readRollup([
        { name: 'dup', isRequired: true },
        { name: 'dup', isRequired: false },
      ]).get('dup'),
    ).toBe('required');
  });
});

describe('compare', () => {
  it('is quiet when the live set matches the record exactly', () => {
    const drift = compare(
      [gateRow('kept', true), gateRow('pending', false)],
      readRollup([
        { name: 'kept', isRequired: true },
        { name: 'pending', isRequired: false },
      ]),
    );
    expect(isFailure(drift)).toBe(false);
    expect(drift.outstanding.map((r) => r.check)).toEqual(['pending']);
  });

  // THE regression this gate exists for: protection matches by name, so a
  // renamed job stops being required with nothing in any diff to review.
  it('fails when a check recorded as enforced is no longer required', () => {
    const drift = compare(
      [gateRow('kept', true)],
      readRollup([{ name: 'kept', isRequired: false }]),
    );
    expect(drift.noLongerRequired.map((r) => r.check)).toEqual(['kept']);
    expect(isFailure(drift)).toBe(true);
  });

  // The good direction, and it fails on purpose. A floor would stay green here
  // and let the public record go stale — which is the defect the per-row column
  // replaced, returning by another door.
  it('fails when a check became required and the record still says otherwise', () => {
    const drift = compare(
      [gateRow('pending', false)],
      readRollup([{ name: 'pending', isRequired: true }]),
    );
    expect(drift.newlyRequired).toEqual(['pending']);
    expect(drift.outstanding).toEqual([]);
    expect(isFailure(drift)).toBe(true);
  });

  // Absent is not "not required". A job that did not run on the PR being read
  // contributes no context, and reading that as a regression would redden the
  // job for a path-filtered workflow.
  it('separates a check that reported nothing from one reported as not required', () => {
    const drift = compare([gateRow('kept', true)], readRollup([]));
    expect(drift.notReported.map((r) => r.check)).toEqual(['kept']);
    expect(drift.noLongerRequired).toEqual([]);
    // Still a failure — it is unread, not read as fine.
    expect(isFailure(drift)).toBe(true);
  });

  // A required check the table never listed is a different edit from a row that
  // needs its mark flipped, so it is reported separately: told to flip a row,
  // the reader goes looking for one that does not exist.
  it('names a required check the table does not list at all', () => {
    const drift = compare(
      [gateRow('kept', true)],
      readRollup([
        { name: 'kept', isRequired: true },
        { name: 'surprise', isRequired: true },
      ]),
    );
    expect(drift.untabled).toEqual(['surprise']);
    expect(drift.newlyRequired).toEqual([]);
    expect(isFailure(drift)).toBe(true);
  });

  // The state this ships in, and the one thing that must NOT fail. Six rows are
  // honestly not required yet and cannot be fixed from a PR; failing on them
  // would make this a permanently red job, which is a job people mute.
  it('does not fail on rows that are recorded as not enforced and are not', () => {
    const drift = compare(
      [gateRow('a', false), gateRow('b', false)],
      readRollup([
        { name: 'a', isRequired: false },
        { name: 'b', isRequired: false },
      ]),
    );
    expect(isFailure(drift)).toBe(false);
    expect(drift.outstanding).toHaveLength(2);
  });
});

describe('buildSummary', () => {
  it('names the PR it read, so a stale answer can be traced to its source', () => {
    const drift = compare([gateRow('a', false)], readRollup([{ name: 'a', isRequired: false }]));
    expect(buildSummary(drift, 284)).toContain('PR #284');
  });

  it('tells the reader to flip the row when a check became required', () => {
    const drift = compare([gateRow('a', false)], readRollup([{ name: 'a', isRequired: true }]));
    const summary = buildSummary(drift, 1);
    expect(summary).toContain('Newly enforced');
    expect(summary).toContain('`a`');
    expect(summary).toContain('CONTRIBUTING.md');
  });

  // The regression summary has to name the cause, because the cause is not
  // visible anywhere else: nothing in the diff that renamed the job says the
  // check stopped gating.
  it('names the rename as the likely cause when a check stops being required', () => {
    const drift = compare([gateRow('a', true)], readRollup([{ name: 'a', isRequired: false }]));
    expect(buildSummary(drift, 1)).toContain('renamed job');
  });

  it('says the outstanding rows are not a regression', () => {
    const drift = compare([gateRow('a', false)], readRollup([{ name: 'a', isRequired: false }]));
    expect(buildSummary(drift, 1)).toContain('Not a regression');
  });
});

// The PR the live set is read from. Getting this wrong is not a silent wrong
// answer — it is a loud one, since a PR that reported nothing makes every check
// look unreported, which this gate fails on.
describe('selectPr', () => {
  const pr = (number: number, ...contexts: RollupContext[]): PrNode => ({
    number,
    commits: {
      nodes: [{ commit: { statusCheckRollup: { contexts: { nodes: contexts } } } }],
    },
  });

  // The input is oldest-first — the only order the connection offers — so the
  // search runs from the end. Reading it forwards would answer with the OLDEST
  // pull request, whose checks may predate the workflow being asked about.
  it('takes the newest that covers what was asked for', () => {
    const chosen = selectPr(
      [pr(1, { name: 'a' }), pr(2, { name: 'a' }), pr(3, { name: 'a' })],
      ['a'],
    );
    expect(chosen?.number).toBe(3);
  });

  it('skips a newer pull request that reported no checks', () => {
    const chosen = selectPr([pr(1, { name: 'a' }), pr(2)], ['a']);
    expect(chosen?.number).toBe(1);
  });

  // THE daily flake this argument exists for. `flag-major`
  // (dependabot-major-guard.yml) SKIPS on an ordinary PR and reports within
  // seconds, while the five CI jobs take minutes — so a PR opened just before
  // the cron offers exactly one context. The old `contexts.length > 0` test
  // selected it, and every tabled check then read as `not-reported`, which
  // `isFailure` treats as drift.
  it('skips a newer pull request whose rollup is PARTIAL, not merely empty', () => {
    const partial = pr(9, { name: 'flag-major' });
    const complete = pr(4, { name: 'flag-major' }, { name: 'Lint' }, { name: 'Windows' });
    expect(selectPr([complete, partial], ['Lint', 'Windows'])?.number).toBe(4);
  });

  // Finding none is not drift. Comparing against a partial rollup would report
  // a regression that did not happen, so the caller exits on the
  // could-not-read path instead.
  it('finds nothing when no candidate covers the whole table', () => {
    expect(selectPr([pr(1, { name: 'flag-major' })], ['Lint'])).toBeUndefined();
  });

  it('skips one whose rollup is null rather than empty', () => {
    const nullRollup: PrNode = {
      number: 9,
      commits: { nodes: [{ commit: { statusCheckRollup: null } }] },
    };
    expect(selectPr([pr(1, { name: 'a' }), nullRollup], ['a'])?.number).toBe(1);
  });

  // Distinguished from "the newest reported nothing": the caller exits on the
  // could-not-read path rather than comparing against an empty live set, which
  // would report every enforced row as a regression.
  it('finds nothing when no candidate reported a check', () => {
    expect(selectPr([pr(1), pr(2)], ['a'])).toBeUndefined();
    expect(selectPr([], ['a'])).toBeUndefined();
  });
});

describe('parsePrResponse', () => {
  it('reads the pull requests out of a gh response', () => {
    const body = JSON.stringify({
      data: { repository: { pullRequests: { nodes: [{ number: 7, commits: { nodes: [] } }] } } },
    });
    expect(parsePrResponse(body).map((p) => p.number)).toEqual([7]);
  });

  // An empty list is a legible state — a repository with no pull requests — so
  // a failed parse must not produce one. It would exit on the could-not-read
  // path naming the wrong cause, and the real fault (a changed response shape,
  // an auth failure printing JSON) would never be named.
  it('refuses a body it cannot read rather than reporting no pull requests', () => {
    expect(() => parsePrResponse('not json')).toThrow(/did not return JSON/);
    expect(() => parsePrResponse('{"data":{}}')).toThrow(/carried no pull requests/);
  });

  it('reads an genuinely empty list as empty', () => {
    const body = JSON.stringify({ data: { repository: { pullRequests: { nodes: [] } } } });
    expect(parsePrResponse(body)).toEqual([]);
  });
});

describe('the two queries', () => {
  // `isRequired` is the whole point — the other three endpoints mislead a
  // non-admin — and it is one token in a long string, so it is worth pinning.
  // It takes the PR number as an explicit argument on BOTH context shapes.
  it('asks for isRequired, by explicit number, on both context shapes', () => {
    const query = rollupQuery('akasecurity', 'ai-tc', 284);
    expect(query).toContain('... on CheckRun{name isRequired(pullRequestNumber:284)}');
    expect(query).toContain('... on StatusContext{context isRequired(pullRequestNumber:284)}');
  });

  // Why there are two queries at all, pinned so nobody merges them back. The
  // field cannot refer to its enclosing node's number, so asking for it inside
  // the connection fails the WHOLE query — "A pull request ID or pull request
  // number is required", once per node — rather than degrading.
  it('does not ask for isRequired in the candidates query, which cannot supply a number', () => {
    expect(prCandidatesQuery('akasecurity', 'ai-tc', 10)).not.toContain('isRequired');
  });

  // `last` with an ASCENDING sort is the newest N; `first` with the same sort
  // is the OLDEST N, and the gate would answer from pull requests years out of
  // date while looking exactly as healthy.
  it('asks for the newest candidates, not the oldest', () => {
    expect(prCandidatesQuery('o', 'r', 10)).toContain('pullRequests(last:10,');
    expect(prCandidatesQuery('o', 'r', 10)).toContain('orderBy:{field:CREATED_AT,direction:ASC}');
  });

  // `isRequired(pullRequestNumber:)` is answered against THAT pull request's own
  // base protection. A stacked PR based on a feature branch has an unprotected
  // base, so every context reads not-required — and both enforced rows would
  // land in `noLongerRequired` under the summary's confident, wrong headline
  // "the usual cause is a renamed job".
  it('restricts candidates to pull requests based on main', () => {
    expect(prCandidatesQuery('o', 'r', 10)).toContain('baseRefName:"main"');
  });
});

describe('parseRollupResponse', () => {
  const body = (rollup: unknown): string =>
    JSON.stringify({
      data: {
        repository: {
          pullRequest: { commits: { nodes: [{ commit: { statusCheckRollup: rollup } }] } },
        },
      },
    });

  it('reads the contexts out of a rollup response', () => {
    const contexts = parseRollupResponse(
      body({ contexts: { nodes: [{ name: 'a', isRequired: true }] } }),
    );
    expect(contexts).toEqual([{ name: 'a', isRequired: true }]);
  });

  // More at stake here than in the candidates parse: an empty list compares
  // against a table whose every enforced row then reads as `not-reported`, so a
  // silent [] turns a parse failure into a report that two checks stopped
  // gating — a false alarm about the exact thing this gate exists to detect.
  it('refuses a body it cannot read rather than reporting no contexts', () => {
    expect(() => parseRollupResponse('not json')).toThrow(/did not return JSON/);
    expect(() => parseRollupResponse('{"data":{}}')).toThrow(/no commit/);
    expect(() => parseRollupResponse(body(null))).toThrow(/no check rollup/);
  });
});

describe('annotations', () => {
  it('emits one line per drift finding and none for outstanding rows', () => {
    const clean = compare([gateRow('a', false)], readRollup([{ name: 'a', isRequired: false }]));
    expect(annotations(clean)).toEqual([]);

    const drifted = compare(
      [gateRow('kept', true), gateRow('pending', false)],
      readRollup([
        { name: 'kept', isRequired: false },
        { name: 'pending', isRequired: true },
        { name: 'surprise', isRequired: true },
      ]),
    );
    expect(annotations(drifted)).toHaveLength(3);
    expect(annotations(drifted).join('\n')).toContain('kept');
    expect(annotations(drifted).join('\n')).toContain('surprise');
  });
});

// Regression from the xhigh review of this change: a row the strict pattern
// cannot read used to be SKIPPED, so the check it names vanished from the
// comparison while the job still reported a clean match and exited 0.
describe('a table row this reader cannot parse', () => {
  it('is refused, not silently dropped', () => {
    const withEmptyCell = table(row('A'), '| `No-network · Full suite` | `ci.yml` |  |');
    expect(() => parseGateTable(withEmptyCell)).toThrow(GateConfigError);
    expect(() => parseGateTable(withEmptyCell)).toThrow(/2 rows but only 1 parsed/);
  });

  // The positive control on the counter: a healthy table must still parse, and
  // the header and separator rows must not be counted as content.
  it('leaves a well-formed table alone', () => {
    expect(parseGateTable(table(row('A'), row('B', 'audit.yml', '⛔')))).toHaveLength(2);
  });
});

// ReDoS guards for the two patterns CodeQL flagged (alerts 38 and 39), in the
// ratio shape this repository uses: same work at two sizes, fastest of several
// runs. A ratio cancels the runner and the fastest sample is the one load
// cannot inflate; an absolute budget would redden a healthy tree on a preempted
// CI sample.
describe('parseGateTable is linear in its input', () => {
  const fastest = (input: string): number =>
    Math.min(
      ...Array.from({ length: 5 }, () => {
        const started = process.hrtime.bigint();
        try {
          parseGateTable(input);
        } catch {
          // Both witnesses are malformed on purpose — the refusal is the point,
          // and what is being measured is how long reaching it takes.
        }
        return Number(process.hrtime.bigint() - started) / 1e6;
      }),
    );

  // CodeQL's witness for the section slice: the heading repeated, never closed
  // by a fence. The lazy `([\s\S]*?)```bash` form measured 67x for 8x input.
  it('finds the section without rescanning from every heading', () => {
    const witness = (reps: number): string =>
      '### Checks that gate `main`' + '### Checks that gate `main`a'.repeat(reps);
    expect(fastest(witness(16_000)) / fastest(witness(2_000))).toBeLessThan(25);
  });

  // CodeQL's witness for the row counter: a pipe then a long run of spaces. The
  // `(?!\s*[-: ]+\|)` form measured 54x, because a space matches both `\s` and
  // the `[-: ]` class that immediately follows it.
  it('counts row-like lines without backtracking on a run of spaces', () => {
    const witness = (reps: number): string =>
      '### Checks that gate `main`\n|' + ' '.repeat(reps) + '\n```bash';
    expect(fastest(witness(16_000)) / fastest(witness(2_000))).toBeLessThan(25);
  });

  // The positive control on both: the real table still parses to its real rows,
  // so a reader that started refusing everything would not satisfy the ratios
  // above by being uniformly fast.
  it('still reads the repository’s own table', () => {
    expect(parseGateTable(readFileSync(`${REPO_ROOT}/CONTRIBUTING.md`, 'utf8'))).toHaveLength(8);
  });
});

// The orchestration, driven through the seam rather than through `gh`. The four
// exit codes and the messages behind them are decisions, and while they lived
// in the entry file beside a spawnSync nothing could reach them.
describe('runGate', () => {
  const RECORD = table(row('kept'), row('pending', 'ci.yml', '⛔'));

  const rollupFor = (contexts: RollupContext[]): string =>
    JSON.stringify({
      data: {
        repository: {
          pullRequest: {
            commits: {
              nodes: [{ commit: { statusCheckRollup: { contexts: { nodes: contexts } } } }],
            },
          },
        },
      },
    });
  const candidatesFor = (number: number): string =>
    JSON.stringify({
      data: {
        repository: {
          pullRequests: {
            nodes: [
              {
                number,
                commits: {
                  nodes: [
                    // Must COVER the table, or selectPr correctly skips this
                    // candidate — the behaviour the partial-rollup cases pin.
                    {
                      commit: {
                        statusCheckRollup: {
                          contexts: { nodes: [{ name: 'kept' }, { name: 'pending' }] },
                        },
                      },
                    },
                  ],
                },
              },
            ],
          },
        },
      },
    });

  const drive = (
    overrides: Partial<GateIo> & { contexts?: RollupContext[] } = {},
  ): { code: number; printed: string[]; summaries: string[] } => {
    const printed: string[] = [];
    const summaries: string[] = [];
    let call = 0;
    const io: GateIo = {
      readRecord: () => RECORD,
      graphql: () => (call++ === 0 ? candidatesFor(7) : rollupFor(overrides.contexts ?? [])),
      print: (line) => printed.push(line),
      appendSummary: (text) => summaries.push(text),
      ...overrides,
    };
    return { code: runGate(io, 'o', 'r', 10), printed, summaries };
  };

  it('exits 0 and writes the summary when the live set matches the record', () => {
    const { code, printed, summaries } = drive({
      contexts: [
        { name: 'kept', isRequired: true },
        { name: 'pending', isRequired: false },
      ],
    });
    expect(code).toBe(0);
    expect(printed.join('\n')).toContain(
      'Required checks match the record: 1 enforced, 1 outstanding.',
    );
    // The step summary is the only place a maintainer reads this, so a run that
    // decided something must have written one.
    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toContain('# Required checks');
  });

  it('exits 1 and annotates when a check stopped being required', () => {
    const { code, printed } = drive({
      contexts: [
        { name: 'kept', isRequired: false },
        { name: 'pending', isRequired: false },
      ],
    });
    expect(code).toBe(1);
    expect(printed.some((l) => l.startsWith('::error::') && l.includes('kept'))).toBe(true);
  });

  // 3, not 2: a malformed record is deterministic, and retrying it changes
  // nothing. The distinction is the whole reason the codes are separate.
  it('exits 3 on a record it cannot parse', () => {
    const { code, printed } = drive({ readRecord: () => 'no table here' });
    expect(code).toBe(3);
    expect(printed[0]).toContain('::error::');
  });

  it('exits 2 when the API cannot be read at all', () => {
    const { code, printed } = drive({
      graphql: () => {
        throw new Error('gh api graphql failed: 502');
      },
    });
    expect(code).toBe(2);
    expect(printed.join('\n')).toContain('could not read the required-check state');
  });

  // Distinct from the throw above: the query succeeded and simply found nothing
  // usable, which must not be read as "no checks are required".
  it('exits 2 when no recent pull request covers the table', () => {
    const { code, printed } = drive({
      graphql: () => JSON.stringify({ data: { repository: { pullRequests: { nodes: [] } } } }),
    });
    expect(code).toBe(2);
    expect(printed.join('\n')).toContain('reported every check in the table');
  });
});

// The three report branches the earlier cases never reached.
describe('buildSummary branches', () => {
  it('explains a check that reported nothing at all', () => {
    const drift = compare([gateRow('kept', true)], readRollup([]));
    const summary = buildSummary(drift, 1);
    expect(summary).toContain('was not reported');
    expect(summary).toContain('Re-run against a PR where every workflow ran');
    expect(annotations(drift).join('\n')).toContain('reported no check to read');
  });

  it('tells the reader to add a row for a required check the table omits', () => {
    const drift = compare(
      [gateRow('kept', true)],
      readRollup([
        { name: 'kept', isRequired: true },
        { name: 'surprise', isRequired: true },
      ]),
    );
    expect(buildSummary(drift, 1)).toContain('Required but not in the table');
  });

  it('says so plainly when everything in the table is required and nothing else is', () => {
    const drift = compare(
      [gateRow('kept', true)],
      readRollup([{ name: 'kept', isRequired: true }]),
    );
    expect(buildSummary(drift, 1)).toContain('Every check in the table is required');
  });
});

// From the human review of this PR: the gate must not compare against a rollup
// that cannot answer for the whole table.
describe('runGate against a partial rollup', () => {
  it('exits 2 rather than reporting drift it cannot substantiate', () => {
    const printed: string[] = [];
    // Only `flag-major` has reported — the shape a PR opened a minute before
    // the cron really has, since that job skips and the CI jobs take minutes.
    const candidates = JSON.stringify({
      data: {
        repository: {
          pullRequests: {
            nodes: [
              {
                number: 7,
                commits: {
                  nodes: [
                    {
                      commit: {
                        statusCheckRollup: { contexts: { nodes: [{ name: 'flag-major' }] } },
                      },
                    },
                  ],
                },
              },
            ],
          },
        },
      },
    });
    const io: GateIo = {
      readRecord: () => table(row('kept'), row('pending', 'ci.yml', '⛔')),
      graphql: () => candidates,
      print: (line) => printed.push(line),
      appendSummary: () => undefined,
    };
    expect(runGate(io, 'o', 'r', 10)).toBe(2);
    expect(printed.join('\n')).toContain('reported every check in the table');
    // And emphatically NOT the drift wording, which would be a wrong diagnosis.
    expect(printed.join('\n')).not.toContain('does not require them');
  });
});
