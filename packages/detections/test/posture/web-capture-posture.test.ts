import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { WebCaptureStatus } from '@akasecurity/schema';
import { WebCaptureStatus as WebCaptureStatusSchema } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  deriveWebCaptureState,
  DRIFT_MIN_PARSE_FAILURES,
  WEB_CAPTURE_DRIFT_RULE,
  WEB_CAPTURE_DRIFT_STATES,
  webCaptureDriftFires,
  type WebCaptureState,
  webCaptureStateCopy,
} from '../../src/posture/web-capture-posture.ts';
import { expectFixtureBar, MIN_FIXTURES_PER_POLARITY } from '../helpers/fixture-bar.ts';

const fixturesDir = join(
  fileURLToPath(new URL('.', import.meta.url)),
  '../../src/posture/fixtures',
);

interface FixtureCase {
  label: string;
  shouldMatch: boolean;
  status: WebCaptureStatus;
}

function loadFixtures(): FixtureCase[] {
  return JSON.parse(
    readFileSync(join(fixturesDir, 'web-capture-drift.json'), 'utf8'),
  ) as FixtureCase[];
}

const cases = loadFixtures();
const rule = WEB_CAPTURE_DRIFT_RULE;

describe('fixtures: web-capture-drift', () => {
  it(`has at least ${String(MIN_FIXTURES_PER_POLARITY)} positive and ${String(
    MIN_FIXTURES_PER_POLARITY,
  )} negative cases`, () => {
    expectFixtureBar('web-capture-drift', cases, (c) => JSON.stringify(c.status));
  });

  it.each(cases.map((c) => [c.label, c] as const))('%s', (_label, c) => {
    const status = WebCaptureStatusSchema.parse(c.status);
    expect(webCaptureDriftFires(status)).toBe(c.shouldMatch);
  });
});

describe('deriveWebCaptureState — the false-signal proof', () => {
  it('a machine where no endpoint is declared never fires, however loud the tab is', () => {
    // Every OTHER signal reads exactly like the worst possible drift: blind,
    // parse failures over the threshold, and shape misses recorded. The one
    // thing that must stop this from firing is conversationEndpoints === 0.
    const status: WebCaptureStatus = {
      conversationEndpoints: 0,
      patched: true,
      live: false,
      blind: true,
      sendsSeenDom: 9,
      exchangesSeenNet: 0,
      parseFailures: 7,
      unparsedBodies: 0,
      shapeMisses: ['a', 'b'],
      closed: false,
    };
    expect(deriveWebCaptureState(status)).toBe('standby');
    expect(webCaptureDriftFires(status)).toBe(false);
  });
});

describe('deriveWebCaptureState — exhaustive state table', () => {
  const base: WebCaptureStatus = {
    conversationEndpoints: 1,
    patched: true,
    live: false,
    blind: false,
    sendsSeenDom: 0,
    exchangesSeenNet: 0,
    parseFailures: 0,
    unparsedBodies: 0,
    shapeMisses: [],
    closed: false,
  };

  // Annotated Record<WebCaptureState, ...> so a state added to the vocabulary
  // fails to compile here until it is named — the §2 convention applied to a
  // vocabulary of one member each.
  const STATES: Record<WebCaptureState, WebCaptureStatus | undefined> = {
    unreported: undefined,
    standby: { ...base, conversationEndpoints: 0 },
    unpatched: { ...base, patched: false },
    blind: { ...base, blind: true },
    degraded: { ...base, shapeMisses: ['x'] },
    idle: { ...base, live: false },
    active: { ...base, live: true },
  };

  it.each(Object.keys(STATES) as WebCaptureState[])('derives %s from its own status', (state) => {
    expect(deriveWebCaptureState(STATES[state])).toBe(state);
  });
});

describe('deriveWebCaptureState — precedence', () => {
  const base: WebCaptureStatus = {
    conversationEndpoints: 1,
    patched: true,
    live: true,
    blind: false,
    sendsSeenDom: 0,
    exchangesSeenNet: 0,
    parseFailures: 0,
    unparsedBodies: 0,
    shapeMisses: [],
    closed: false,
  };

  it('blind beats a non-empty shapeMisses', () => {
    expect(deriveWebCaptureState({ ...base, blind: true, shapeMisses: ['x'] })).toBe('blind');
  });

  it('a non-empty shapeMisses beats parseFailures at the threshold', () => {
    expect(
      deriveWebCaptureState({
        ...base,
        shapeMisses: ['x'],
        parseFailures: DRIFT_MIN_PARSE_FAILURES,
      }),
    ).toBe('degraded');
  });

  it('unpatched beats blind', () => {
    expect(deriveWebCaptureState({ ...base, patched: false, blind: true })).toBe('unpatched');
  });
});

describe('the parse-failure threshold', () => {
  const base: WebCaptureStatus = {
    conversationEndpoints: 1,
    patched: true,
    live: true,
    blind: false,
    sendsSeenDom: 0,
    exchangesSeenNet: 0,
    parseFailures: 0,
    unparsedBodies: 0,
    shapeMisses: [],
    closed: false,
  };

  it('one parse failure is not drift', () => {
    expect(deriveWebCaptureState({ ...base, parseFailures: DRIFT_MIN_PARSE_FAILURES - 1 })).toBe(
      'active',
    );
  });

  it('the threshold itself is drift', () => {
    expect(deriveWebCaptureState({ ...base, parseFailures: DRIFT_MIN_PARSE_FAILURES })).toBe(
      'degraded',
    );
  });
});

describe('the rule definition', () => {
  it('is category config with a parseable definition naming the drift states', () => {
    expect(rule.category).toBe('config');
    const definition = JSON.parse(rule.definition) as { states: string[] };
    expect(definition.states).toEqual([...WEB_CAPTURE_DRIFT_STATES]);
  });
});

// Annotated Record<WebCaptureState, true> for its KEYS: the vocabulary is
// restated nowhere, so a state added to it fails to compile here until it is
// named, and the copy assertions below then cover it. A hand-written array
// would leave a new state unchecked — and `remediation` is optional on
// WebCaptureStateCopy, so STATIC_COPY's own Record forces an entry for a new
// state but not a fix string, which is what the CLI prints under the rule id.
const ALL_STATES = Object.keys({
  unreported: true,
  standby: true,
  unpatched: true,
  blind: true,
  degraded: true,
  active: true,
  idle: true,
} satisfies Record<WebCaptureState, true>) as WebCaptureState[];

describe('state copy', () => {
  it('every drift state has remediation copy and no other state does', () => {
    for (const state of ALL_STATES) {
      const hasRemediation = webCaptureStateCopy(state).remediation !== undefined;
      expect(hasRemediation).toBe(WEB_CAPTURE_DRIFT_STATES.has(state));
    }
  });

  it('every state has its own headline', () => {
    // Pairwise distinct and non-empty: the CLI prints the headline as the
    // whole of what a state means, so two states sharing one, or a blank one,
    // is a state the user cannot act on. Distinctness rather than exact
    // strings, so rewording copy stays a copy edit.
    const headlines = ALL_STATES.map((state) => webCaptureStateCopy(state).headline);
    for (const headline of headlines) expect(headline.length).toBeGreaterThan(0);
    expect(new Set(headlines).size).toBe(ALL_STATES.length);
  });

  it('does not assert the tap installed in the state that says it did not patch', () => {
    // `patched` is false for a tap that installed and hooked neither transport
    // AND for one that never ran; the report is identical, so the copy must
    // not claim the first.
    expect(webCaptureStateCopy('unpatched').headline).not.toContain('tap installed');
  });

  it('does not quote a turn count it cannot keep current', () => {
    // The stored count is only as current as the report that carried it, and
    // the bridge relays on a TRANSITION rather than per turn — so once a tab
    // is live nothing moves the signature again and this headline used to
    // print "1 turn observed" for a session of fifty. `exchangesSeenNet` is
    // still on the stored status for a surface that wants it as of that
    // report; the headline no longer states it as a total.
    const headline = webCaptureStateCopy('active').headline;
    expect(headline).not.toMatch(/[0-9]/);
    expect(headline).not.toContain('turn observed');
    // And it still says the thing a reader needs: capture is working here.
    expect(headline).toContain('observed');
  });
});
