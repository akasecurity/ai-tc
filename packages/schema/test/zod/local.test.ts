import { describe, expect, it } from 'vitest';

import type { AttachmentMode } from '../../src/zod/control-plane.ts';
import type { ResolvedAttachmentScope } from '../../src/zod/local.ts';
import {
  ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH,
  AttachmentScope,
  AttachmentScopeEntry,
  canSweepSyncLane,
  controlPlaneName,
  defaultWorkspaceSettings,
  HISTORY_SYNC_PAYLOAD_VERSION,
  isAttached,
  isAttachmentScopeValid,
  isHistorySyncConsentStale,
  isHistorySyncConsentValid,
  isModelJudgeConsentValid,
  isWebChatCaptureConsentValid,
  MODEL_JUDGE_PAYLOAD_VERSION,
  parseAttachmentScope,
  resolveScope,
  scopeFilterOf,
  scopeVerdict,
  toEventRow,
  toFindingRow,
  WEB_CHAT_CAPTURE_CONSENT_VERSION,
  WebChatCapture,
  webChatCaptureOf,
  WORKSPACE_SETTINGS_SPEC_VERSION,
  WorkspaceSettings,
} from '../../src/zod/local.ts';

const EVENT = '00000000-0000-0000-0000-0000000000d4';
const FINDING = '00000000-0000-0000-0000-0000000000e5';
const ISO = '2026-06-18T00:00:00.000Z';

describe('WorkspaceSettings (versioned, default-filled)', () => {
  it('fills defaults for an empty object so older/missing files stay valid', () => {
    const s = WorkspaceSettings.parse({});
    expect(s).toMatchObject({
      specVersion: WORKSPACE_SETTINGS_SPEC_VERSION,
      runMode: 'standalone',
      policy: 'redact',
      // Historical scanning is opt-in — defaults to session-only, never an
      // assumed grant for a settings.json written before the field existed.
      historicalAccess: 'session-only',
    });
    // onboardedAt is absent until /aka:setup completes — that absence is "not onboarded"
    expect(s.onboardedAt).toBeUndefined();
  });

  it('pins the settings spec version, so moving it is a decision rather than a side effect', () => {
    // The case above compares through the constant, so it stays green whatever
    // the constant says: reverting the bump for the attachment scope would pass
    // it. The version is a changelog marker that nothing reads, which is exactly
    // why a change to it needs a test that names the number. The next field that
    // bumps it changes this literal on purpose.
    expect(WORKSPACE_SETTINGS_SPEC_VERSION).toBe(9);
  });

  it('enables in-place Data Shares extraction by default', () => {
    expect(WorkspaceSettings.parse({}).dataSharesInPlace).toBe(true);
  });

  it('round-trips the Data Shares kill-switch when explicitly disabled', () => {
    expect(WorkspaceSettings.parse({ dataSharesInPlace: false }).dataSharesInPlace).toBe(false);
    expect(WorkspaceSettings.safeParse({ dataSharesInPlace: 'nope' }).success).toBe(false);
  });

  it('defaultWorkspaceSettings() equals the parsed defaults', () => {
    expect(defaultWorkspaceSettings()).toEqual(WorkspaceSettings.parse({}));
  });

  it('leaves modelJudgeConsent absent by default (opt-in, never assumed)', () => {
    expect(WorkspaceSettings.parse({}).modelJudgeConsent).toBeUndefined();
  });

  it('round-trips a valid modelJudgeConsent and rejects a malformed one', () => {
    const consent = { acknowledgedAt: ISO, payloadVersion: 1 };
    expect(WorkspaceSettings.parse({ modelJudgeConsent: consent }).modelJudgeConsent).toEqual(
      consent,
    );
    // payloadVersion must be a positive integer; acknowledgedAt an ISO datetime.
    expect(
      WorkspaceSettings.safeParse({ modelJudgeConsent: { acknowledgedAt: ISO, payloadVersion: 0 } })
        .success,
    ).toBe(false);
    expect(
      WorkspaceSettings.safeParse({
        modelJudgeConsent: { acknowledgedAt: 'not-a-date', payloadVersion: 1 },
      }).success,
    ).toBe(false);
  });

  it('accepts a fully onboarded file and rejects unknown enum values', () => {
    expect(
      WorkspaceSettings.safeParse({
        runMode: 'standalone',
        policy: 'warn',
        historicalAccess: 'full',
        onboardedAt: ISO,
      }).success,
    ).toBe(true);
    expect(WorkspaceSettings.safeParse({ runMode: 'nope' }).success).toBe(false);
    expect(WorkspaceSettings.safeParse({ policy: 'delete' }).success).toBe(false);
    expect(WorkspaceSettings.safeParse({ historicalAccess: 'partial' }).success).toBe(false);
  });

  it('accepts both run modes and still rejects an unknown one', () => {
    expect(WorkspaceSettings.parse({}).runMode).toBe('standalone');
    expect(WorkspaceSettings.parse({ runMode: 'attached' }).runMode).toBe('attached');
    // A typo is still an error — the enum was widened, not opened.
    expect(WorkspaceSettings.safeParse({ runMode: 'atached' }).success).toBe(false);
  });

  it('attached means nothing without a descriptor', () => {
    // The mode alone can be set by a hand edit or an interrupted attach.
    // Reporting that as attached would show a connection that does not exist
    // and offer a detach that clears nothing.
    expect(isAttached(WorkspaceSettings.parse({ runMode: 'attached' }))).toBe(false);
    expect(isAttached(WorkspaceSettings.parse({ runMode: 'standalone' }))).toBe(false);
    const attached = WorkspaceSettings.parse({
      runMode: 'attached',
      controlPlane: { endpoint: 'https://aka.example.internal', attachedAt: ISO },
    });
    expect(isAttached(attached)).toBe(true);
  });

  it('a descriptor without the mode is not attached either', () => {
    // The reverse half: a stale descriptor left behind by a failed detach must
    // not resurrect the attachment.
    const s = WorkspaceSettings.parse({
      runMode: 'standalone',
      controlPlane: { endpoint: 'https://aka.example.internal', attachedAt: ISO },
    });
    expect(isAttached(s)).toBe(false);
  });

  it('controlPlaneName prefers the label and falls back to the endpoint', () => {
    expect(controlPlaneName({ endpoint: 'https://x.internal', attachedAt: ISO })).toBe(
      'https://x.internal',
    );
    expect(
      controlPlaneName({ endpoint: 'https://x.internal', label: 'Acme Prod', attachedAt: ISO }),
    ).toBe('Acme Prod');
  });
});

describe('row mappers (tenant-free local store)', () => {
  it('toEventRow converts ISO->epoch, JSON-encodes metadata, and carries no tenant/user', () => {
    const row = toEventRow({
      id: EVENT,
      sourceTool: 'claude-code',
      kind: 'prompt',
      occurredAt: ISO,
      contentHash: 'hash',
      content: 'a prompt',
      metadata: { sessionId: 'sess-1' },
    });
    expect(row).toMatchObject({
      id: EVENT,
      sourceTool: 'claude-code',
      kind: 'prompt',
      occurredAt: Date.parse(ISO),
      contentHash: 'hash',
      content: 'a prompt',
    });
    expect(row.metadata).toBe(JSON.stringify({ sessionId: 'sess-1' }));
    // The OSS local store is tenant-free — the row must not carry tenant/user.
    expect(row).not.toHaveProperty('tenantId');
    expect(row).not.toHaveProperty('userId');
  });

  it('toEventRow leaves metadata null when absent', () => {
    const row = toEventRow({
      id: EVENT,
      sourceTool: 'claude-code',
      kind: 'prompt',
      occurredAt: ISO,
      contentHash: 'hash',
      content: 'a prompt',
    });
    expect(row.metadata).toBeNull();
  });

  it('toFindingRow splits the span, carries no tenant, and never carries a raw match', () => {
    const row = toFindingRow({
      id: FINDING,
      eventId: EVENT,
      ruleId: 'secrets.aws-access-key',
      category: 'secret',
      severity: 'critical',
      span: { start: 3, end: 9 },
      maskedMatch: 'AKIA****',
      actionTaken: 'block',
      confidence: 0.99,
    });
    expect(row).toMatchObject({
      id: FINDING,
      eventId: EVENT,
      ruleId: 'secrets.aws-access-key',
      category: 'secret',
      severity: 'critical',
      spanStart: 3,
      spanEnd: 9,
      maskedMatch: 'AKIA****',
      actionTaken: 'block',
      confidence: 0.99,
    });
    expect(row).not.toHaveProperty('tenantId');
    // The findings table has no raw column; nothing here should resemble one.
    expect(JSON.stringify(row)).not.toContain('rawMatch');
  });

  it('toFindingRow carries a supplied findingKey through, and coerces an absent one to null (never undefined)', () => {
    const base = {
      id: FINDING,
      eventId: EVENT,
      ruleId: 'secrets.aws-access-key',
      category: 'secret',
      severity: 'critical',
      span: { start: 3, end: 9 },
      maskedMatch: 'AKIA****',
      actionTaken: 'block',
      confidence: 0.99,
    } as const;

    const withKey = toFindingRow({ ...base, findingKey: 'a'.repeat(64) });
    expect(withKey.findingKey).toBe('a'.repeat(64));

    const withoutKey = toFindingRow(base);
    expect(withoutKey.findingKey).toBeNull();
  });
});

// The judge gate, the CLI and the dashboard all decide "has the user consented?"
// through this one predicate, so they cannot drift into disagreeing — the failure
// mode being a settings page that shows "Granted" for a consent the judge is
// already treating as revoked.
describe('isModelJudgeConsentValid', () => {
  const consentAt = (payloadVersion: number) => ({
    acknowledgedAt: ISO,
    payloadVersion,
  });

  it('is false when no consent has been recorded', () => {
    expect(isModelJudgeConsentValid(undefined)).toBe(false);
  });

  it('is true when the consent covers the current payload version', () => {
    expect(isModelJudgeConsentValid(consentAt(MODEL_JUDGE_PAYLOAD_VERSION))).toBe(true);
  });

  // A grant given for a narrower payload must not silently authorize a wider one:
  // bumping the version is how a payload change re-asks the user.
  it('is false for a consent recorded against an older payload version', () => {
    expect(isModelJudgeConsentValid(consentAt(MODEL_JUDGE_PAYLOAD_VERSION - 1))).toBe(false);
  });

  it('is false for a consent recorded against an unknown newer version', () => {
    expect(isModelJudgeConsentValid(consentAt(MODEL_JUDGE_PAYLOAD_VERSION + 1))).toBe(false);
  });

  it('accepts what the schema actually parses out of a settings.json', () => {
    const parsed = WorkspaceSettings.parse({
      modelJudgeConsent: { acknowledgedAt: ISO, payloadVersion: MODEL_JUDGE_PAYLOAD_VERSION },
    });
    expect(isModelJudgeConsentValid(parsed.modelJudgeConsent)).toBe(true);
  });
});

// Shared by both history-sync predicates below. One definition rather than two:
// `isHistorySyncConsentStale` is specified against `isHistorySyncConsentValid`
// (a strict subset of its falsity), so a second, drifting fixture would let the
// two suites disagree about what the same grant IS while both stayed green.
const ENDPOINT = 'https://plane.example.com';
const consent = (payloadVersion: number, endpoint = ENDPOINT) => ({
  acknowledgedAt: ISO,
  payloadVersion,
  endpoint,
});

describe('isHistorySyncConsentValid', () => {
  it('is false when no consent has been recorded', () => {
    expect(isHistorySyncConsentValid(undefined, ENDPOINT)).toBe(false);
  });

  // A grant names the deployment it was given for, so an unattached machine has
  // nothing to compare against and sends nothing.
  it('is false when the machine is not attached to any endpoint', () => {
    expect(isHistorySyncConsentValid(consent(HISTORY_SYNC_PAYLOAD_VERSION), undefined)).toBe(false);
  });

  it('is true when the consent covers the current payload and this endpoint', () => {
    expect(isHistorySyncConsentValid(consent(HISTORY_SYNC_PAYLOAD_VERSION), ENDPOINT)).toBe(true);
  });

  // Widening what is sent must re-ask rather than ride an older, narrower grant.
  it('is false for a consent recorded against an older payload version', () => {
    expect(isHistorySyncConsentValid(consent(HISTORY_SYNC_PAYLOAD_VERSION - 1), ENDPOINT)).toBe(
      false,
    );
  });

  it('is false for a consent recorded against an unknown newer version', () => {
    expect(isHistorySyncConsentValid(consent(HISTORY_SYNC_PAYLOAD_VERSION + 1), ENDPOINT)).toBe(
      false,
    );
  });

  // Consent to send history to one deployment is not consent to send it to
  // another: re-attaching elsewhere asks again.
  it('is false when the grant names a different deployment', () => {
    const granted = consent(HISTORY_SYNC_PAYLOAD_VERSION, 'https://other.example.com');
    expect(isHistorySyncConsentValid(granted, ENDPOINT)).toBe(false);
  });

  it('accepts what the schema actually parses out of a settings.json', () => {
    const parsed = WorkspaceSettings.parse({
      historySyncConsent: {
        acknowledgedAt: ISO,
        payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
        endpoint: ENDPOINT,
      },
    });
    expect(isHistorySyncConsentValid(parsed.historySyncConsent, ENDPOINT)).toBe(true);
  });
});

// Staleness is what a settings surface offers to heal in ONE save. It is a
// strict subset of invalidity, and the gap between the two is the whole point:
// an invalid grant naming another deployment must never be offered as a
// re-consent, because accepting would start sending this machine's activity
// somewhere the user never chose.
// A TRIPWIRE, not a tautology, and the distinction is the point.
//
// Every other test in this file is written RELATIVE to the constant
// (`HISTORY_SYNC_PAYLOAD_VERSION - 1`, `+ 1`), which is correct for testing the
// predicates and useless for guarding a bump: the whole suite stays green when
// the number changes. That is not hypothetical — it is exactly how v1 shipped
// with no guard tying it to what it discloses, and the sibling model-judge
// consent grew a real payload-derived guard (plugins/claude-code's
// FOOTNOTE_DISCLOSURE, keyed on TriageHit.shape) only after a field crossed to
// the model API with the workspace fully green.
//
// The disclosure here has no single Zod shape to derive from — it is four pieces
// of hand-written prose in three packages — so this pins the literal instead and
// makes the failure message carry the checklist. Bumping the constant WILL fail
// this test; the fix is to re-read every surface below, confirm each still
// describes what the new payload sends, and then update the number here.
//
//   cli/src/commands/attach.ts        askAboutHistory — the grant prompt
//   cli/src/commands/sync-history.ts  grant/revoke/describe output
//   packages/dashboard-ui/src/settings/WorkspaceSettingsFormView.tsx
//                                     HISTORY_SYNC_SECTION_DESCRIPTION,
//                                     HISTORY_SYNC_CHOICES,
//                                     HISTORY_SYNC_STALE_NOTICE
//   packages/plugin-runtime/src/attached/status.ts
//                                     historyLines — what `aka status` prints,
//                                     including the paused-grant branch
//   README.md                         the [^egress] footnote
//   SECURITY.md                       the "Data in transit" section's
//                                     sync-history paragraph — pinned by no
//                                     other test; at-rest-docs.test.ts scopes
//                                     to "## Data at rest" and
//                                     privacy-claims.test.ts reads only the
//                                     three READMEs
//
// v2 widened the subject from the pre-attach backlog to everything the machine
// still owes its deployment, which brought CAPTURE rows — and their prompt,
// reply and tool-result TEXT — inside the grant for the first time.
//
// v3 widens it again, inside that same scope: through v2 a pre-attach capture
// could never be marked owed at all, because `outbox_owed` was set only by a
// live forward that ran while attached. v3 adds the other writer of that
// marker — a one-time backfill, run once from each grant site at the instant
// consent is given, over what is already on disk — so the pre-attach backlog
// is no longer structural-only: it now carries the same prompt/reply/tool-
// result TEXT as an undelivered live send, masked by the same rule.
describe('the payload version and its disclosure move together', () => {
  it('fails on a bump so the copy gets re-read', () => {
    expect(HISTORY_SYNC_PAYLOAD_VERSION).toBe(3);
  });
});

describe('isHistorySyncConsentStale', () => {
  it('is false when no consent has been recorded', () => {
    expect(isHistorySyncConsentStale(undefined, ENDPOINT)).toBe(false);
  });

  it('is false when the machine is not attached to any endpoint', () => {
    expect(isHistorySyncConsentStale(consent(HISTORY_SYNC_PAYLOAD_VERSION - 1), undefined)).toBe(
      false,
    );
  });

  // The healable case: same deployment, older payload.
  it('is true for an older payload recorded against this same deployment', () => {
    expect(isHistorySyncConsentStale(consent(HISTORY_SYNC_PAYLOAD_VERSION - 1), ENDPOINT)).toBe(
      true,
    );
  });

  // A current grant is not stale — nothing to re-ask.
  it('is false for a grant that already covers the current payload', () => {
    expect(isHistorySyncConsentStale(consent(HISTORY_SYNC_PAYLOAD_VERSION), ENDPOINT)).toBe(false);
  });

  // THE SAFETY PROPERTY. Both clauses are wrong at once — old payload AND a
  // different deployment — and the endpoint must dominate. If this returned
  // true, a settings form would render "re-consent to keep sharing" for a grant
  // given to somebody else's deployment, and one save would honour it.
  it('is false when the grant names a different deployment, even with an old payload', () => {
    const elsewhere = consent(HISTORY_SYNC_PAYLOAD_VERSION - 1, 'https://other.example.com');
    expect(isHistorySyncConsentStale(elsewhere, ENDPOINT)).toBe(false);
    // ...and it is invalid too, so it reads as no grant rather than as stale.
    expect(isHistorySyncConsentValid(elsewhere, ENDPOINT)).toBe(false);
  });

  it('is false for a current payload recorded against a different deployment', () => {
    const elsewhere = consent(HISTORY_SYNC_PAYLOAD_VERSION, 'https://other.example.com');
    expect(isHistorySyncConsentStale(elsewhere, ENDPOINT)).toBe(false);
  });

  // Staleness never overlaps validity: every grant is at most one of the two.
  it('is never true at the same time as validity', () => {
    for (const version of [
      HISTORY_SYNC_PAYLOAD_VERSION - 1,
      HISTORY_SYNC_PAYLOAD_VERSION,
      HISTORY_SYNC_PAYLOAD_VERSION + 1,
    ]) {
      for (const endpoint of [ENDPOINT, 'https://other.example.com']) {
        const c = consent(version, endpoint);
        expect(
          isHistorySyncConsentValid(c, ENDPOINT) && isHistorySyncConsentStale(c, ENDPOINT),
        ).toBe(false);
      }
    }
  });
});

// The browser extension's network capture records things nothing recorded
// before — per-turn model and token metadata, the tool calls a reply made, and
// the reply's own text — so it carries its own versioned grant rather than
// riding an existing one. Same rule as the vault and the model judge: the grant
// names the version it was given against, and a grant recorded against an older
// version stops counting.
describe('WebChatCapture', () => {
  it('is absent by default — recording is opt-in and never assumed on upgrade', () => {
    expect(WorkspaceSettings.parse({}).webChatCapture).toBeUndefined();
  });

  it('defaults a partial block to with-findings, no account data, and no grant', () => {
    // A settings.json carrying only the grant must still resolve the two modes,
    // or the reader that projects them has to invent its own defaults.
    const parsed = WebChatCapture.parse({});
    expect(parsed.responses).toBe('with-findings');
    expect(parsed.account).toBe(false);
    expect(parsed.consent).toBeUndefined();
  });

  it('round-trips a full block out of a settings.json', () => {
    const block = {
      responses: 'always' as const,
      account: false,
      consent: { acknowledgedAt: ISO, version: WEB_CHAT_CAPTURE_CONSENT_VERSION },
    };
    expect(WorkspaceSettings.parse({ webChatCapture: block }).webChatCapture).toEqual(block);
  });

  it('refuses a response mode outside the vocabulary', () => {
    // 'never' must stay distinguishable from an absent grant: it keeps the
    // per-turn metadata and drops the reply text, which is a different answer
    // from recording nothing at all.
    expect(WebChatCapture.safeParse({ responses: 'sometimes' }).success).toBe(false);
    expect(WebChatCapture.parse({ responses: 'never' }).responses).toBe('never');
  });

  it('refuses a malformed grant', () => {
    expect(
      WebChatCapture.safeParse({ consent: { acknowledgedAt: 'yesterday', version: 1 } }).success,
    ).toBe(false);
    expect(WebChatCapture.safeParse({ consent: { acknowledgedAt: ISO, version: 0 } }).success).toBe(
      false,
    );
  });
});

describe('webChatCaptureOf', () => {
  it('resolves the block in force when the file carries none', () => {
    // One definition of the defaults, so the settings writer, the form and the
    // recording gate cannot disagree about what an un-configured machine does.
    expect(webChatCaptureOf(WorkspaceSettings.parse({}))).toEqual(WebChatCapture.parse({}));
  });

  it('returns the stored block untouched when there is one', () => {
    const block = { responses: 'never' as const, account: false };
    expect(webChatCaptureOf(WorkspaceSettings.parse({ webChatCapture: block }))).toEqual(block);
  });
});

describe('isWebChatCaptureConsentValid', () => {
  const consentAt = (version: number) => ({ acknowledgedAt: ISO, version });

  it('is false when nothing has been granted', () => {
    expect(isWebChatCaptureConsentValid(undefined)).toBe(false);
  });

  it('is true for a grant recorded against the current version', () => {
    expect(isWebChatCaptureConsentValid(consentAt(WEB_CHAT_CAPTURE_CONSENT_VERSION))).toBe(true);
  });

  // Widening what is written down must re-ask rather than ride the older,
  // narrower grant.
  it('is false for a grant recorded against an older version', () => {
    expect(isWebChatCaptureConsentValid(consentAt(WEB_CHAT_CAPTURE_CONSENT_VERSION - 1))).toBe(
      false,
    );
  });

  it('is false for a grant recorded against an unknown newer version', () => {
    expect(isWebChatCaptureConsentValid(consentAt(WEB_CHAT_CAPTURE_CONSENT_VERSION + 1))).toBe(
      false,
    );
  });

  it('accepts what the schema actually parses out of a settings.json', () => {
    const parsed = WorkspaceSettings.parse({
      webChatCapture: {
        consent: { acknowledgedAt: ISO, version: WEB_CHAT_CAPTURE_CONSENT_VERSION },
      },
    });
    expect(isWebChatCaptureConsentValid(parsed.webChatCapture?.consent)).toBe(true);
  });
});

// A TRIPWIRE, for the reason the history-sync one beside it gives: every other
// case in this block is written RELATIVE to the constant, so the whole suite
// stays green when the number changes and nothing sends the author to re-read
// what the number is supposed to mean.
//
// Bumping this WILL fail this test. The fix is to re-read every surface below,
// confirm each still describes what is now recorded, and then update the number
// here.
//
//   packages/dashboard-ui/src/settings/WorkspaceSettingsFormView.tsx
//                                     WEB_CHAT_SECTION_DESCRIPTION,
//                                     WEB_CHAT_CHOICES,
//                                     WEB_CHAT_STALE_NOTICE
//
// A grant given against v1 covers per-turn model, token and tool metadata plus
// the assistant's reply text under the stored `responses` mode. Anything that
// widens that set — account and quota snapshots, request bodies, a mode that
// keeps more text — is a new version.
describe('the web-chat consent version and its disclosure move together', () => {
  it('fails on a bump so the copy gets re-read', () => {
    expect(WEB_CHAT_CAPTURE_CONSENT_VERSION).toBe(1);
  });
});

/**
 * The predicate standing between an attached machine and permanent loss of
 * undelivered bodies.
 *
 * Every caller supplies its answer as a boolean, so nothing else in the tree
 * executes the clauses that return FALSE — and false is the safe answer here.
 * Turning a `!==` into `===` or dropping the consent clause leaves the rest of
 * the suite green while an hourly detached pass starts clearing `prompt`,
 * `response` and `tool_use` bodies that a deployment is still owed.
 */
describe('canSweepSyncLane', () => {
  const base = defaultWorkspaceSettings();
  const connection = { endpoint: 'https://cp.example', attachedAt: '2026-01-01T00:00:00.000Z' };

  it('is true on a machine that has never attached and never granted', () => {
    expect(canSweepSyncLane(base)).toBe(true);
  });

  it('is false while attached', () => {
    expect(canSweepSyncLane({ ...base, runMode: 'attached', controlPlane: connection })).toBe(
      false,
    );
  });

  it('is false on a bare runMode with no descriptor', () => {
    // Half an attachment is not "not attached": `isAttached` needs both, and
    // this predicate is deliberately wider than `isAttached`.
    expect(canSweepSyncLane({ ...base, runMode: 'attached' })).toBe(false);
  });

  it('is false on a bare descriptor with no runMode', () => {
    expect(canSweepSyncLane({ ...base, controlPlane: connection })).toBe(false);
  });

  it('is false on a DETACHED machine that still holds a history-sync grant', () => {
    // The clause with no `isAttached` analogue, and the reason this predicate
    // exists rather than a call to that one. `aka sync-history --on` claims the
    // backlog retroactively with no age bound, so a grant outliving a detach
    // still owes those bodies.
    expect(
      canSweepSyncLane({
        ...base,
        historySyncConsent: {
          acknowledgedAt: '2026-01-01T00:00:00.000Z',
          payloadVersion: 3,
          endpoint: 'https://cp.example',
        },
      }),
    ).toBe(false);
  });
});

// Fixtures for the attachment-scope suites below. Identities are canonical repo
// keys (`host/owner/repo`), and every comparison on them is byte-for-byte.
const WORK_REPO = 'github.com/acme/work-repo';
const OTHER_WORK_REPO = 'github.com/acme/infra';
const PERSONAL_REPO = 'github.com/someone/dotfiles';
// Built at runtime so this file holds no raw control byte.
const ESC = String.fromCharCode(0x1b);

const scopeEntry = (identity: string, extra: Record<string, unknown> = {}) => ({
  kind: 'repo',
  identity,
  enrolledAt: ISO,
  ...extra,
});

const scopeFor = (endpoint: string, ...identities: string[]) => ({
  endpoint,
  entries: identities.map((identity) => scopeEntry(identity)),
});

// Garbled or future-shaped records. Each must cost nothing but itself.
const GARBLED_SCOPES: [string, unknown][] = [
  ['a string', 'not-a-scope'],
  ['a number', 42],
  ['null', null],
  ['an array', []],
  ['an envelope with a non-string endpoint', { endpoint: 7, entries: [] }],
  ['an envelope whose entries is not an array', { endpoint: ENDPOINT, entries: 'x' }],
  [
    'an envelope holding only a future-shaped entry',
    { endpoint: ENDPOINT, entries: [scopeEntry(WORK_REPO, { kind: 'org' })] },
  ],
];

describe('WorkspaceSettings.attachmentScope', () => {
  it('is absent by default, with no default to fill, so a fresh settings file is unchanged', () => {
    expect(WorkspaceSettings.parse({}).attachmentScope).toBeUndefined();
    expect(JSON.stringify(defaultWorkspaceSettings())).not.toContain('attachmentScope');
  });

  it('carries NO meta id — not on the field, not on either shape', () => {
    expect(WorkspaceSettings.shape.attachmentScope.meta()?.id).toBeUndefined();
    expect(AttachmentScope.meta()?.id).toBeUndefined();
    expect(AttachmentScopeEntry.meta()?.id).toBeUndefined();
  });

  it('round-trips a well-formed record untouched', () => {
    const scope = scopeFor(ENDPOINT, WORK_REPO);
    expect(WorkspaceSettings.parse({ attachmentScope: scope }).attachmentScope).toEqual(scope);
  });

  // The reason the field is untyped: a settings.json that fails this schema
  // reads as unonboarded defaults, and the next save writes those back.
  it.each(GARBLED_SCOPES)(
    'keeps every other setting, and the raw value, when the record is %s',
    (_label, raw) => {
      const file = {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: ISO },
        historySyncConsent: consent(HISTORY_SYNC_PAYLOAD_VERSION),
        onboardedAt: ISO,
        attachmentScope: raw,
      };
      const parsed = WorkspaceSettings.parse(file);
      expect(isAttached(parsed)).toBe(true);
      expect(parsed.controlPlane).toEqual(file.controlPlane);
      expect(parsed.historySyncConsent).toEqual(file.historySyncConsent);
      expect(parsed.onboardedAt).toBe(ISO);
      // Kept exactly as found, so the next save writes it back rather than losing it,
      expect(parsed.attachmentScope).toEqual(raw);
      // and it names nothing.
      expect(parseAttachmentScope(parsed.attachmentScope)?.entries ?? []).toEqual([]);
    },
  );
});

describe('AttachmentScopeEntry identity length', () => {
  const ofLength = (n: number) => scopeEntry('i'.repeat(n));

  it('is capped at 512 units, and the exported cap says so', () => {
    expect(ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH).toBe(512);
    expect(AttachmentScopeEntry.safeParse(ofLength(512)).success).toBe(true);
    expect(AttachmentScopeEntry.safeParse(ofLength(513)).success).toBe(false);
  });

  it('reads the exported cap rather than a copy of its value', () => {
    const cap = ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH;
    expect(AttachmentScopeEntry.safeParse(ofLength(cap)).success).toBe(true);
    expect(AttachmentScopeEntry.safeParse(ofLength(cap + 1)).success).toBe(false);
  });
});

describe('parseAttachmentScope', () => {
  const NOT_A_SCOPE: [string, unknown][] = [
    ['undefined', undefined],
    ['a string', 'not-a-scope'],
    ['a number', 42],
    ['null', null],
    ['an array', []],
    ['an envelope with no endpoint', { entries: [] }],
    ['an envelope with an empty endpoint', { endpoint: '', entries: [] }],
    ['an envelope with a non-string endpoint', { endpoint: 7, entries: [] }],
    ['an envelope with no entries', { endpoint: ENDPOINT }],
    [
      'an envelope whose entries is an object',
      { endpoint: ENDPOINT, entries: { 0: scopeEntry(WORK_REPO) } },
    ],
  ];

  it('reads a well-formed record', () => {
    const raw = {
      endpoint: ENDPOINT,
      entries: [
        scopeEntry(WORK_REPO, { label: 'Work repo' }),
        { kind: 'account', identity: 'claude:org-1234', enrolledAt: ISO },
      ],
    };
    expect(parseAttachmentScope(raw)).toEqual(raw);
  });

  it('reads an empty entry list as a valid, empty scope', () => {
    expect(parseAttachmentScope(scopeFor(ENDPOINT))).toEqual({ endpoint: ENDPOINT, entries: [] });
  });

  it('drops a bad entry by itself and keeps the rest', () => {
    const raw = {
      endpoint: ENDPOINT,
      entries: [
        scopeEntry(WORK_REPO),
        scopeEntry(PERSONAL_REPO, { kind: 'org' }), // an unknown kind
        scopeEntry(`${OTHER_WORK_REPO}${ESC}[2J`), // a control character in the identity
        scopeEntry(OTHER_WORK_REPO, { label: `Infra${ESC}[2J` }), // and in the label
        scopeEntry(OTHER_WORK_REPO, { enrolledAt: 'last tuesday' }), // a bad timestamp
        scopeEntry(''), // an empty identity
        'not-an-entry',
        null,
      ],
    };
    expect(parseAttachmentScope(raw)).toEqual({
      endpoint: ENDPOINT,
      entries: [scopeEntry(WORK_REPO)],
    });
  });

  it('strips an unknown key on an entry, such as a provenance marker, rather than refusing it', () => {
    const parsed = parseAttachmentScope({
      endpoint: ENDPOINT,
      entries: [scopeEntry(WORK_REPO, { source: 'org' })],
    });
    expect(parsed?.entries).toEqual([scopeEntry(WORK_REPO)]);
    expect(parsed?.entries[0]).not.toHaveProperty('source');
  });

  it('strips an unknown key on the envelope too, so a later field there does not break this reader', () => {
    expect(
      parseAttachmentScope({ endpoint: ENDPOINT, entries: [], builtFor: { org: 'Acme' } }),
    ).toEqual({ endpoint: ENDPOINT, entries: [] });
  });

  it.each(NOT_A_SCOPE)('reads %s as no scope at all', (_label, raw) => {
    expect(parseAttachmentScope(raw)).toBeUndefined();
  });

  it('never throws, even on a value whose properties throw', () => {
    const hostile = {
      get endpoint(): string {
        throw new Error('boom');
      },
      entries: [],
    };
    expect(parseAttachmentScope(hostile)).toBeUndefined();
  });
});

describe('isAttachmentScopeValid', () => {
  it('is true for a record built for this deployment', () => {
    expect(isAttachmentScopeValid(scopeFor(ENDPOINT, WORK_REPO), ENDPOINT)).toBe(true);
  });

  it('is true for an empty record built for this deployment', () => {
    expect(isAttachmentScopeValid(scopeFor(ENDPOINT), ENDPOINT)).toBe(true);
  });

  // Bound by value, like HistorySyncConsent: a scope built for one deployment is
  // not a scope for another.
  it('is false for a record built for a different deployment', () => {
    const elsewhere = scopeFor('https://other.example.com', WORK_REPO);
    expect(isAttachmentScopeValid(elsewhere, ENDPOINT)).toBe(false);
  });

  it('is false when the machine is not attached to any endpoint', () => {
    expect(isAttachmentScopeValid(scopeFor(ENDPOINT, WORK_REPO), undefined)).toBe(false);
  });

  it('is false when there is no record, or the record is not one', () => {
    expect(isAttachmentScopeValid(undefined, ENDPOINT)).toBe(false);
    expect(isAttachmentScopeValid('not-a-scope', ENDPOINT)).toBe(false);
    expect(isAttachmentScopeValid({ endpoint: ENDPOINT, entries: 'x' }, ENDPOINT)).toBe(false);
  });

  it('compares the endpoint exactly, the way the credential binding does', () => {
    expect(isAttachmentScopeValid(scopeFor(`${ENDPOINT}/`, WORK_REPO), ENDPOINT)).toBe(false);
  });

  it('accepts what the schema actually parses out of a settings.json', () => {
    const parsed = WorkspaceSettings.parse({ attachmentScope: scopeFor(ENDPOINT, WORK_REPO) });
    expect(isAttachmentScopeValid(parsed.attachmentScope, ENDPOINT)).toBe(true);
  });
});

describe('resolveScope and scopeVerdict — the forwarding verdict', () => {
  const scoped = (scope: unknown) => resolveScope({ mode: 'scoped', scope, endpoint: ENDPOINT });

  it('machine mode forwards every event, keyed or not, and reads no scope', () => {
    const machine = resolveScope({
      mode: 'machine',
      scope: scopeFor(ENDPOINT, WORK_REPO),
      endpoint: ENDPOINT,
    });
    expect(machine.mode).toBe('machine');
    expect(machine.keys.size).toBe(0);
    for (const key of [WORK_REPO, PERSONAL_REPO, '', undefined]) {
      expect(scopeVerdict(machine, key)).toBe('forward');
    }
  });

  it('machine mode forwards even with a garbled scope and no endpoint: the mode decides', () => {
    const machine = resolveScope({ mode: 'machine', scope: 'garbled', endpoint: undefined });
    expect(scopeVerdict(machine, undefined)).toBe('forward');
  });

  it('machine mode never reads the scope, however hostile it is', () => {
    // A scope whose every property throws when read and counts the attempt.
    // parseAttachmentScope swallows a throw, so a throw alone could not show that
    // resolveScope looked: the count does, and the throw covers a read that does
    // not go through that parser.
    let reads = 0;
    const hostile = {
      get endpoint(): unknown {
        reads += 1;
        throw new Error('boom');
      },
      get entries(): unknown {
        reads += 1;
        throw new Error('boom');
      },
    };
    const machine = resolveScope({ mode: 'machine', scope: hostile, endpoint: ENDPOINT });
    expect(machine.mode).toBe('machine');
    for (const key of [WORK_REPO, '', undefined]) {
      expect(scopeVerdict(machine, key)).toBe('forward');
    }
    expect(reads).toBe(0);
  });

  it('scoped mode forwards a key in scope', () => {
    const resolved = scoped(scopeFor(ENDPOINT, WORK_REPO, OTHER_WORK_REPO));
    expect(scopeVerdict(resolved, WORK_REPO)).toBe('forward');
    expect(scopeVerdict(resolved, OTHER_WORK_REPO)).toBe('forward');
  });

  it('scoped mode keeps a key out of scope local', () => {
    expect(scopeVerdict(scoped(scopeFor(ENDPOINT, WORK_REPO)), PERSONAL_REPO)).toBe('local');
  });

  it('scoped mode keeps an event with no key, or an empty key, local', () => {
    const resolved = scoped(scopeFor(ENDPOINT, WORK_REPO));
    expect(scopeVerdict(resolved, undefined)).toBe('local');
    expect(scopeVerdict(resolved, '')).toBe('local');
  });

  it('compares keys byte-for-byte: path case is part of the identity', () => {
    const resolved = scoped(scopeFor(ENDPOINT, WORK_REPO));
    expect(scopeVerdict(resolved, 'github.com/Acme/Work-Repo')).toBe('local');
  });

  it('an empty scope keeps everything local', () => {
    expect(scopeVerdict(scoped(scopeFor(ENDPOINT)), WORK_REPO)).toBe('local');
  });

  it('an absent or invalid scope resolves to no keys and keeps everything local', () => {
    for (const scope of [undefined, null, 'garbled', { endpoint: ENDPOINT, entries: 'x' }]) {
      const resolved = scoped(scope);
      expect(resolved).toEqual({ mode: 'scoped', keys: new Set() });
      expect(scopeVerdict(resolved, WORK_REPO)).toBe('local');
    }
  });

  it('a scope built for another deployment keeps everything local', () => {
    const resolved = resolveScope({
      mode: 'scoped',
      scope: scopeFor('https://other.example.com', WORK_REPO),
      endpoint: ENDPOINT,
    });
    expect(scopeVerdict(resolved, WORK_REPO)).toBe('local');
  });

  it('a machine attached to no endpoint keeps everything local', () => {
    const resolved = resolveScope({
      mode: 'scoped',
      scope: scopeFor(ENDPOINT, WORK_REPO),
      endpoint: undefined,
    });
    expect(scopeVerdict(resolved, WORK_REPO)).toBe('local');
  });

  it('counts only the valid entries of a partly garbled scope', () => {
    const resolved = scoped({
      endpoint: ENDPOINT,
      entries: [scopeEntry(WORK_REPO), scopeEntry(PERSONAL_REPO, { enrolledAt: 'never' })],
    });
    expect(scopeVerdict(resolved, WORK_REPO)).toBe('forward');
    expect(scopeVerdict(resolved, PERSONAL_REPO)).toBe('local');
  });

  it('reads anything but an exact machine mode as scoped', () => {
    const resolved = resolveScope({
      mode: 'everything' as never,
      scope: undefined,
      endpoint: ENDPOINT,
    });
    expect(resolved.mode).toBe('scoped');
    expect(scopeVerdict(resolved, WORK_REPO)).toBe('local');
  });

  it('resolveScope never throws: a throwing input resolves to scoped with no keys', () => {
    const throwingMode = {
      get mode(): AttachmentMode {
        throw new Error('boom');
      },
      scope: scopeFor(ENDPOINT, WORK_REPO),
      endpoint: ENDPOINT,
    };
    const throwingScope = {
      mode: 'scoped' as const,
      get scope(): unknown {
        throw new Error('boom');
      },
      endpoint: ENDPOINT,
    };
    const throwingExtras = {
      [Symbol.iterator]() {
        throw new Error('boom');
      },
    } as unknown as readonly AttachmentScopeEntry[];
    for (const resolved of [
      resolveScope(throwingMode),
      resolveScope(throwingScope),
      resolveScope(
        { mode: 'scoped', scope: scopeFor(ENDPOINT, WORK_REPO), endpoint: ENDPOINT },
        throwingExtras,
      ),
    ]) {
      expect(resolved).toEqual({ mode: 'scoped', keys: new Set() });
      expect(scopeVerdict(resolved, WORK_REPO)).toBe('local');
    }
  });

  it('scopeVerdict never throws: a resolved scope that throws answers local', () => {
    const throwingKeys: ResolvedAttachmentScope = {
      mode: 'scoped',
      keys: {
        has: () => {
          throw new Error('boom');
        },
      } as unknown as ReadonlySet<string>,
    };
    const throwingModeRead: ResolvedAttachmentScope = {
      get mode(): AttachmentMode {
        throw new Error('boom');
      },
      keys: new Set([WORK_REPO]),
    };
    expect(scopeVerdict(throwingKeys, WORK_REPO)).toBe('local');
    expect(scopeVerdict(throwingModeRead, WORK_REPO)).toBe('local');
  });
});

describe('scopeFilterOf — the one filter value every store read takes', () => {
  it('is undefined in machine mode: no filter at all', () => {
    const machine = resolveScope({
      mode: 'machine',
      scope: scopeFor(ENDPOINT, WORK_REPO),
      endpoint: ENDPOINT,
    });
    expect(scopeFilterOf(machine)).toBeUndefined();
  });

  it('is the resolved keys, sorted, in scoped mode', () => {
    const resolved = resolveScope({
      mode: 'scoped',
      scope: scopeFor(ENDPOINT, PERSONAL_REPO, WORK_REPO, OTHER_WORK_REPO),
      endpoint: ENDPOINT,
    });
    expect(scopeFilterOf(resolved)).toEqual([OTHER_WORK_REPO, WORK_REPO, PERSONAL_REPO]);
  });

  it('is an empty list, which matches nothing, on a scoped machine with no valid scope', () => {
    const resolved = resolveScope({ mode: 'scoped', scope: undefined, endpoint: ENDPOINT });
    expect(scopeFilterOf(resolved)).toEqual([]);
  });

  it('reads anything but an exact machine mode as scoped', () => {
    expect(scopeFilterOf({ mode: 'everything' as never, keys: new Set([WORK_REPO]) })).toEqual([
      WORK_REPO,
    ]);
  });

  it('fails toward matching nothing when the keys cannot be read', () => {
    const unreadable: ResolvedAttachmentScope = {
      mode: 'scoped',
      keys: {
        [Symbol.iterator]() {
          throw new Error('boom');
        },
      } as unknown as ReadonlySet<string>,
    };
    expect(scopeFilterOf(unreadable)).toEqual([]);
  });
});

// Freeze every level, so an in-place write anywhere below throws. resolveScope
// catches that throw and resolves to no keys, so a case using this must assert
// the verdict too, not only that the object is unchanged.
function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

describe('resolveScope extra entries — merged in memory, never persisted', () => {
  // Stand-in for identities that arrive from somewhere other than settings.json.
  // Shaped as AttachmentScopeEntry and held only in memory.
  const published: readonly AttachmentScopeEntry[] = [
    { kind: 'repo', identity: OTHER_WORK_REPO, enrolledAt: ISO },
  ];
  const attachedWith = (attachmentScope: unknown) =>
    WorkspaceSettings.parse({
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: ISO },
      attachmentScope,
    });

  it('forwards a key only an extra entry names, beside the stored entries', () => {
    const settings = attachedWith(scopeFor(ENDPOINT, WORK_REPO));
    const resolved = resolveScope(
      {
        mode: 'scoped',
        scope: settings.attachmentScope,
        endpoint: settings.controlPlane?.endpoint,
      },
      published,
    );
    expect(scopeVerdict(resolved, WORK_REPO)).toBe('forward');
    expect(scopeVerdict(resolved, OTHER_WORK_REPO)).toBe('forward');
    expect(scopeVerdict(resolved, PERSONAL_REPO)).toBe('local');
  });

  it('counts extra entries even when the stored record is absent or for another deployment', () => {
    for (const scope of [undefined, scopeFor('https://other.example.com', WORK_REPO)]) {
      const resolved = resolveScope({ mode: 'scoped', scope, endpoint: ENDPOINT }, published);
      expect(scopeVerdict(resolved, OTHER_WORK_REPO)).toBe('forward');
      expect(scopeVerdict(resolved, WORK_REPO)).toBe('local');
    }
  });

  it('validates extra entries like stored ones: a bad one is dropped by itself', () => {
    const extras = [
      { kind: 'repo', identity: OTHER_WORK_REPO, enrolledAt: ISO },
      { kind: 'org', identity: PERSONAL_REPO, enrolledAt: ISO },
    ] as unknown as readonly AttachmentScopeEntry[];
    const resolved = resolveScope({ mode: 'scoped', scope: undefined, endpoint: ENDPOINT }, extras);
    expect([...resolved.keys]).toEqual([OTHER_WORK_REPO]);
  });

  it('leaves the settings object exactly as it found it', () => {
    const settings = deepFreeze(attachedWith(scopeFor(ENDPOINT, WORK_REPO)));
    const before = JSON.stringify(settings);
    const resolved = resolveScope(
      { mode: 'scoped', scope: settings.attachmentScope, endpoint: ENDPOINT },
      published,
    );
    // A write into the frozen record would throw inside resolveScope, which
    // resolves a throw to no keys: these two lines are what would show it.
    expect(scopeVerdict(resolved, WORK_REPO)).toBe('forward');
    expect(scopeVerdict(resolved, OTHER_WORK_REPO)).toBe('forward');
    expect(JSON.stringify(settings)).toBe(before);
  });

  it('never carries an extra entry into a serialised WorkspaceSettings', () => {
    const settings = attachedWith(scopeFor(ENDPOINT, WORK_REPO));
    resolveScope(
      { mode: 'scoped', scope: settings.attachmentScope, endpoint: ENDPOINT },
      published,
    );
    const written = JSON.stringify(WorkspaceSettings.parse(settings));
    expect(written).toContain(WORK_REPO);
    expect(written).not.toContain(OTHER_WORK_REPO);
  });

  it('honours a stored entry that carries a provenance marker, with the marker stripped', () => {
    const stored = { endpoint: ENDPOINT, entries: [scopeEntry(WORK_REPO, { source: 'org' })] };
    const resolved = resolveScope({ mode: 'scoped', scope: stored, endpoint: ENDPOINT });
    expect(scopeVerdict(resolved, WORK_REPO)).toBe('forward');
    expect(parseAttachmentScope(stored)?.entries[0]).not.toHaveProperty('source');
  });
});
