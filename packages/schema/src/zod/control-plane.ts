import { z } from 'zod';

import type { ActionTaken } from './finding.ts';
import { ACTION_TAKEN_KEYS } from './finding.ts';
import { AuditEventInput, ToolCallInspection } from './meta.ts';

// The control-plane wire contract: what an ATTACHED machine sends to the
// deployment named by `WorkspaceSettings.controlPlane` (see ./local.ts), and
// the on-disk credential that authenticates it.
//
// Two kinds of shape live here, and the `.meta({ id })` line between them is
// the contract:
//
//   REQUEST bodies (`StorePostureSnapshot` and its components,
//   `RecordAuditEventRequest`) carry an id. They are the single source of
//   truth for what a control plane must accept — a deployment validates the
//   bytes with these exact schemas, so client and server cannot drift.
//   `IngestBatch` (./event.ts) and `InventoryContext` (./meta.ts) are the
//   other two request bodies; they predate this file and stay where the local
//   store owns them.
//
//   RESPONSE parsers (`IngestAck`, `PluginWhoami`, `ControlPlaneErrorBody`)
//   carry NO id. A response contract is owned by the deployment that serves
//   it; the client parses leniently — unknown keys are stripped, widened
//   members tolerated — so an older client keeps working against a newer
//   control plane. The policy-bundle response is `PolicyBundle` (./policy.ts).
//
// `AttachedCredential` is neither: a local 0600 file, never on any wire.

// ─── The credential file ─────────────────────────────────────────────────────

export const ATTACHED_CREDENTIAL_FILENAME = 'control-plane-credential.json';

export const ATTACHED_CREDENTIAL_SPEC_VERSION = 1;

// The credential half of an attachment, at
// `~/.aka/settings/control-plane-credential.json`, owner-read/write only.
//
// settings.json holds the PUBLIC half — `runMode: 'attached'` plus the
// `ControlPlaneConnection` descriptor — and deliberately carries no credential
// (see ./local.ts). This file holds the secret half. Both halves, or the
// machine is standalone: a credential with no matching settings descriptor
// authenticates nothing, and a descriptor with no credential dials nothing.
//
// `endpoint` is repeated here on purpose, and the transport must refuse to
// present the credential when it differs from
// `WorkspaceSettings.controlPlane.endpoint`. The two files have different
// writers and different protections, so a hand edit of settings.json alone
// must DETACH the machine, never redirect an existing credential to a host it
// was not minted for.
//
// An ADMINISTRATOR moving the pinned endpoint is the same case and resolves
// the same way. A managed overlay (./managed.ts) can repoint `controlPlane` on
// every machine at once, and it cannot write this file — so those machines
// stop matching, fall back to standalone, and stay protected until each is
// re-attached against the new deployment. Silent is the wrong shape for that,
// so a mismatch is a state a status surface must be able to name, not merely
// the absence of an attachment.
//
// NO `.meta({ id })` ON THIS SHAPE. EVER. An id registers the shape in Zod's
// global registry, and a consumer walking that registry publishes every entry
// it finds. This shape carries a bearer credential; the same rule protects
// `WorkspaceSettings` (./local.ts).
export const AttachedCredential = z.object({
  specVersion: z.literal(ATTACHED_CREDENTIAL_SPEC_VERSION),
  // The control-plane endpoint this credential was minted against.
  endpoint: z.string().min(1),
  // The bearer credential itself. Never logged, never rendered — status
  // surfaces show `keyPrefix` and nothing else.
  apiKey: z.string().min(1),
  // First few characters of the key, safe to display so a user can match the
  // credential against their organization's key list.
  keyPrefix: z.string().min(1).max(16).optional(),
  mintedAt: z.iso.datetime().optional(),
});
export type AttachedCredential = z.infer<typeof AttachedCredential>;

// ─── Whether that credential can actually be used ────────────────────────────

// The two types below are PLAIN TYPESCRIPT, not Zod, and they describe a
// derived answer rather than a stored or wire shape — so the `.meta({ id })`
// rule in this file's header has nothing to say about them.
//
// They live here, beside `AttachedCredential`, because they are the vocabulary
// for reading one: every reason names a way that file can exist and still not
// authenticate. The reader itself is `readControlPlaneCredentialState` in
// @akasecurity/persistence, which owns the file I/O and re-exports these; they
// sit in this package so a PRESENTATIONAL surface can name a state without
// depending on the module that reads the disk. @akasecurity/dashboard-ui is
// exactly that case — it may reach this package and not that one.

/**
 * Why a credential is not usable, for a surface that has to explain itself.
 *
 *   `absent`         — no file. The ordinary unattached state.
 *   `untrusted-file` — a symlink, a file owned by someone else, or one whose
 *                      mode could not be tightened. A planted credential rather
 *                      than a permissions accident.
 *   `unreadable`     — present but could not be read.
 *   `malformed`      — not JSON, or not an `AttachedCredential` (which includes
 *                      an unknown `specVersion`, a `z.literal`).
 *   `unsafe-endpoint`— minted against an endpoint this build will not send a
 *                      credential to.
 *   `endpoint-mismatch` — a valid credential for a DIFFERENT deployment than the
 *                      one settings names.
 */
export type CredentialUnusableReason =
  | 'absent'
  | 'untrusted-file'
  | 'unreadable'
  | 'malformed'
  | 'unsafe-endpoint'
  | 'endpoint-mismatch';

/**
 * The credential half of an attachment, as a surface should read it.
 *
 * THE USABLE BRANCH CARRIES NO PAYLOAD, and that is the point of the type
 * rather than an omission. `AttachedCredential` holds a bearer key; a state
 * that carried one would mean every surface accepting a `CredentialState`
 * accepts a credential — including a client component, where the value is
 * serialised into the payload the browser receives on every render. This type's
 * own name says what it is for: naming a state, which needs a verdict and not a
 * secret.
 *
 * A caller that genuinely needs the credential is a server one, and asks for it
 * by name — `readControlPlaneCredential` for the transport's door, or
 * `readControlPlaneCredentialFile` for the full read. Having to name it is the
 * property: the narrow type is what a surface gets by default, and reaching
 * past it is a visible act.
 *
 * `endpoint-mismatch` carries BOTH endpoints because it is the one reason a
 * user can act on: the answer is either to re-attach against the endpoint
 * settings now names, or to put the old one back, and neither instruction can
 * be written without saying which is which. Neither is secret — the endpoints
 * are in settings and on screen already.
 */
export type CredentialState =
  | { usable: true }
  | { usable: false; reason: Exclude<CredentialUnusableReason, 'endpoint-mismatch'> }
  | {
      usable: false;
      reason: 'endpoint-mismatch';
      credentialEndpoint: string;
      settingsEndpoint: string;
    };

// ─── Bounds shared with the reference deployment's storage ───────────────────

// The largest epoch-millis value that round-trips as a timestamp everywhere:
// 9999-12-31T23:59:59.999Z. Past year 9999, `Date#toISOString()` switches to
// the extended-year form (`+010000-…`), which timestamp parsers reject.
//
// WHAT THIS BOUND BUYS, stated precisely, because an earlier wording claimed
// more. It does NOT refuse the value on this machine: nothing in product code
// parses a request body, here or on any other route — `reportStorePosture`
// stringifies the snapshot straight into `send`, and `parsed()` in the client is
// applied to RESPONSES. So an out-of-range value still leaves the device and
// still fails inside the receiving deployment.
//
// What it does is define the contract that deployment validates against, which
// is this file's job: a plane parsing with these schemas rejects the body for a
// stated reason rather than failing somewhere in its storage layer, and the
// bound is testable at the sender even though it is not enforced there. Making
// it a local refusal would mean parsing request bodies before sending them —
// a different decision, and one that has to weigh a fail-open capture path
// against dropping a report the plane might have accepted.
const MAX_DATE_MS = 253_402_300_799_999;

// Ceiling of a signed 32-bit integer column. `.int()` alone admits everything
// up to MAX_SAFE_INTEGER. Same standing as MAX_DATE_MS above: the contract the
// receiving deployment validates against, not a refusal this machine performs.
const MAX_INT4 = 2_147_483_647;

// ─── Store-posture report (request: POST /v1/store-posture) ──────────────────

export const StorePosturePack = z
  .object({
    packId: z.string().min(1), // 'namespace/packId'
    version: z.string().min(1),
    enabled: z.boolean(),
    // Stringified pass-through of the local store's `installed_packs.updated_at`
    // — the column format is store-version-dependent (epoch millis vs ISO), so
    // the wire shape assumes neither.
    updatedAt: z.string().nullable(),
  })
  .meta({ id: 'StorePosturePack' });
export type StorePosturePack = z.infer<typeof StorePosturePack>;

// Policy tuning travels as COUNTS ONLY — no field here can carry a target, a
// name, or a custom keyword. That is the privacy invariant of the whole
// posture channel.
export const StorePosturePolicyCounts = z
  .object({
    total: z.number().int().min(0),
    disabled: z.number().int().min(0),
    // Exhaustive per-action map; the builder pre-fills every action with 0.
    //
    // Spelled out member-by-member rather than `z.record(ActionTaken, …)`. Zod
    // enforces exhaustiveness either way, but z.record emits `propertyNames` +
    // `additionalProperties` into a generated schema document, and a type
    // generator renders THAT with every key optional — a sender built against
    // the generated type would typecheck and still be rejected at runtime. An
    // explicit object emits `properties` + `required`, so generated types
    // demand all five.
    //
    // `satisfies Record<ActionTaken, …>` keeps the link to the enum: adding an
    // ActionTaken member is a COMPILE error here instead of silent drift.
    // `.strict()` is load-bearing — it rejects an unknown action key, which a
    // bare object would silently STRIP, accepting a miscounted map as valid.
    byAction: z
      .object({
        warn: z.number().int().min(0),
        redact: z.number().int().min(0),
        block: z.number().int().min(0),
        allow: z.number().int().min(0),
        log: z.number().int().min(0),
      } satisfies Record<ActionTaken, z.ZodNumber>)
      .strict(),
  })
  .meta({ id: 'StorePosturePolicyCounts' });
export type StorePosturePolicyCounts = z.infer<typeof StorePosturePolicyCounts>;

// Compile-time pin that the explicit object above still names every ActionTaken
// member — `satisfies` checks assignability of what IS there; this checks
// nothing is MISSING when the enum grows.
const _BY_ACTION_EXHAUSTIVE: readonly (keyof z.infer<
  typeof StorePosturePolicyCounts
>['byAction'])[] = ACTION_TAKEN_KEYS;
void _BY_ACTION_EXHAUSTIVE;

/**
 * Identity of the REPORTING BINARY — which build sent this snapshot and which
 * policy bundle it was last enforcing. Not a measurement of the local store.
 *
 * Every member is bounded but none of the strings requires `.min(1)`, and that
 * asymmetry is deliberate: a deployment validates the WHOLE body, so rejecting
 * a degenerate `''` here would drop the entire snapshot — `storePresent`, the
 * wipe/tamper signal, included — on a channel whose discipline is fail-open
 * and whose sender swallows rejections. A receiver collapses blanks to null at
 * its own write boundary instead.
 */
export const StorePosturePlugin = z
  .object({
    /** Package name of the reporting plugin. */
    package: z.string().min(1).max(200),
    version: z.string().min(1).max(64),
    /** Version of the bundled core, when the build records one separately. */
    ossVersion: z.string().max(64).nullable(),
    /**
     * `version` of the policy bundle this machine last fetched. Bounded at 200
     * rather than the 64 a bare sha256 hex digest needs today, so a later
     * format with an algorithm prefix does not start rejecting the channel.
     */
    policyBundleVersion: z.string().max(200).nullable(),
    /** Epoch millis, on the CLIENT clock, of that fetch. */
    policyFetchedAt: z.number().int().min(0).max(MAX_DATE_MS).nullable(),
  })
  .meta({ id: 'StorePosturePlugin' });
export type StorePosturePlugin = z.infer<typeof StorePosturePlugin>;

export const StorePostureSnapshot = z
  .object({
    deviceId: z.guid(),
    hostname: z.string().min(1).max(253),
    // Epoch millis on the CLIENT clock. Bounded by what a receiving store
    // accepts (see MAX_DATE_MS), not by what a JavaScript Date can hold.
    capturedAt: z.number().int().min(0).max(MAX_DATE_MS),
    // False is a measurement, not an error state: "no local store exists on
    // this machine".
    storePresent: z.boolean(),
    schemaVersion: z.number().int().min(0).max(MAX_INT4).nullable(), // PRAGMA user_version
    findingsTotal: z.number().int().min(0).max(MAX_INT4),
    // Epoch millis, bounded like `capturedAt` — see MAX_DATE_MS on what that
    // bound does and does not do. Worth stating for these two specifically:
    // they are read from the local store's own ROWS rather than from this
    // machine's clock, so a damaged or hand-edited store is enough to produce
    // an out-of-range value with no clock skew involved.
    findingsFirstAt: z.number().int().min(0).max(MAX_DATE_MS).nullable(),
    findingsLastAt: z.number().int().min(0).max(MAX_DATE_MS).nullable(),
    packs: z.array(StorePosturePack).max(500),
    policyCounts: StorePosturePolicyCounts,
    // OPTIONAL, not nullable: a reporter that predates this member keeps
    // getting its 200 without a payload change.
    plugin: StorePosturePlugin.optional(),
  })
  .meta({ id: 'StorePostureSnapshot' });
export type StorePostureSnapshot = z.infer<typeof StorePostureSnapshot>;

// ─── Audit-event submission (request: POST /v1/audit-events) ─────────────────

// The version namespace a control plane mints capture-path definitions under —
// `capture/<category>/<severity>`, see captureDefinitionVersion in ./local.ts.
// Reserved from clients: inspection-definition identity is content-addressed
// on (ruleId, version), so a client claiming this prefix would mint exactly
// the id the receiver's own capture path owns and silently reclassify findings
// joined through it. Refusing the prefix here keeps the two producers' id
// spaces disjoint by construction.
const CAPTURE_VERSION_PREFIX = 'capture/';

// `AuditEventInput` (./meta.ts) + per-tool-call detected-secret inspections
// (`ToolCallInput.inspections`, already masked — the raw secret never rides
// this shape). `.default([])` keeps a plain AuditEventInput body valid: only a
// tool_call carrying detected secrets sets it.
export const RecordAuditEventRequest = AuditEventInput.extend({
  inspections: z.array(ToolCallInspection).default([]),
})
  .refine((v) => v.inspections.every((i) => !i.ruleVersion.startsWith(CAPTURE_VERSION_PREFIX)), {
    message: `inspections[].ruleVersion must not start with \`${CAPTURE_VERSION_PREFIX}\` — that namespace is reserved for capture definitions the control plane mints itself`,
    path: ['inspections'],
  })
  .meta({ id: 'RecordAuditEventRequest' });
export type RecordAuditEventRequest = z.infer<typeof RecordAuditEventRequest>;

/**
 * The most events one batch may carry.
 *
 * Sized against SERVER COST rather than against the body limit. Each inspection
 * costs its own statements in a per-event loop on the receiving side, so a batch
 * of inspection-heavy tool calls is already hundreds of statements inside one
 * transaction; doubling this would double how long that transaction is held.
 */
export const AUDIT_EVENT_BATCH_MAX = 50;

// `POST /v1/audit-events/batch` — the same per-event upsert as the single-event
// route, several at a time in one transaction.
//
// A batch is 50 of the same call, not a different call: idempotency is
// unchanged, and a duplicate is settled exactly as it is one at a time. What it
// buys is round trips, which is the whole cost of draining a large backlog.
export const RecordAuditEventBatch = z
  .object({
    events: z.array(RecordAuditEventRequest).min(1).max(AUDIT_EVENT_BATCH_MAX),
  })
  .meta({ id: 'RecordAuditEventBatch' });
export type RecordAuditEventBatch = z.infer<typeof RecordAuditEventBatch>;

// ─── Lenient response parsers (no ids — see the header) ──────────────────────

// `POST /v1/events` — how many events were accepted and how many were dropped
// as duplicates.
export const IngestAck = z.object({
  accepted: z.number().int().nonnegative(),
  duplicates: z.number().int().nonnegative(),
});
export type IngestAck = z.infer<typeof IngestAck>;

// `POST /v1/audit-events/batch` — how many of the batch were accepted.
//
// An AGGREGATE count, like the ingest ack above and for the same reason: the
// upsert settles a duplicate silently, so there is no per-item verdict to
// report and nothing a caller could do with one. The caller knows which rows it
// sent.
export const AuditEventBatchAck = z.object({
  accepted: z.number().int().nonnegative(),
});
export type AuditEventBatchAck = z.infer<typeof AuditEventBatchAck>;

// `GET /v1/plugin/whoami` — the identity behind the caller's own credential,
// used by the attach flow to verify a key before storing it and to show the
// user what they attached to. Everything is about the CALLER; nothing
// organization-wide rides this shape. Members a control plane types more
// narrowly (role and credential-kind enums) are plain strings here: the client
// displays them, it does not branch on them.
// BOUNDED AND CHARSET-CONSTRAINED, because every member is rendered straight
// into a terminal by `aka attach`. A control plane is authenticated, not
// trusted: a compromised or hostile one answering with an ANSI escape sequence
// could repaint the line, hide what it just did, or move the cursor over
// output the user is relying on — and a newline alone is enough to forge an
// extra field in the block. Constraining the SHAPE rather than each render site
// means a future consumer inherits the protection instead of having to know.
/**
 * A bounded string with no control or format characters.
 *
 * Exported because it is not only a wire concern. Any string this tree renders
 * into a terminal — `aka status` prints the control-plane label, and these
 * whoami fields — can repaint or hide lines around it if an escape sequence
 * survives, so the refusal belongs wherever such a string is accepted. Named
 * here rather than moved to a new primitives module for one helper; it is the
 * shape's own file until a second unrelated caller earns the move.
 */
const PRINTABLE = /^[^\p{Cc}\p{Cf}]*$/u;
export const printable = (max: number) =>
  z.string().max(max).regex(PRINTABLE, 'must not contain control characters');

export const PluginWhoami = z.object({
  tenantName: printable(200),
  userEmail: printable(320),
  role: printable(64),
  keyKind: printable(64),
  serverTime: printable(64),
});
export type PluginWhoami = z.infer<typeof PluginWhoami>;

// Best-effort parse of a control plane's error envelope. Everything optional:
// the transport acts on the HTTP status; this only dresses a status line with
// a code when one is present.
export const ControlPlaneErrorBody = z.object({
  error: z
    .object({
      code: z.string().optional(),
      message: z.string().optional(),
    })
    .optional(),
});
export type ControlPlaneErrorBody = z.infer<typeof ControlPlaneErrorBody>;

// ─── Attaching a machine without ferrying a key by hand ──────────────────────
//
// The shape of RFC 8628's Device Authorization Grant, for the same reason it
// exists there: the terminal that wants a credential cannot receive a browser
// redirect. It needs no local listener, so nothing here opens a socket, and it
// works over SSH and on headless machines — the printed code completes on
// whatever browser the user can reach.
//
// TWO ENDPOINTS, BOTH UNAUTHENTICATED, because the caller has no credential
// yet — that is the whole point. Everything a device sends is therefore
// attacker-chosen, so every field below is length-capped, and every field a
// deployment sends back is `printable`: the CLI writes them straight into a
// terminal, and this flow renders MORE server-authored text than any other
// (a code, a URL, and a refusal message). The reasoning is the one on
// `PluginWhoami` above and applies with more force here, since a caller reaches
// these routes before it has established which deployment it is talking to.

/**
 * `POST /v1/attach/device` — start a grant.
 *
 * Everything here is REPORTED BY THE DEVICE and none of it is verified: this is
 * an unauthenticated POST, so a caller says whatever it likes. It exists so the
 * person approving in a browser can recognise their own machine, and an
 * approval surface must present it as claimed rather than as fact — what the
 * server actually observed (source address, timing) is the half that cannot be
 * forged.
 *
 * Required rather than optional, so an approval page always has something to
 * show: a caller that cannot determine its own hostname sends a placeholder,
 * which is a decision the CLI makes visibly rather than an absence the server
 * has to render as a blank.
 */
export const AttachDeviceRequest = z
  .object({
    // This machine's own continuity id, so re-attaching ROTATES the credential
    // on one machine record instead of producing a second one. Client-minted
    // and losable — a wiped state file mints a fresh id and the deployment sees
    // a new machine, which is benign precisely because the identity that
    // matters is the credential, not this. Deliberately NOT a hardware
    // fingerprint: nothing here should be a value a device could be tracked by
    // across organizations.
    deviceId: printable(128).min(1),
    hostname: printable(255).min(1),
    os: printable(64).min(1),
    cliVersion: printable(64).min(1),
    // What to call this machine afterwards. Optional because the CLI's own
    // `--label` is optional, and absent means "use the endpoint".
    label: printable(200).optional(),
  })
  .meta({ id: 'AttachDeviceRequest' });
export type AttachDeviceRequest = z.infer<typeof AttachDeviceRequest>;

/**
 * `POST /v1/attach/token` — the poll.
 *
 * `deviceCode` is the secret half of the grant and never leaves the machine
 * that started it. It is the reason this endpoint can answer RFC-distinct
 * states without leaking anything: every answer only ever confirms something
 * about a grant the caller already holds the code for.
 */
export const AttachTokenRequest = z
  .object({
    deviceCode: printable(128).min(1),
  })
  .meta({ id: 'AttachTokenRequest' });
export type AttachTokenRequest = z.infer<typeof AttachTokenRequest>;

// ── The answers ──────────────────────────────────────────────────────────────
//
// Response parsers, so NO `.meta({ id })` on any of them — see this file's
// header. On `AttachTokenIssued` that rule is not merely conventional: it
// carries a bearer credential in `apiKey`, and an id would register the shape in
// Zod's global registry for anything walking it to publish. Same rule, and the
// same reason, as `AttachedCredential` at the top of this file.

/** `POST /v1/attach/device` — what the terminal prints and then polls with. */
export const AttachDeviceGrant = z.object({
  // The secret. Long and high-entropy; the user never sees or types it.
  deviceCode: printable(128),
  // The short one a human reads off the terminal and types into a browser.
  userCode: printable(32),
  verificationUri: printable(512),
  // The same page with the code already filled in. Optional because a
  // deployment may decline to offer it, and a client must not require it.
  verificationUriComplete: printable(512).optional(),
  expiresIn: z.number().int().positive(),
  // The deployment's requested poll spacing, in seconds. Advisory until the
  // deployment says `slow_down`, which is not.
  interval: z.number().int().positive(),
});
export type AttachDeviceGrant = z.infer<typeof AttachDeviceGrant>;

/** Still waiting for someone to approve or deny it in a browser. */
export const AttachTokenPending = z.object({ status: z.literal('pending') });

/**
 * Polling faster than the deployment will answer.
 *
 * Carries a new `interval` rather than leaving the client to guess a backoff,
 * and is a distinct state from `pending` so a client can tell "nothing has
 * happened yet" from "you are asking too often".
 */
export const AttachTokenSlowDown = z.object({
  status: z.literal('slow_down'),
  interval: z.number().int().positive(),
});

/**
 * Decided, and the answer was no — a TERMINAL state, not a reason to keep
 * polling.
 *
 * `message` is optional and server-authored, so a deployment can say WHY when
 * the reason is actionable — a role that may not attach machines is the case
 * this exists for, and one a user would otherwise experience as ten minutes of
 * polling ending in a false "expired".
 */
export const AttachTokenDenied = z.object({
  status: z.literal('denied'),
  message: printable(500).optional(),
});

/** The grant ran out before anyone decided. Terminal; start again. */
export const AttachTokenExpired = z.object({ status: z.literal('expired') });

/**
 * Approved and redeemed — the credential, exactly once.
 *
 * `endpoint` is echoed back rather than assumed from the URL the client dialled:
 * the credential file binds a key to the endpoint it was minted for, and the
 * deployment is the party that knows its own canonical origin.
 */
export const AttachTokenIssued = z.object({
  status: z.literal('issued'),
  apiKey: z.string().min(1).max(512),
  endpoint: printable(512),
  // What the deployment resolved the caller to, so the CLI can show who it is
  // about to attach as before writing anything. Optional: a deployment that
  // does not send it leaves the CLI to ask `whoami`, which it does anyway.
  tenantName: printable(200).optional(),
  userEmail: printable(320).optional(),
});

/**
 * Every answer `POST /v1/attach/token` can give, parsed leniently.
 *
 * A plain union with an UNKNOWN-STATUS member last, rather than a
 * discriminated union that would reject anything it has not been taught. A
 * newer deployment adding a sixth state must not turn an older CLI's poll into
 * a parse error — the client's own rule is to keep waiting for a state it does
 * not recognise, which is only expressible if the parse succeeds.
 *
 * Order is load-bearing: `z.union` takes the first member that matches, so the
 * catch-all has to be last. It also makes a MALFORMED known state degrade
 * safely — an `issued` with no `apiKey` fails the first member and lands on the
 * catch-all as an unrecognised status, so the client waits rather than
 * attaching with nothing.
 */
export const AttachTokenResponse = z.union([
  AttachTokenIssued,
  AttachTokenPending,
  AttachTokenSlowDown,
  AttachTokenDenied,
  AttachTokenExpired,
  z.object({ status: printable(64) }),
]);
export type AttachTokenResponse = z.infer<typeof AttachTokenResponse>;
