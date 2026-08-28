'use client';
import type { ManagedContext, ManagedSettingKey, WorkspaceSettings } from '@akasecurity/schema';
import {
  controlPlaneName,
  isAttached,
  isFieldManaged,
  isModelJudgeConsentValid,
  isVaultConsentValid,
  managedByLabel,
  NO_MANAGED_CONTEXT,
} from '@akasecurity/schema';
import { Button, cn, Input } from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';
import { useState } from 'react';

interface Choice<T extends string> {
  value: T;
  label: string;
  description: string;
}

// Enforcement is NOT configured here, and this section exists to say so rather
// than to offer a control.
//
// A global redact/warn preference used to sit on this page. It had not driven
// enforcement for some time — per-detection policies do — so it presented a
// choice with no effect, which is worse than no control at all: a user who set
// it to Warn believed they had changed what the plugin does. Every handling
// level now lives on one axis, assigned per detection on the Detections page.
export const HANDLING_SECTION_LABEL = 'Enforcement';

export const HANDLING_SECTION_DESCRIPTION =
  'What happens when a detection fires — Monitor, Warn, Redact, Redact & Vault or Block — is ' +
  'assigned per detection on the Detections page. There is no global handling setting: one ' +
  'detection can block while another only logs, and this page would not be able to say which.';

export const HANDLING_SECTION_LINK_LABEL = 'Configure detections';

// This is the same grant the /aka:setup wizard collects, and it is what gates the
// wizard's history sweep — READING local surfaces, nothing more. Sending what that
// sweep finds to the model API is gated by the separate Model-judge consent below,
// so the 'full' copy must point at that control rather than claim the egress for
// itself: a user who grants Full here has not authorized any send.
export const HISTORICAL_SECTION_LABEL = 'Historical access';

export const HISTORICAL_SECTION_DESCRIPTION =
  'Consent to inspect surfaces that existed before AKA was installed.';

export const HISTORICAL_CHOICES: Choice<WorkspaceSettings['historicalAccess']>[] = [
  {
    value: 'session-only',
    label: 'Session only',
    description: 'Only activity from after install is inspected (default — never assumed).',
  },
  {
    value: 'full',
    label: 'Full',
    description:
      'Pre-install surfaces (existing configs, history) may be scanned too. This grant covers ' +
      'reading them only — sending what the scan finds to the model API is the separate ' +
      'Model-judge consent below, which this one does not give. Switching back to Session ' +
      'only stops future scans; it cannot recall data already sent.',
  },
];

// The distinct consent for the /aka:setup model-judge egress — separate from
// historical access, which only governs READING local transcripts. This grants
// or revokes sending findings to the model API for triage.
type ModelJudgeChoice = 'granted' | 'revoked';

export const MODEL_JUDGE_SECTION_LABEL = 'Model-judge consent';

export const MODEL_JUDGE_SECTION_DESCRIPTION =
  'A separate consent from historical access: this governs whether the /aka:setup scan may ' +
  'send findings to the model API to sort real leaks from noise. Per finding that is the raw, ' +
  'unmasked value including any secret, about 120 characters of surrounding transcript text on ' +
  'either side of it, the rule, category, severity, masked value and confidence it was ' +
  'scored with, and a sequential counter the model echoes back. The file ' +
  'path is never sent, and any secrets in the surrounding context are masked before it goes. ' +
  'Revoking stops future scans; it cannot recall data already sent.';

export const MODEL_JUDGE_CHOICES: Choice<ModelJudgeChoice>[] = [
  {
    value: 'revoked',
    label: 'Not granted',
    description:
      'The setup scan will not send findings to the model API (default — never assumed).',
  },
  {
    value: 'granted',
    label: 'Granted',
    description:
      'The setup scan may send each finding — its raw, unmasked value including any secret, plus about 120 characters of surrounding context on either side of it with any secrets in that window masked — to the model API to sort real leaks from noise.',
  },
];

// This is a custody change from one-way redaction: with the grant, a detected
// value survives as recoverable ciphertext instead of being destroyed. The form
// only ever emits the choice string — the grant object itself (acknowledgedAt,
// version) is stamped by the server action, never built client-side.
export const VAULT_SECTION_LABEL = 'Reversible secret vault';

// A CAPABILITY grant, not an enforcement switch — and the distinction is the
// whole point of this section's wording. It used to be both: turning it on made
// every redaction on the machine reversible at once, which meant the same
// "Redact" assignment did two materially different things depending on a
// setting three pages away. Which detections keep a recoverable copy is now the
// Redact & Vault archetype on the Detections page. What survives here is the
// custody consent that archetype needs — permission to hold recoverable copies
// at all. Both are required: without this grant, a detection set to Redact &
// Vault degrades to one-way Redact rather than failing or silently vaulting.
export const VAULT_SECTION_DESCRIPTION =
  'Permission for AKA to keep recoverable copies of what it redacts. This grant does not by ' +
  'itself vault anything — a detection has to be set to Redact & Vault on the Detections page. ' +
  'Without the grant, those detections fall back to one-way Redact.';

export type VaultConsentChoice = 'off' | 'on';

export const VAULT_CHOICES: Choice<VaultConsentChoice>[] = [
  {
    value: 'off',
    label: 'Off (default)',
    description:
      'Nothing recoverable is stored. Detections set to Redact & Vault fall back to one-way ' +
      'Redact, so values are destroyed as they are redacted.',
  },
  {
    value: 'on',
    label: 'Allow vaulting',
    description:
      'A detected value is replaced by a pointer, and an encrypted, recoverable copy is ' +
      'kept in the local vault under ~/.aka — this machine holds recoverable copies of ' +
      'detected secrets, encrypted at rest. The pointers written into files and ' +
      'transcripts show where each secret is used, and which places share the same ' +
      'secret, to anyone who can read those files. Switching back to Off stops new ' +
      'vaulting but does not erase what is already stored — purging the vault from the ' +
      "dashboard's Vault page is what erases it.",
  },
];

// The stored grant maps to the form choice: a recorded consent renders as 'on',
// an absent one as 'off'.
export const INLINE_REVEAL_SECTION_LABEL = 'Inline reveal in the terminal';

export const INLINE_REVEAL_SECTION_DESCRIPTION =
  "How a vault pointer renders inside Claude's on-screen replies. Display-only — the " +
  'transcript and what the model sees always keep the pointer.';

export const INLINE_REVEAL_CHOICES: Choice<WorkspaceSettings['vaultInlineReveal']>[] = [
  {
    value: 'masked',
    label: 'Masked badge (default)',
    description:
      'Pointers render as a masked badge (category and partial value). No raw value is ' +
      'resolved and nothing is written to the audit trail.',
  },
  {
    value: 'full',
    label: 'Full reveal',
    description:
      'Pointers resolve to the real value on screen, capped at two per message and never ' +
      'inside code blocks or quotes. The risk is real: anything the model is induced to ' +
      'mention renders in plaintext where it can be shoulder-surfed, screen-shared, or ' +
      'copy-pasted onward. Every reveal is audited.',
  },
  {
    value: 'off',
    label: 'Off',
    description: 'Replies are not modified; pointers show as-is.',
  },
];

export function vaultChoiceOf(vaultConsent: WorkspaceSettings['vaultConsent']): VaultConsentChoice {
  return vaultConsent ? 'on' : 'off';
}

// A grant recorded against an older consent version no longer authorizes
// vaulting — the version bump means what the vault does has widened since the
// user agreed. The form still derives 'on' (a grant exists) but must say the
// grant is dormant and re-saving re-consents at the current version.
export function vaultConsentStale(vaultConsent: WorkspaceSettings['vaultConsent']): boolean {
  return vaultConsent !== undefined && !isVaultConsentValid(vaultConsent);
}

// The one-word form of VAULT_STALE_NOTICE, for the collapsed summary. The row
// says "Allow vaulting" there, which is the stored answer and NOT what is
// happening, so the summary has to carry the contradiction itself.
export const VAULT_STALE_BADGE = 'Paused';

export const VAULT_STALE_NOTICE =
  'Your grant was recorded against an older version of the vault — vaulting is paused ' +
  'until you re-consent. Saving with "Allow vaulting" selected re-consents to the current version.';

// One collapsible settings row: the label and the CURRENT answer are always
// visible, the options only when opened.
//
// This is the shape of the declutter. Five sections rendered every option of
// every setting at once — twelve radio cards and roughly three thousand
// characters of prose before the user had made a single decision — so the state
// actually in force was the one thing the page did not show. Native
// details/summary rather than a built disclosure: it is keyboard-accessible and
// screen-reader-announced without a behaviour to get wrong.
function SettingRow<T extends string>({
  label,
  description,
  name,
  choices,
  value,
  onChange,
  managed,
  notice,
  alert,
  defaultOpen,
  children,
}: {
  label: string;
  description: string;
  name: string;
  choices: Choice<T>[];
  value: T;
  onChange: (value: T) => void;
  managed?: string | undefined;
  notice?: ReactNode;
  // A short warning shown on the SUMMARY, so a collapsed row can still say that
  // its stated answer is not the one in force.
  alert?: string | undefined;
  defaultOpen?: boolean | undefined;
  children?: ReactNode;
}) {
  const current = choices.find((c) => c.value === value);
  const headingId = `${name}-label`;
  return (
    <details
      className="group border-b border-border last:border-b-0"
      data-slot="setting-row"
      // A row carrying a warning opens itself. Collapsing is for reducing noise,
      // and a warning is not noise: the vault stale-grant notice was always
      // visible before this page collapsed, and hiding it would mean a user
      // reads "Allow vaulting" on a machine where vaulting is paused.
      open={defaultOpen === true}
    >
      <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-3 hover:bg-surface-2">
        <ChevronRight />
        <span className="flex-1">
          <span id={headingId} className="block text-sm font-medium text-text">
            {label}
          </span>
          <span className="mt-0.5 block text-xs text-text-3">{description}</span>
        </span>
        {/* The answer in force, so scanning the page reads the posture without
            opening anything. Managed rows say who decided instead. */}
        {alert !== undefined && (
          <span
            className="shrink-0 rounded-full bg-sev-high-fill px-2 py-0.5 text-xs font-medium text-sev-high-ink"
            data-slot="row-alert"
          >
            {alert}
          </span>
        )}
        {managed === undefined ? (
          <span className="shrink-0 text-xs font-medium text-text-2" data-slot="current-value">
            {current?.label ?? value}
          </span>
        ) : (
          <span
            className="shrink-0 rounded-full bg-surface-2 px-2 py-0.5 text-xs text-text-3"
            data-slot="managed-badge"
            title={managed}
          >
            {current?.label ?? value} · locked
          </span>
        )}
      </summary>
      <div className="px-4 pb-4 pl-11">
        {notice}
        {managed !== undefined && (
          <p className="mb-3 text-xs text-text-3" data-slot="managed-notice">
            {managed}. This setting cannot be changed here.
          </p>
        )}
        <fieldset disabled={managed !== undefined} className="contents">
          <ChoiceGroup
            name={name}
            labelledBy={headingId}
            choices={choices}
            value={value}
            onChange={onChange}
            disabled={managed !== undefined}
          />
        </fieldset>
        {children}
      </div>
    </details>
  );
}

function ChevronRight() {
  return (
    <svg
      className="size-4 shrink-0 text-text-3 transition-transform group-open:rotate-90"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden="true"
    >
      <path d="M6 4l4 4-4 4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ChoiceGroup<T extends string>({
  name,
  labelledBy,
  choices,
  value,
  onChange,
  disabled,
}: {
  name: string;
  labelledBy?: string;
  choices: Choice<T>[];
  value: T;
  onChange: (value: T) => void;
  disabled?: boolean;
}) {
  return (
    <div
      className="flex flex-col gap-2"
      role="radiogroup"
      // Points at the visible heading rather than repeating the field NAME.
      // This announced "vaultConsent" and "historicalAccess" to a screen reader
      // — the storage key, which names the setting to nobody but us.
      aria-labelledby={labelledBy}
    >
      {choices.map((c) => (
        <label
          key={c.value}
          className={cn(
            'flex items-start gap-3 rounded-lg border p-3 transition-colors',
            disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
            value === c.value
              ? 'border-primary bg-primary-tint'
              : cn('border-border bg-surface', !disabled && 'hover:bg-surface-2'),
          )}
        >
          <input
            type="radio"
            name={name}
            checked={value === c.value}
            disabled={disabled}
            onChange={() => {
              onChange(c.value);
            }}
            className="mt-1 accent-primary"
          />
          <span>
            <span className="block text-sm font-semibold text-text">{c.label}</span>
            <span className="mt-0.5 block text-xs text-text-2">{c.description}</span>
          </span>
        </label>
      ))}
    </div>
  );
}

/** A titled group of setting rows. Gives the page an outline to skim. */
function SettingGroup({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h2 className="mb-2 text-label font-semibold uppercase tracking-wider text-text-3">
        {title}
      </h2>
      <div className="overflow-hidden rounded-xl border border-border bg-surface">{children}</div>
    </section>
  );
}

export interface WorkspaceSettingsFormViewProps {
  settings: WorkspaceSettings;
  // What an administrator has pinned, and which of those the user may not
  // change. Absent context ⇒ an unmanaged machine, every control editable.
  managed?: ManagedContext;
  // Both consents are plain answers, not the stored records: acknowledgement
  // timestamps and versions are stamped server-side, so a client-supplied one
  // would only be discarded. modelJudgeConsent: true grants, false revokes.
  //
  // `policy` is deliberately absent. Enforcement is per detection now; see
  // HANDLING_SECTION_DESCRIPTION.
  onSave: (
    changes: Pick<WorkspaceSettings, 'historicalAccess' | 'vaultInlineReveal'> & {
      modelJudgeConsent: boolean;
      vaultConsent: VaultConsentChoice;
    },
  ) => void;
  // Register this machine against an organization's deployment, and undo that.
  // Both optional: a build with no transport plugged in renders the connection
  // state read-only rather than offering an action that cannot complete.
  onAttach?: (endpoint: string, label: string, accessKey: string) => void;
  onDetach?: () => void;
  // Where "Configure detections" points. Injected rather than hardcoded so this
  // package stays router-agnostic.
  detectionsHref?: string;
  busy?: boolean;
  error?: string | null;
  saved?: boolean;
}

/**
 * The workspace settings editor — the web twin of the `/aka:setup` wizard's
 * consent questions, plus the machine's connection state.
 *
 * Grouped rather than flat, and collapsed rather than fully expanded, because
 * what a user needs from this page most of the time is to READ the posture in
 * force. Every option of every setting rendered at once put that answer behind
 * three thousand characters of prose.
 */
export function WorkspaceSettingsFormView({
  settings,
  managed = NO_MANAGED_CONTEXT,
  onSave,
  onAttach,
  onDetach,
  detectionsHref = '/detections',
  busy,
  error,
  saved,
}: WorkspaceSettingsFormViewProps) {
  const [historicalAccess, setHistoricalAccess] = useState(settings.historicalAccess);
  // Validity, not presence: this is the same predicate the judge gate uses, so a
  // consent recorded against an older payload version renders as "Not granted"
  // (which is how the judge treats it) instead of showing a green "Granted" for
  // a grant that no longer authorizes anything. Deriving `dirty` from the same
  // value also keeps re-granting a stale consent a single save.
  const initialModelJudge: ModelJudgeChoice = isModelJudgeConsentValid(settings.modelJudgeConsent)
    ? 'granted'
    : 'revoked';
  const [modelJudge, setModelJudge] = useState<ModelJudgeChoice>(initialModelJudge);
  const [vaultConsent, setVaultConsent] = useState(vaultChoiceOf(settings.vaultConsent));
  const [inlineReveal, setInlineReveal] = useState(settings.vaultInlineReveal);

  // One helper rather than a check per row: a locked field must render the same
  // way everywhere, and an inline conditional per section is how one of them
  // ends up editable.
  const lockOn = (key: ManagedSettingKey): string | undefined =>
    isFieldManaged(managed, key) ? managedByLabel(managed) : undefined;

  const dirty =
    historicalAccess !== settings.historicalAccess ||
    modelJudge !== initialModelJudge ||
    vaultConsent !== vaultChoiceOf(settings.vaultConsent) ||
    inlineReveal !== settings.vaultInlineReveal ||
    // A stale grant renders as 'on' but authorizes nothing; keeping 'on'
    // selected and saving is the documented one-save re-consent, so staleness
    // itself must enable Save.
    (vaultConsent === 'on' && vaultConsentStale(settings.vaultConsent));

  return (
    <div className="flex max-w-4xl flex-col gap-7">
      <SettingGroup title="Connection">
        <ConnectionRow
          settings={settings}
          managedLabel={lockOn('runMode')}
          onAttach={onAttach}
          onDetach={onDetach}
          busy={busy}
        />
      </SettingGroup>

      <SettingGroup title={HANDLING_SECTION_LABEL}>
        <div className="flex items-start gap-3 px-4 py-3" data-slot="enforcement-pointer">
          <span className="flex-1 text-xs text-text-3">{HANDLING_SECTION_DESCRIPTION}</span>
          <a
            href={detectionsHref}
            className="shrink-0 text-xs font-medium text-primary hover:underline"
          >
            {HANDLING_SECTION_LINK_LABEL}
          </a>
        </div>
      </SettingGroup>

      <SettingGroup title="Data access">
        <SettingRow
          label={HISTORICAL_SECTION_LABEL}
          description={HISTORICAL_SECTION_DESCRIPTION}
          name="historicalAccess"
          choices={HISTORICAL_CHOICES}
          value={historicalAccess}
          onChange={setHistoricalAccess}
          managed={lockOn('historicalAccess')}
        />
        <SettingRow
          label={MODEL_JUDGE_SECTION_LABEL}
          // The one-line summary. The FULL disclosure is below, in the expanded
          // body — it must stay complete (every field that crosses the wire is
          // named in it, and a test drives that against the payload schema), so
          // it is placed where it does not crowd the page rather than trimmed.
          description="Whether the setup scan may send findings to the model API."
          name="modelJudgeConsent"
          choices={MODEL_JUDGE_CHOICES}
          value={modelJudge}
          onChange={setModelJudge}
          managed={lockOn('modelJudgeConsent')}
          notice={
            <p className="mb-3 text-xs text-text-3" data-slot="model-judge-disclosure">
              {MODEL_JUDGE_SECTION_DESCRIPTION}
            </p>
          }
        />
        <SettingRow
          label={VAULT_SECTION_LABEL}
          description={VAULT_SECTION_DESCRIPTION}
          name="vaultConsent"
          choices={VAULT_CHOICES}
          value={vaultConsent}
          onChange={setVaultConsent}
          managed={lockOn('vaultConsent')}
          alert={vaultConsentStale(settings.vaultConsent) ? VAULT_STALE_BADGE : undefined}
          defaultOpen={vaultConsentStale(settings.vaultConsent)}
          notice={
            vaultConsentStale(settings.vaultConsent) ? (
              <p className="mb-3 text-xs text-sev-high-ink" data-slot="vault-stale-notice">
                {VAULT_STALE_NOTICE}
              </p>
            ) : null
          }
        />
      </SettingGroup>

      <SettingGroup title="Display">
        <SettingRow
          label={INLINE_REVEAL_SECTION_LABEL}
          description={INLINE_REVEAL_SECTION_DESCRIPTION}
          name="vaultInlineReveal"
          choices={INLINE_REVEAL_CHOICES}
          value={inlineReveal}
          onChange={setInlineReveal}
          managed={lockOn('vaultInlineReveal')}
        />
      </SettingGroup>

      <div className="flex items-center gap-3">
        <Button
          variant="solid"
          tone="primary"
          size="sm"
          disabled={!dirty || busy}
          onClick={() => {
            onSave({
              historicalAccess,
              // Just the answers — the server stamps the acknowledgement times
              // and the versions the grants are recorded against.
              modelJudgeConsent: modelJudge === 'granted',
              vaultConsent,
              vaultInlineReveal: inlineReveal,
            });
          }}
        >
          {busy ? 'Saving…' : 'Save changes'}
        </Button>
        {saved && !dirty && <span className="text-xs text-ok-ink">Saved.</span>}
        {error && <span className="text-xs text-sev-critical-ink">{error}</span>}
      </div>
    </div>
  );
}

// ─── Connection ──────────────────────────────────────────────────────────────

export const CONNECTION_STANDALONE_LABEL = 'Standalone';
export const CONNECTION_ATTACHED_LABEL = 'Attached';

export const CONNECTION_STANDALONE_DESCRIPTION =
  'Everything stays on this machine: detection, policy and history all run against the local ' +
  'store under ~/.aka. Nothing is sent anywhere.';

// Describes the RECORDED STATE, not a live exchange — and the distinction is
// the whole point of this string.
//
// It read "…which supplies policy and receives activity", which claimed a live
// exchange this string cannot know about. The reason has narrowed but not gone:
// `attachToControlPlane` now DOES dial once, to verify the key before it writes
// anything — but that is a check at attach time, not a status. What this string
// renders from is still `ControlPlaneConnection`, which carries no status or
// handshake, read through `isAttached`, a pure local predicate over two stored
// fields. A successful attach an hour ago says nothing about now, so this copy
// must still not claim there is anything on the other end.
export const CONNECTION_ATTACHED_DESCRIPTION =
  'This machine is registered against your organization’s deployment. Detection, policy and ' +
  'history still run against the local store under ~/.aka.';

// Rendered under an attached connection, because an attached machine is one that
// SENDS and the user is owed that in plain words on the surface that records it.
//
// This said the opposite until attached mode shipped — "this build carries no
// control-plane transport, so nothing is sent to that deployment" — which was
// true when written and became a falsehood on a consent surface the moment the
// transport landed. It renders on `attached &&` with no capability check, so
// nothing about the build could ever have corrected it.
//
// What it must NOT do is describe a live exchange it cannot observe. Forwarding
// is the plugin's, not this dashboard's: the page reads the local store, so it
// knows a registration is recorded and knows nothing about whether the other end
// answered. The copy is scoped to exactly that.
export const CONNECTION_FORWARDING_NOTICE =
  'While this machine is attached, the plugin forwards the activity that deployment is entitled ' +
  'to see and pulls the policy it sets. This page reads only your local store, so it cannot ' +
  'report what the deployment received. Detach to stop sending.';

// Shown where attaching is offered but the surface supplies no attach handler.
//
// Reworded away from "this build has no control-plane transport": that stopped
// being the reason. The transport exists, and both the CLI and the web dashboard
// use it — what this notice describes is a HOST that wired no `onAttach`, which
// is a property of the embedding surface rather than of the build.
export const CONNECTION_UNAVAILABLE_NOTICE =
  'This view cannot change the connection. Attach from the AKA dashboard, or with `aka attach` in ' +
  'a terminal.';

export const DETACH_LABEL = 'Detach';

export const DETACH_EXPLANATION =
  'Detaching clears the connection and returns this machine to standalone. Findings and history ' +
  'already in the local store stay where they are.';

// Attached on a surface with no detach handler. The explanation above describes
// a button, so showing it without one reads as a rendering fault rather than as
// the deliberate absence it is.
export const DETACH_UNAVAILABLE_NOTICE =
  'This machine is registered, and this build offers no way to detach it here.';
export const ATTACH_LABEL = 'Attach';

/**
 * The kind is named on screen because it is the one attach failure a user
 * cannot diagnose from the outside: an `ingest` key authenticates and then
 * fails the policy read, which looks exactly like a bad key.
 */
/**
 * Both halves of an attachment, or neither.
 *
 * Named and exported rather than left inline in the button's `disabled`, because
 * it is the rule this whole surface exists to enforce: an attach with an
 * endpoint and no key writes a descriptor with no credential, which every later
 * surface reads as attached-and-broken — `aka status` says "attached — no usable
 * credential" and forwarding silently does nothing. Inline in JSX it was a
 * condition no test in this package could reach.
 *
 * Trimmed, so whitespace does not enable the button and then fail the action.
 */
export function canAttach(endpoint: string, accessKey: string): boolean {
  return endpoint.trim() !== '' && accessKey.trim() !== '';
}

export const ATTACH_KEY_HINT =
  'Create a plugin key in your deployment and paste it here. It is stored on this machine only, in a file readable by you alone.';

// The detach that MDM takes away. A machine an administrator attached is not
// one the user may leave, and saying which organization decided that is the
// difference between a policy and a broken button.
export const DETACH_MANAGED_NOTICE =
  'Your organization set this connection, so this machine cannot be detached here.';

function ConnectionRow({
  settings,
  managedLabel,
  onAttach,
  onDetach,
  busy,
}: {
  settings: WorkspaceSettings;
  managedLabel?: string | undefined;
  onAttach?: ((endpoint: string, label: string, accessKey: string) => void) | undefined;
  onDetach?: (() => void) | undefined;
  busy?: boolean | undefined;
}) {
  const [endpoint, setEndpoint] = useState('');
  const [label, setLabel] = useState('');
  // Held in component state like the other two, and cleared the moment the
  // attach is handed off below.
  const [accessKey, setAccessKey] = useState('');
  const attached = isAttached(settings);
  const locked = managedLabel !== undefined;

  return (
    <div className="px-4 py-3" data-slot="connection-row">
      <div className="flex items-start gap-3">
        <span className="flex-1">
          <span className="block text-sm font-medium text-text">Run mode</span>
          <span className="mt-0.5 block text-xs text-text-3">
            {attached ? CONNECTION_ATTACHED_DESCRIPTION : CONNECTION_STANDALONE_DESCRIPTION}
          </span>
          {attached && settings.controlPlane && (
            <span className="mt-1 block text-xs text-text-2" data-slot="control-plane-name">
              {controlPlaneName(settings.controlPlane)}
            </span>
          )}
        </span>
        <span
          className={cn(
            'shrink-0 rounded-full px-2 py-0.5 text-xs font-medium',
            attached ? 'bg-teal-fill text-teal-ink' : 'bg-surface-2 text-text-3',
          )}
          data-slot="run-mode-badge"
        >
          {attached ? CONNECTION_ATTACHED_LABEL : CONNECTION_STANDALONE_LABEL}
          {locked && ' · locked'}
        </span>
      </div>

      {attached && (
        <p className="mt-3 text-xs text-text-3" data-slot="connection-forwarding">
          {CONNECTION_FORWARDING_NOTICE}
        </p>
      )}

      {locked ? (
        <p className="mt-3 text-xs text-text-3" data-slot="connection-managed-notice">
          {managedLabel}. {attached ? DETACH_MANAGED_NOTICE : ''}
        </p>
      ) : attached && onDetach ? (
        <div className="mt-3">
          <Button
            variant="outline"
            tone="danger"
            size="sm"
            disabled={busy}
            onClick={() => {
              // Clear what was typed BEFORE detaching. The attach form is the
              // same component instance and keeps its own state, so without
              // this the endpoint of the deployment just left reappears
              // pre-filled in the form offering to join a new one.
              //
              // The key is cleared for a stronger reason than a stale form: a
              // key typed and never submitted — the user changed their mind, or
              // a concurrent `aka attach` flipped this view to attached under
              // them — would otherwise sit in component state across the whole
              // detached period and reappear pre-filled afterwards.
              setEndpoint('');
              setLabel('');
              setAccessKey('');
              onDetach();
            }}
            data-slot="detach-button"
          >
            {DETACH_LABEL}
          </Button>
          <p className="mt-2 text-xs text-text-3">{DETACH_EXPLANATION}</p>
        </div>
      ) : attached ? (
        // Attached, but this surface supplies no way to leave. Say so rather
        // than rendering the explanation for a button that is not there.
        <p className="mt-3 text-xs text-text-3" data-slot="detach-unavailable">
          {DETACH_UNAVAILABLE_NOTICE}
        </p>
      ) : onAttach ? (
        <div className="mt-3 flex flex-col gap-2" data-slot="attach-form">
          <div className="flex flex-col gap-2 sm:flex-row">
            <Input
              value={endpoint}
              placeholder="Deployment endpoint"
              aria-label="Deployment endpoint"
              onChange={(e) => {
                setEndpoint(e.target.value);
              }}
            />
            <Input
              value={label}
              placeholder="Name (optional)"
              aria-label="Deployment name"
              onChange={(e) => {
                setLabel(e.target.value);
              }}
            />
          </div>
          {/*
            `type="password"` for the masking, and the autoComplete/spellCheck/
            autoCorrect opt-outs because a browser offering to SAVE this, or a
            spellchecker shipping the value to a remote dictionary, defeats the
            masking by another route.
          */}
          <Input
            type="password"
            name="aka-access-key"
            value={accessKey}
            placeholder="Access key"
            aria-label="Access key"
            autoComplete="off"
            spellCheck={false}
            autoCorrect="off"
            onChange={(e) => {
              setAccessKey(e.target.value);
            }}
          />
          <p className="text-xs text-text-3" data-slot="attach-key-hint">
            {ATTACH_KEY_HINT}
          </p>
          <div>
            <Button
              variant="solid"
              tone="primary"
              size="sm"
              disabled={busy === true || !canAttach(endpoint, accessKey)}
              onClick={() => {
                const key = accessKey.trim();
                // Cleared BEFORE the handler runs, not after it resolves. The
                // attach is async and this component stays mounted across it, so
                // clearing on completion would leave the secret in a live input
                // — and in React DevTools state — for the whole round trip,
                // including the failure case where the form stays on screen.
                setAccessKey('');
                onAttach(endpoint.trim(), label.trim(), key);
              }}
              data-slot="attach-button"
            >
              {ATTACH_LABEL}
            </Button>
          </div>
        </div>
      ) : (
        <p className="mt-3 text-xs text-text-3" data-slot="connection-unavailable">
          {CONNECTION_UNAVAILABLE_NOTICE}
        </p>
      )}
    </div>
  );
}
