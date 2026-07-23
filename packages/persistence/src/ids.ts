import { createHash } from 'node:crypto';

import { canonicalIdentity } from '@akasecurity/schema';

// Content-addressed ids for the [Meta] Data Model dimensions. Lives here (not in
// `@akasecurity/schema`) because the spine must stay free of Node-API deps — `@akasecurity/schema`
// only provides the pure `canonicalIdentity` join; the sha256 happens in this
// Node layer. Mirrors the sha256 fingerprint used for event `content_hash`.
// Content-addressing dedupes repeat sessions on the same machine/project
// within the local store.
function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

// sha256(object_type + identity_key). Repeat sessions on the same machine/project
// upsert to the same row; random UUIDs would never merge.
export function inventoryId(objectType: string, identityKey: string): string {
  return sha256Hex(canonicalIdentity(['inventory', objectType, identityKey]));
}

// sha256(remote_url): two machines reporting the same repo collapse.
export function sourceProjectId(url: string): string {
  return sha256Hex(canonicalIdentity(['source_project', url]));
}

// sha256(class): a handful of rows, one per recognized class.
export function classifiedDataId(cls: string): string {
  return sha256Hex(canonicalIdentity(['classified_data', cls]));
}

// sha256(rule_id + version): editing a rule mints a new definition id so
// historical findings keep citing the exact version that fired.
export function inspectionDefinitionId(ruleId: string, version: string): string {
  return sha256Hex(canonicalIdentity(['inspection_definition', ruleId, version]));
}

// sha256(session_id + message_id): transcript-derived `llm_call` rows are re-read on
// every reconcile pass, so a random id would double-count. Keying the id on the
// transcript `message.id` (`msg_…`) plus the session makes the row content-addressed.
//
// `message.id` is NOT unique within a transcript — verified across 159 real
// transcripts. A single assistant API response is written as MULTIPLE records (one
// per content block: thinking/text/tool_use), all sharing the same `message.id` +
// `requestId`; and in subagent/streaming transcripts the earlier records are
// streaming partials whose `output_tokens` is a smaller cumulative count, with the
// terminal (last-in-file) record carrying the full count. Within such a group
// input/cache tokens are constant and only output grows. Keying on `message.id` is
// therefore DELIBERATE: it COLLAPSES all those duplicate records into one
// `llm_call`. The transcript parser already collapses by `message.id` taking
// MAX(output_tokens), so within a single reconcile pass this id + INSERT OR IGNORE
// is correct. The remaining cross-pass risk (a streaming partial lands in pass N,
// its terminal record in pass N+1) MUST be handled by the reconciler with an
// UPSERT that takes MAX(output_tokens) — first-write-wins INSERT OR IGNORE would
// under-count there.
export function llmCallId(sessionId: string, messageId: string): string {
  return sha256Hex(canonicalIdentity(['audit_event_llm_call', sessionId, messageId]));
}

// sha256(session_id + tool_use_id): transcript-derived `tool_call` rows are re-read
// on every reconcile pass, so a random id would double-count. The transcript
// `tool_use.id` (`toolu_…`) is globally unique per call, so keying on it plus the
// session makes the row content-addressed — a re-read no-ops via INSERT OR IGNORE.
export function toolCallId(sessionId: string, toolUseId: string): string {
  return sha256Hex(canonicalIdentity(['audit_event_tool_call', sessionId, toolUseId]));
}

// sha256(audit_event + rule + span): a transcript-derived inspection finding
// (one detected secret hit on a tool_call) is re-scanned on every reconcile pass, so
// unlike the config-scan path (which mints randomUUID per fresh scan event) this MUST
// be content-addressed — a re-read of the same hit (same tool_call, same rule,
// same span) yields the same id and no-ops via the finding insert's ON CONFLICT.
// Keyed on the RULE id, not the inspection_definition id: a rule's definition mints
// a fresh id per version (see `inspectionDefinitionId`), so keying on the definition
// would mint a new finding id every time a pack update bumped the rule's version —
// the same hit would look like a brand-new finding rather than the SAME finding
// whose definition reference merely needs refreshing (the insert's
// ON CONFLICT ... DO UPDATE handles that refresh). NOT keyed on the matched value:
// the id never encodes secret content.
export function inspectionFindingId(
  auditEventId: string,
  ruleId: string,
  spanStart: number,
  spanEnd: number,
): string {
  return sha256Hex(
    canonicalIdentity([
      'inspection_finding',
      auditEventId,
      ruleId,
      String(spanStart),
      String(spanEnd),
    ]),
  );
}

// sha256(session_id + prompt_uuid): the run-grouping key the `tool_call` /
// `llm_call` attribute bags reference as `run_key` — every leaf spawned by the
// same user turn shares it. Content-addressed on the transcript's own per-turn
// uuid (the natural key the reconciler already maps `parentUuid → promptId`
// from) plus the session, so the same turn always resolves to the same key
// across reconcile passes.
export function promptId(sessionId: string, promptUuid: string): string {
  return sha256Hex(canonicalIdentity(['audit_event_prompt', sessionId, promptUuid]));
}

// Folded into `captureId`'s identity in place of a real session id. A capture
// taken outside any harness session (e.g. a CLI worktree scan) still needs a
// stable tuple length, so the missing component becomes this fixed literal
// rather than being dropped from the join.
const NO_SESSION = 'no_session';

// Folded into `captureId`'s identity in place of a real file path. A capture
// with no path (a prompt/response, or a Bash/WebFetch tool_use) still needs a
// stable tuple length, so the missing component becomes this fixed literal
// rather than being dropped from the join — mirroring NO_SESSION above.
const NO_FILE = 'no_file';

// sha256(session_id + content_hash + file_path): a capture (a prompt/response/
// code-change/tool-use record) is content-addressed on the hash of its own
// text, scoped to the session it belongs to so identical content captured in
// two different sessions never collapses onto one row, AND to its file path so
// the SAME bytes at two different paths (a secret duplicated across files) get
// two rows rather than collapsing onto the first-written one. `sessionId` /
// `filePath` are `null` for a session-less / path-less capture, each folding
// onto its fixed sentinel above instead of shortening the join.
export function captureId(
  sessionId: string | null,
  contentHash: string,
  filePath: string | null,
): string {
  return sha256Hex(
    canonicalIdentity(['capture', sessionId ?? NO_SESSION, contentHash, filePath ?? NO_FILE]),
  );
}

// Data Shares dimensions — id derivations for share destinations,
// endpoints, and call-sites. Structurally stable (fixed prefixes, fixed
// canonicalIdentity join order) so a future local-store egress scan derives
// the id the same way on every pass.

// Normalise a destination host so equivalent hosts (mixed case, trailing dot)
// collapse to the same canonical form before being hashed.
export function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.+$/, '');
}

// sha256(host): identity = the host AS GIVEN — callers pass normalizeHost(host)
// (the same value stored on the host column) so the id and the unique index
// agree and repeat scans collapse to one row.
export function shareDestinationId(host: string): string {
  return sha256Hex(canonicalIdentity(['share_destination', host]));
}

// sha256(destinationId + method + url).
export function shareEndpointId(destinationId: string, method: string, url: string): string {
  return sha256Hex(canonicalIdentity(['share_endpoint', destinationId, method, url]));
}

// sha256(endpointId + project + file + line).
export function shareCallSiteId(
  endpointId: string,
  project: string,
  file: string,
  line: number,
): string {
  return sha256Hex(canonicalIdentity(['share_call_site', endpointId, project, file, String(line)]));
}
