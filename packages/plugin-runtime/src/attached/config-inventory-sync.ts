// Reports an attached machine's config inventory to its deployment. A session
// start stages the report in the data dir; the detached sync child sends it.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  ATTACHED_CONFIG_INVENTORY_FILENAME,
  ATTACHED_CONFIG_INVENTORY_STATE_FILENAME,
  ensureDataDirSync,
  readControlPlaneCredentialFile,
  readWorkspaceSettings,
  writeOwnerOnlyFileSync,
} from '@akasecurity/persistence';
import type { RemoteClient } from '@akasecurity/remote';
import {
  classifyRemoteFailure,
  createRemoteClient,
  RemoteResponseInvalid,
} from '@akasecurity/remote';
import type { ConfigScanRecord } from '@akasecurity/schema';
import {
  attachmentModeOf,
  ConfigInventoryRequest,
  isAttached,
  isProjectScopedConfigItem,
} from '@akasecurity/schema';

import { configInventoryRequests } from './config-inventory-wire.ts';
import { endpointFingerprint } from './history-sync.ts';
import { withTimeout } from './with-timeout.ts';

/** An unchanged report is sent again once its last delivery is this old. */
export const CONFIG_INVENTORY_RESEND_MS = 60 * 60 * 1000;

export const CONFIG_INVENTORY_REQUEST_TIMEOUT_MS = 30_000;

/** The most staged reports kept, one per harness and project. */
export const CONFIG_INVENTORY_STAGED_MAX = 32;

/** A staged report older than this is dropped. */
export const CONFIG_INVENTORY_STAGED_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/** The size the staged file is kept under, dropping the oldest reports first. */
export const CONFIG_INVENTORY_STAGED_MAX_BYTES = 8 * 1024 * 1024;

interface StagedEntry<Request = unknown> {
  key: string;
  stagedAtMs: number;
  requests: Request[];
}

type StagedReport = StagedEntry<ConfigInventoryRequest>;

interface Delivered {
  /** The deployment's fingerprint and the attachment's `attachedAt`. */
  attachment: string;
  /** Per staged report key: the digest last delivered, and when. */
  reports: Record<string, { digest: string; atMs: number }>;
  /** Per harness: the digest of the machine-wide items last delivered. */
  global: Record<string, string>;
}

/**
 * `sent`       reports delivered in this pass.
 * `unchanged`  reports skipped because the deployment already holds them.
 * `failed`     reports whose send failed; they stay staged. A failure that ends
 *              the pass leaves the reports after it staged and uncounted.
 */
export interface ConfigInventorySyncResult {
  sent: number;
  unchanged: number;
  failed: number;
}

export interface RunConfigInventorySyncDeps {
  /** The ~/.aka root. */
  base: string;
  settingsDir: string;
  dataDir: string;
  now?: (() => number) | undefined;
}

export function stagedConfigInventoryPath(dataDir: string): string {
  return join(dataDir, ATTACHED_CONFIG_INVENTORY_FILENAME);
}

export function configInventoryStatePath(dataDir: string): string {
  return join(dataDir, ATTACHED_CONFIG_INVENTORY_STATE_FILENAME);
}

/**
 * Stage the report for one config scan, replacing the report staged earlier
 * for the same harness and project. Keeps at most
 * {@link CONFIG_INVENTORY_STAGED_MAX} reports in under `maxBytes`, dropping the
 * oldest first; the new report is always kept. A record that yields no request
 * stages nothing. Never throws. Two session starts staging at the same moment
 * can lose one report; the next session start in that project stages it again.
 */
export function stageConfigInventory(
  dataDir: string,
  record: ConfigScanRecord,
  nowMs: number = Date.now(),
  maxBytes: number = CONFIG_INVENTORY_STAGED_MAX_BYTES,
): void {
  try {
    const requests = configInventoryRequests(record);
    const [first] = requests;
    if (first === undefined) return;
    const key = reportKey(first);
    const kept = readStagedEntries(dataDir).filter(
      (report) =>
        report.key !== key && nowMs - report.stagedAtMs < CONFIG_INVENTORY_STAGED_MAX_AGE_MS,
    );
    const entries = [...kept, { key, stagedAtMs: nowMs, requests }]
      .slice(-CONFIG_INVENTORY_STAGED_MAX)
      .map((entry) => JSON.stringify(entry));
    let bytes = entries.reduce((total, entry) => total + Buffer.byteLength(entry, 'utf8') + 1, 0);
    while (entries.length > 1 && bytes > maxBytes) {
      bytes -= Buffer.byteLength(entries.shift() ?? '', 'utf8') + 1;
    }
    ensureDataDirSync(dataDir);
    writeOwnerOnlyFileSync(
      stagedConfigInventoryPath(dataDir),
      `{"reports":[${entries.join(',')}]}\n`,
    );
  } catch {
    // The scan is already in the local store; an unstaged report is sent after
    // the next session start.
  }
}

/**
 * Send the staged reports, oldest first, to the deployment a machine-wide
 * attachment names.
 *
 * A report is skipped when the deployment already holds it: the same digest
 * was delivered for its key and, for the newest report staged for a harness,
 * the machine-wide items in it match the last ones delivered for that harness.
 * It is sent again once its last delivery is
 * {@link CONFIG_INVENTORY_RESEND_MS} old and a session start has staged it
 * since. A report the deployment refuses is left staged and the pass moves on;
 * any other failure ends the pass. A report the deployment answers with an
 * unreadable acknowledgement counts as delivered.
 *
 * Returns null, and sends nothing, unless the machine holds a usable
 * machine-wide credential for the endpoint its settings name. What was
 * delivered is recorded per attachment, so a new attachment sends every report
 * again. Never throws.
 */
export async function runConfigInventorySync(
  deps: RunConfigInventorySyncDeps,
): Promise<ConfigInventorySyncResult | null> {
  const result: ConfigInventorySyncResult = { sent: 0, unchanged: 0, failed: 0 };
  try {
    const settings = readWorkspaceSettings(deps.base);
    const connection = isAttached(settings) ? settings.controlPlane : undefined;
    if (connection === undefined) return null;
    const state = readControlPlaneCredentialFile(deps.settingsDir, connection);
    if (!state.usable || attachmentModeOf(state.credential) !== 'machine') return null;

    const staged = readStagedReports(deps.dataDir);
    if (staged.length === 0) return result;
    const nowMs = (deps.now ?? Date.now)();
    const attachment = `${endpointFingerprint(connection.endpoint)} ${connection.attachedAt}`;
    const delivered = readDelivered(deps.dataDir, attachment);
    const client = createRemoteClient({
      endpoint: connection.endpoint,
      apiKey: state.credential.apiKey,
      timeoutMs: CONFIG_INVENTORY_REQUEST_TIMEOUT_MS,
    });

    const newest = new Map(staged.map((report) => [harnessOf(report), report]));
    for (const report of staged) {
      const digest = digestOf(report.requests);
      const harness = harnessOf(report);
      const machineWide =
        newest.get(harness) === report ? machineWideDigest(report.requests) : null;
      if (!isDue(delivered, report, { digest, harness, machineWide }, nowMs)) {
        result.unchanged += 1;
        continue;
      }
      try {
        await sendReport(client, report.requests);
      } catch (err) {
        result.failed += 1;
        const kind = classifyRemoteFailure(err);
        if (kind === 'rejected' || kind === 'invalid-request') continue;
        break;
      }
      delivered.reports[report.key] = { digest, atMs: nowMs };
      delivered.global[harness] = machineWideDigest(report.requests);
      result.sent += 1;
      writeDelivered(deps.dataDir, delivered, staged);
    }
    return result;
  } catch {
    return result;
  }
}

async function sendReport(
  client: Pick<RemoteClient, 'recordConfigInventory'>,
  requests: readonly ConfigInventoryRequest[],
): Promise<void> {
  for (const request of requests) {
    try {
      await withTimeout(client.recordConfigInventory(request), CONFIG_INVENTORY_REQUEST_TIMEOUT_MS);
    } catch (err) {
      if (!(err instanceof RemoteResponseInvalid)) throw err;
    }
  }
}

// `machineWide` is null for a report that is not the newest staged for its
// harness: its machine-wide items are older than that report's.
function isDue(
  delivered: Delivered,
  report: StagedReport,
  current: { digest: string; harness: string; machineWide: string | null },
  nowMs: number,
): boolean {
  const last = delivered.reports[report.key];
  if (last?.digest !== current.digest) return true;
  if (current.machineWide !== null && delivered.global[current.harness] !== current.machineWide) {
    return true;
  }
  return report.stagedAtMs > last.atMs && nowMs - last.atMs >= CONFIG_INVENTORY_RESEND_MS;
}

function harnessOf(report: StagedReport): string {
  return report.requests[0]?.harness.identityKey ?? '';
}

function reportKey(request: ConfigInventoryRequest): string {
  return JSON.stringify([request.harness.identityKey, request.projectKey ?? null]);
}

function digestOf(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

// The harness, whether the report is complete, and its items that are not
// project scoped: what a report sets for the whole machine.
function machineWideDigest(requests: readonly ConfigInventoryRequest[]): string {
  const [first] = requests;
  return digestOf([
    first?.harness.identityKey,
    first?.complete === true,
    requests.flatMap((request) => request.items.filter((item) => !isProjectScopedConfigItem(item))),
  ]);
}

// The staged entries, oldest first, without validating their requests.
function readStagedEntries(dataDir: string): StagedEntry[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(stagedConfigInventoryPath(dataDir), 'utf8'));
  } catch {
    return [];
  }
  const entries = (parsed as { reports?: unknown } | null)?.reports;
  if (!Array.isArray(entries)) return [];
  const valid: StagedEntry[] = [];
  for (const entry of entries as unknown[]) {
    const candidate = entry as Partial<Record<keyof StagedEntry, unknown>> | null;
    if (typeof candidate?.key !== 'string' || !isTimestamp(candidate.stagedAtMs)) continue;
    if (!Array.isArray(candidate.requests) || candidate.requests.length === 0) continue;
    valid.push({
      key: candidate.key,
      stagedAtMs: candidate.stagedAtMs,
      requests: candidate.requests as unknown[],
    });
  }
  return valid.sort((a, b) => a.stagedAtMs - b.stagedAtMs);
}

// The staged reports whose every request is a valid config inventory request.
function readStagedReports(dataDir: string): StagedReport[] {
  const reports: StagedReport[] = [];
  for (const entry of readStagedEntries(dataDir)) {
    const requests: ConfigInventoryRequest[] = [];
    for (const request of entry.requests) {
      const checked = ConfigInventoryRequest.safeParse(request);
      if (checked.success) requests.push(checked.data);
    }
    if (requests.length === entry.requests.length) reports.push({ ...entry, requests });
  }
  return reports;
}

// The delivered state for `attachment`; empty when none is recorded, it is
// unreadable, or it was recorded for another attachment.
function readDelivered(dataDir: string, attachment: string): Delivered {
  const empty: Delivered = { attachment, reports: {}, global: {} };
  try {
    const parsed = JSON.parse(readFileSync(configInventoryStatePath(dataDir), 'utf8')) as Partial<
      Record<keyof Delivered, unknown>
    > | null;
    if (parsed?.attachment !== attachment) return empty;
    const reports: Delivered['reports'] = {};
    for (const [key, value] of Object.entries(asRecord(parsed.reports))) {
      const entry = value as { digest?: unknown; atMs?: unknown } | null;
      if (typeof entry?.digest !== 'string' || !isTimestamp(entry.atMs)) continue;
      reports[key] = { digest: entry.digest, atMs: entry.atMs };
    }
    const global: Delivered['global'] = {};
    for (const [harness, digest] of Object.entries(asRecord(parsed.global))) {
      if (typeof digest === 'string') global[harness] = digest;
    }
    return { attachment, reports, global };
  } catch {
    return empty;
  }
}

// Keeps only the keys still staged.
function writeDelivered(
  dataDir: string,
  delivered: Delivered,
  staged: readonly StagedReport[],
): void {
  try {
    const reports: Delivered['reports'] = {};
    for (const { key } of staged) {
      const entry = delivered.reports[key];
      if (entry !== undefined) reports[key] = entry;
    }
    ensureDataDirSync(dataDir);
    writeOwnerOnlyFileSync(
      configInventoryStatePath(dataDir),
      `${JSON.stringify({ ...delivered, reports })}\n`,
    );
  } catch {
    // The report was delivered; an unrecorded delivery is sent again next pass.
  }
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
