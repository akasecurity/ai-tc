/**
 * The PRODUCTION redaction adapter a shipped caller binds: given the raw-free
 * secret findings the remediation decision presents, it redacts the leaked keys
 * they reference and returns the real redacted-key count.
 *
 * Unlike `redactLeakedKeys` (which trusts whatever `RedactionScope` its caller
 * builds — fine for tests that construct their own fixture roots), this adapter
 * DERIVES the artifact scope itself from `platformRedactionScope()` /
 * `transcriptsDir()`, so a future production caller can never widen redaction by
 * handing it an arbitrary `artifactRoots` list. In production the enforced scope
 * is exactly the platform transcripts root — the current shipped caller passes no
 * temp root. This adapter also supports one additional, EXPLICITLY named bounded
 * temp directory a caller can say it owns for a given call — validated before it
 * is trusted: it must not itself resolve to (or sit inside) a git-tracked project
 * — the same repo-resolution primitive (`resolveRepo`) the codebase already uses
 * to find a real repo root — so a mislabeled project directory can never be
 * smuggled in as "temp." That path is exercised only by tests today, via the
 * `tempRoot` override below. A finding whose artifact resolves outside the
 * enforced scope is simply never redacted — the same binding-scope guarantee
 * `redactLeakedKeys` already provides, just enforced against a self-derived
 * scope rather than a caller-supplied one.
 *
 * `MaskedSecretFinding` deliberately omits the raw key value (it is a raw-free
 * projection persisted in the calibration frame), so the raw value redaction
 * needs has to be recovered fresh from the on-disk artifact the finding
 * references. That recovery reuses the SAME secret-detection engine the
 * historical backfill scans with (`createPluginRuntime(...).processText`, the
 * shared detect path behind `scanHistory`) — never a hand-rolled matcher — read
 * ONLY over artifacts already inside the enforced scope, and matched back to a
 * finding by the same (provider, maskedToken) pair `deriveSurfacedSecretFindings`
 * used to build the finding in the first place.
 */
import { readFileSync } from 'node:fs';

import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import {
  createPluginRuntime,
  createVaultGlue,
  loadConfig,
  maskMatch,
  resolveRepo,
  safeMaskedMatch,
} from '@akasecurity/plugin-sdk';
import type { DetectionCategory, MaskedSecretFinding } from '@akasecurity/schema';
import { isVaultConsentValid } from '@akasecurity/schema';
import { deriveProvider } from '@akasecurity/setup-wizard';

import { transcriptsDir } from '../history/transcripts.ts';
import {
  realPathOrNull,
  type RedactionScope,
  type RedactionTarget,
  redactLeakedKeysDetailed,
  resolveRedactableArtifact,
} from './redact.ts';

// Test-only overrides — no production call site sets any of these; every real
// invocation derives its scope from the real OS home and reads the real `~/.aka`
// store. `home` mirrors `transcriptsDir`'s own override (which real HOME's
// transcripts to scan); `dataDirBase` mirrors `loadConfig`'s own override (which
// real `~/.aka` to read, so a test never opens the developer's actual local
// store); `tempRoot` names ONE additional bounded scratch directory this call
// explicitly owns — validated below, never trusted outright.
export interface RedactSurfacedSecretsOverrides {
  home?: string;
  dataDirBase?: string;
  tempRoot?: string;
}

// `tempRoot` is trusted as an additional artifact root ONLY when it exists and
// does not itself resolve to (or sit inside) a git-tracked project — the same
// check the codebase already uses to find a real repo root. A caller that hands
// in a project directory under the guise of "temp" fails this check and the
// root is simply dropped from the enforced scope, exactly as if it had never
// been supplied — never widening redaction into a project working tree.
function isBoundedTempRoot(candidate: string): boolean {
  return realPathOrNull(candidate) !== null && resolveRepo(candidate) === undefined;
}

// The scope this adapter will enforce: the platform's transcripts root, plus the
// caller's named temp root when (and only when) it validates as genuinely
// bounded. Never widened by anything else a caller supplies.
function enforcedScope(overrides: RedactSurfacedSecretsOverrides): RedactionScope {
  const roots = [transcriptsDir(overrides.home)];
  if (overrides.tempRoot !== undefined && isBoundedTempRoot(overrides.tempRoot)) {
    roots.push(overrides.tempRoot);
  }
  return { artifactRoots: roots };
}

// One recovered redaction target plus the detection identity of the on-disk
// occurrence it came from — the identity the vault needs to mint a pointer for
// the value. Undefined when no occurrence matching this finding's
// (provider, maskedToken) pair was found in the scanned content.
interface RecoveredTarget {
  target: RedactionTarget;
  ruleId: string;
  category: DetectionCategory;
}

function recoverTarget(
  finding: MaskedSecretFinding,
  matches: readonly { ruleId: string; rawMatch: string; category: DetectionCategory }[],
): RecoveredTarget | undefined {
  const hit = matches.find(
    (m) =>
      deriveProvider(m.ruleId) === finding.provider &&
      safeMaskedMatch(m.rawMatch) === finding.maskedToken,
  );
  return hit === undefined
    ? undefined
    : {
        target: { where: finding.where, rawValue: hit.rawMatch },
        ruleId: hit.ruleId,
        category: hit.category,
      };
}

// Whether the settings on record carry a currently valid vault consent.
// Fail-closed: a settings load fault reads as no consent, so the strike stays
// the plain one-way redaction rather than attempting to vault.
function hasValidVaultConsent(base: string | undefined): boolean {
  try {
    return isVaultConsentValid(loadConfig(base).settings.vaultConsent);
  } catch {
    return false;
  }
}

// The pre-resolved replacement map for the synchronous strike: each DISTINCT
// raw value among the recovered targets is tokenized ONCE, so the same key
// leaked into several artifacts resolves to one pointer everywhere. Only a
// well-formed pointer return lands in the map — a degraded `[REDACTED:…]`
// return is dropped, because the synchronous default already strikes one-way.
// Any fault yields an empty map (plain strike), never a throw: the glue is
// built to never surface raw or throw, and this guard is belt-and-braces on
// top of that.
//
// Deliberately NOT filtered by the assigned pack policy, unlike the automatic
// paths (the hooks, and the transcript scrub behind them). Those are the pack
// acting on its own, where Monitor has to mean the value is only logged. This
// is the user reading a list of their own surfaced secrets and asking for these
// ones to be struck — an instruction about specific values, not an enforcement
// decision — and a Redact button that silently declined to strike what it was
// pointed at would be a worse answer than the policy it was honouring. Monitor
// still governs what reached the list: it stops nothing from being detected and
// surfaced, which is exactly what makes it a choice the user can act on here.
//
// That divergence has to be RECORDED, not merely acted on, which is what
// `userAuthorized` is for. A policy sweep over the vault sees only the
// assignment — `log` — and would read these rows as vaulting no policy
// authorizes, restore the raw value into the very artifact it was struck from,
// and delete the entry. The marker is what tells that sweep a person asked, and
// it survives on the row when an automatic path later vaults the same value.
async function buildPointerReplacements(
  recovered: readonly RecoveredTarget[],
  base: string | undefined,
): Promise<ReadonlyMap<string, string>> {
  const replacements = new Map<string, string>();
  try {
    const glue = createVaultGlue(base === undefined ? undefined : { base });
    const distinct = new Map<string, RecoveredTarget>();
    for (const entry of recovered) {
      if (!distinct.has(entry.target.rawValue)) distinct.set(entry.target.rawValue, entry);
    }
    for (const [rawValue, entry] of distinct) {
      const replacement = await glue.tokenizeValue(rawValue, {
        ruleId: entry.ruleId,
        category: entry.category,
        maskedMatch: maskMatch(rawValue),
        userAuthorized: true,
      });
      if (replacement.startsWith('[[aka:') && replacement !== rawValue) {
        replacements.set(rawValue, replacement);
      }
    }
  } catch {
    return new Map();
  }
  return replacements;
}

// The real outcome of a redaction pass: the count of keys actually struck, plus
// exactly which of the input findings are NOT covered by that count — a
// vanished/unreadable artifact, content that changed between the calibration
// scan and this redact-time re-scan, an out-of-scope artifact, or a recovery
// failure all land a finding here. A caller must never present a "resolved"
// framing while `unredacted` is non-empty — that is exactly the false
// all-clear this shape exists to prevent.
export interface SurfacedRedactionResult {
  readonly redactedKeys: number;
  // How many of `redactedKeys` were replaced with recoverable vault pointers
  // rather than the irreversible placeholder — set only when a valid vault
  // consent is on record, 0 otherwise. The caller's copy must distinguish the
  // two: a pointered value is viewable again, a struck value is gone.
  readonly pointeredKeys: number;
  readonly unredacted: readonly MaskedSecretFinding[];
}

/**
 * Redact every in-scope leaked key the surfaced secret findings reference, and
 * report the real count of keys actually redacted plus which findings were not
 * (so a caller can render an honest partial outcome rather than claim complete
 * redaction). Fully fail-open: any failure recovering raw values (config/store
 * unavailable, an unreadable artifact) leaves the affected findings in
 * `unredacted` rather than throwing — the caller's session must never break
 * because a best-effort recovery pass failed. The actual in-place striking is
 * delegated entirely to `redactLeakedKeysDetailed`, so its binding-scope,
 * atomic-write, and per-file fail-open guarantees apply unchanged.
 *
 * With a valid vault consent on record the strike is RECOVERABLE: each distinct
 * recovered value is tokenized into the local secret vault and its occurrences
 * are rewritten to the resulting pointer instead of the one-way placeholder
 * (`pointeredKeys` reports how many keys landed that way). Without consent — or
 * on any vault fault — nothing is vaulted and the strike is byte-identical to
 * the plain one-way redaction.
 */
export async function redactSurfacedSecrets(
  findings: readonly MaskedSecretFinding[],
  overrides: RedactSurfacedSecretsOverrides = {},
): Promise<SurfacedRedactionResult> {
  if (findings.length === 0) return { redactedKeys: 0, pointeredKeys: 0, unredacted: [] };
  const scope = enforcedScope(overrides);

  // Group by file, and set aside any finding whose artifact does not resolve
  // inside the enforced scope BEFORE reading it — an out-of-scope (e.g. project)
  // file is never opened, let alone scanned, by this adapter, and the finding
  // referencing it is honestly reported as unredacted rather than silently dropped.
  const byFile = new Map<string, MaskedSecretFinding[]>();
  const outOfScope: MaskedSecretFinding[] = [];
  for (const finding of findings) {
    if (resolveRedactableArtifact(finding.where.filePath, scope) === null) {
      outOfScope.push(finding);
      continue;
    }
    const existing = byFile.get(finding.where.filePath);
    if (existing) existing.push(finding);
    else byFile.set(finding.where.filePath, [finding]);
  }
  if (byFile.size === 0) return { redactedKeys: 0, pointeredKeys: 0, unredacted: findings };

  // Every finding whose raw value could not be recovered — because its file
  // vanished/is unreadable, the re-scan found no matching occurrence, or it was
  // out-of-scope above — accumulates here. `recovered` pairs a finding with the
  // redaction target derived from it, so a struck/unstruck target can be traced
  // back to the finding it came from.
  // Whether a valid vault consent is on record. Without it no vault is ever
  // constructed and the strike below is byte-identical to the plain one-way
  // redaction. An unreadable settings file counts as no consent.
  const vaultConsented = hasValidVaultConsent(overrides.dataDirBase);

  const unrecovered: MaskedSecretFinding[] = [...outOfScope];
  const recovered: { finding: MaskedSecretFinding; recovery: RecoveredTarget }[] = [];
  try {
    const config = loadConfig(overrides.dataDirBase);
    const gateway = resolveDataGateway(config);
    const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
    try {
      for (const [filePath, fileFindings] of byFile) {
        let content: string;
        try {
          content = readFileSync(filePath, 'utf8');
        } catch {
          unrecovered.push(...fileFindings); // vanished/unreadable artifact — best-effort, skip it
          continue;
        }
        let matches: { ruleId: string; rawMatch: string; category: DetectionCategory }[];
        try {
          matches = (await runtime.processText(content)).findings;
        } catch {
          unrecovered.push(...fileFindings); // a scan failure on one artifact must not abort the others
          continue;
        }
        for (const finding of fileFindings) {
          const recovery = recoverTarget(finding, matches);
          if (recovery === undefined) unrecovered.push(finding);
          else recovered.push({ finding, recovery });
        }
      }
    } finally {
      try {
        await runtime.close();
      } catch {
        // Best-effort teardown: a close fault here must never rewrite the
        // outcome already computed above — the targets already recovered stay
        // recovered, and the redaction below still runs.
      }
    }
  } catch {
    // Config/store unavailable — recover nothing rather than break the session.
    return { redactedKeys: 0, pointeredKeys: 0, unredacted: findings };
  }

  // With a valid consent the strike becomes recoverable: each distinct raw
  // value is pre-resolved to a vault pointer, and the synchronous sweep below
  // substitutes those pointers instead of the one-way placeholder. Without
  // consent no map is built at all, so the sweep is the plain legacy strike.
  const replacements = vaultConsented
    ? await buildPointerReplacements(
        recovered.map((r) => r.recovery),
        overrides.dataDirBase,
      )
    : undefined;

  const { redactedKeys, pointeredKeys, struck } = redactLeakedKeysDetailed(
    recovered.map((r) => r.recovery.target),
    scope,
    replacements,
  );
  const struckTargets = new Set(struck);
  const unredacted = [
    ...unrecovered,
    ...recovered.filter((r) => !struckTargets.has(r.recovery.target)).map((r) => r.finding),
  ];
  return { redactedKeys, pointeredKeys, unredacted };
}
