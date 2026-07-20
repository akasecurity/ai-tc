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
  loadConfig,
  resolveRepo,
  safeMaskedMatch,
} from '@akasecurity/plugin-sdk';
import type { MaskedSecretFinding } from '@akasecurity/schema';

import { transcriptsDir } from '../history/transcripts.ts';
import { deriveProvider } from '../triage/surfaced-secrets.ts';
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

// One recovered (finding, rawValue) redaction target, or undefined when no
// on-disk occurrence matching this finding's (provider, maskedToken) pair was
// found in the scanned content.
function recoverTarget(
  finding: MaskedSecretFinding,
  matches: readonly { ruleId: string; rawMatch: string }[],
): RedactionTarget | undefined {
  const hit = matches.find(
    (m) =>
      deriveProvider(m.ruleId) === finding.provider &&
      safeMaskedMatch(m.rawMatch) === finding.maskedToken,
  );
  return hit === undefined ? undefined : { where: finding.where, rawValue: hit.rawMatch };
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
 */
export async function redactSurfacedSecrets(
  findings: readonly MaskedSecretFinding[],
  overrides: RedactSurfacedSecretsOverrides = {},
): Promise<SurfacedRedactionResult> {
  if (findings.length === 0) return { redactedKeys: 0, unredacted: [] };
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
  if (byFile.size === 0) return { redactedKeys: 0, unredacted: findings };

  // Every finding whose raw value could not be recovered — because its file
  // vanished/is unreadable, the re-scan found no matching occurrence, or it was
  // out-of-scope above — accumulates here. `recovered` pairs a finding with the
  // redaction target derived from it, so a struck/unstruck target can be traced
  // back to the finding it came from.
  const unrecovered: MaskedSecretFinding[] = [...outOfScope];
  const recovered: { finding: MaskedSecretFinding; target: RedactionTarget }[] = [];
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
        let matches: { ruleId: string; rawMatch: string }[];
        try {
          matches = (await runtime.processText(content)).findings;
        } catch {
          unrecovered.push(...fileFindings); // a scan failure on one artifact must not abort the others
          continue;
        }
        for (const finding of fileFindings) {
          const target = recoverTarget(finding, matches);
          if (target === undefined) unrecovered.push(finding);
          else recovered.push({ finding, target });
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
    return { redactedKeys: 0, unredacted: findings };
  }

  const { redactedKeys, struck } = redactLeakedKeysDetailed(
    recovered.map((r) => r.target),
    scope,
  );
  const struckTargets = new Set(struck);
  const unredacted = [
    ...unrecovered,
    ...recovered.filter((r) => !struckTargets.has(r.target)).map((r) => r.finding),
  ];
  return { redactedKeys, unredacted };
}
