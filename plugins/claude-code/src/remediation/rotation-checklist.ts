import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { resolveRepo, resolveWorktreeRoot } from '@akasecurity/plugin-sdk';
import type { MaskedSecretFinding, RotationChecklistEntry } from '@akasecurity/schema';

const GENERIC_CONSOLE_PATH = "rotate via the provider's own console";

const CONSOLE_PATHS: Readonly<Record<string, string>> = {
  anthropic: 'console.anthropic.com → Settings → API keys',
  aws: 'console.aws.amazon.com → IAM → Security credentials',
  azure: 'portal.azure.com → App registrations → Certificates & secrets',
  cloudflare: 'dash.cloudflare.com → My Profile → API Tokens',
  datadog: 'app.datadoghq.com → Organization Settings → API Keys',
  digitalocean: 'cloud.digitalocean.com → API → Tokens',
  discord: 'discord.com/developers/applications → Bot → Reset Token',
  gcp: 'console.cloud.google.com → IAM & Admin → Service Accounts → Keys',
  github: 'github.com → Settings → Developer settings → Personal access tokens',
  gitlab: 'gitlab.com → Preferences → Access Tokens',
  heroku: 'dashboard.heroku.com → Account settings → API Key',
  npm: 'npmjs.com → Access Tokens',
  openai: 'platform.openai.com → API keys',
  pulumi: 'app.pulumi.com → Settings → Access Tokens',
  sendgrid: 'app.sendgrid.com → Settings → API Keys',
  slack: 'api.slack.com/apps → OAuth & Permissions',
  stripe: 'dashboard.stripe.com → Developers → API keys',
  terraform: 'app.terraform.io → User settings → Tokens',
  twilio: 'console.twilio.com → Account → API keys & tokens',
  vault: 'rotate or revoke the token through the configured Vault operator workflow',
};

interface GroupedFinding {
  readonly provider: string;
  readonly maskedToken: string;
  readonly filePaths: Set<string>;
  oldestObservedAt?: string;
}

interface RotationChecklistTarget {
  readonly directory: string;
  readonly locationLabel: string;
}

export type RotationChecklistGenerationResult =
  | {
      readonly status: 'written';
      readonly filePath: string;
      readonly locationLabel: string;
      readonly resolvedLine: string;
    }
  | {
      readonly status: 'degraded';
      readonly note: string;
    };

function compareText(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

export function consolePathForProvider(provider: string): string {
  return CONSOLE_PATHS[provider] ?? GENERIC_CONSOLE_PATH;
}

export function buildChecklistEntries(
  findings: readonly MaskedSecretFinding[],
): RotationChecklistEntry[] {
  const groupsByProvider = new Map<string, Map<string, GroupedFinding>>();

  for (const finding of findings) {
    let providerGroups = groupsByProvider.get(finding.provider);
    if (providerGroups === undefined) {
      providerGroups = new Map();
      groupsByProvider.set(finding.provider, providerGroups);
    }

    let group = providerGroups.get(finding.maskedToken);
    if (group === undefined) {
      group = {
        provider: finding.provider,
        maskedToken: finding.maskedToken,
        filePaths: new Set(),
      };
      providerGroups.set(finding.maskedToken, group);
    }

    group.filePaths.add(finding.where.filePath);
    if (
      finding.observedAt !== undefined &&
      (group.oldestObservedAt === undefined || finding.observedAt < group.oldestObservedAt)
    ) {
      group.oldestObservedAt = finding.observedAt;
    }
  }

  const groups = [...groupsByProvider.values()].flatMap((providerGroups) => [
    ...providerGroups.values(),
  ]);
  groups.sort((left, right) => {
    const spreadDifference = right.filePaths.size - left.filePaths.size;
    if (spreadDifference !== 0) return spreadDifference;

    if (left.oldestObservedAt !== right.oldestObservedAt) {
      if (left.oldestObservedAt === undefined) return 1;
      if (right.oldestObservedAt === undefined) return -1;
      const ageDifference = compareText(left.oldestObservedAt, right.oldestObservedAt);
      if (ageDifference !== 0) return ageDifference;
    }

    const providerDifference = compareText(left.provider, right.provider);
    return providerDifference !== 0
      ? providerDifference
      : compareText(left.maskedToken, right.maskedToken);
  });

  return groups.map((group) => ({
    provider: group.provider,
    maskedToken: group.maskedToken,
    consolePath: consolePathForProvider(group.provider),
    occurrenceSpread: group.filePaths.size,
  }));
}

export function renderChecklistMarkdown(entries: readonly RotationChecklistEntry[]): string {
  if (entries.length === 0) return '';
  return `${entries
    .map((entry) => `- [ ] ${entry.provider} — ${entry.maskedToken} — ${entry.consolePath}`)
    .join('\n')}\n`;
}

export function renderRotationChecklistResolvedLine(location: string): string {
  return `✓ Drafted rotation-checklist.md (${location})`;
}

export function writeRotationChecklist(
  entries: readonly RotationChecklistEntry[],
  targetDirectory: string,
): void {
  writeFileSync(
    `${targetDirectory}/rotation-checklist.md`,
    renderChecklistMarkdown(entries),
    'utf8',
  );
}

export function resolveRotationChecklistTarget(cwd: string): RotationChecklistTarget {
  const repoRoot = resolveRepo(cwd) === undefined ? undefined : resolveWorktreeRoot(cwd);
  return repoRoot === undefined
    ? { directory: cwd, locationLabel: `invocation working directory: ${cwd}` }
    : { directory: repoRoot, locationLabel: 'repo root' };
}

export function generateRotationChecklist(input: {
  readonly entries: readonly RotationChecklistEntry[];
  readonly cwd: string;
}): RotationChecklistGenerationResult {
  let targetDirectory = input.cwd;
  try {
    const target = resolveRotationChecklistTarget(input.cwd);
    targetDirectory = target.directory;
    const filePath = join(target.directory, 'rotation-checklist.md');
    writeRotationChecklist(input.entries, target.directory);
    return {
      status: 'written',
      filePath,
      locationLabel: target.locationLabel,
      resolvedLine: renderRotationChecklistResolvedLine(target.locationLabel),
    };
  } catch {
    return {
      status: 'degraded',
      note: `Could not draft rotation-checklist.md at ${targetDirectory}.`,
    };
  }
}
