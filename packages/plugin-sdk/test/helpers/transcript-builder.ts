import { randomBytes, randomUUID } from 'node:crypto';
import { appendFileSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { attachedUserDigestOf, sessionAccountsDir } from '@akasecurity/persistence';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { AccountContext } from '../../src/account/account-check.ts';

// Synthetic Claude Code transcripts and a throwaway machine to read them on.
// Every org id is a fresh randomUUID() and every address is assembled at run
// time, so no real or address-shaped literal is committed.

/** An address on the reserved test domain, assembled at run time. */
export function fixtureEmail(local: string): string {
  return [local, 'example.test'].join('@');
}

/** A host that is not the default API host, assembled at run time. */
export function otherHost(): string {
  return ['gateway', randomBytes(3).toString('hex'), 'example', 'test'].join('.');
}

export const T0 = Date.parse('2026-01-05T10:00:00.000Z');
export const SECOND = 1_000;
export const MINUTE = 60 * SECOND;

const iso = (t: number): string => new Date(t).toISOString();

/** The record the host writes when a request's organization differs from the last one in context. */
export function credentialOrgLine(sessionId: string, org: string, t: number): string {
  return JSON.stringify({
    parentUuid: null,
    isSidechain: false,
    type: 'attachment',
    attachment: { type: 'credential_org', organizationUuid: org },
    uuid: randomUUID(),
    timestamp: iso(t),
    sessionId,
  });
}

export function userPromptLine(sessionId: string, text: string, t: number): string {
  return JSON.stringify({
    type: 'user',
    message: { role: 'user', content: text },
    uuid: randomUUID(),
    timestamp: iso(t),
    sessionId,
  });
}

export function assistantLine(sessionId: string, t: number, id: string = randomUUID()): string {
  return JSON.stringify({
    type: 'assistant',
    message: {
      id,
      role: 'assistant',
      model: 'claude-sonnet-4-5',
      content: [{ type: 'text', text: 'ok' }],
    },
    uuid: randomUUID(),
    timestamp: iso(t),
    sessionId,
  });
}

/** A tool result whose structured output is shaped like a credential_org record. */
export function toolOutputLine(sessionId: string, org: string, t: number): string {
  return JSON.stringify({
    type: 'user',
    message: {
      role: 'user',
      content: [{ type: 'tool_result', tool_use_id: randomUUID(), content: 'done' }],
    },
    toolUseResult: { type: 'credential_org', organizationUuid: org },
    uuid: randomUUID(),
    timestamp: iso(t),
    sessionId,
  });
}

export function writeLines(path: string, lines: readonly string[]): void {
  writeFileSync(path, lines.map((line) => `${line}\n`).join(''));
}

export function appendLines(path: string, lines: readonly string[]): void {
  appendFileSync(path, lines.map((line) => `${line}\n`).join(''));
}

export type SettingsLayer = 'user' | 'project' | 'local' | 'managed';

export interface ContextOptions {
  readonly on?: boolean;
  readonly learned?: readonly string[];
  readonly manual?: readonly string[];
  readonly inScope?: (accountKey: string) => boolean;
  readonly email?: string;
  readonly bindingHash?: string;
}

export interface ClaudeMachine {
  readonly root: string;
  readonly home: string;
  readonly cwd: string;
  readonly dataDir: string;
  readonly stateDir: string;
  readonly transcript: string;
  readonly sessionId: string;
  readonly email: string;
  readonly bindingHash: string;
  readonly paths: { readonly home: string; readonly managedSettings: string };
  writeConfig(config: unknown): void;
  writeSettings(layer: SettingsLayer, settings: unknown): void;
  context(options?: ContextOptions): AccountContext;
  dispose(): void;
}

/**
 * A home with a Claude Code config, a project directory, an AKA data dir, a
 * transcript path and a managed-settings path, all under one temp root. The
 * managed path is the temp one, so no test reads the machine's real file.
 */
export function claudeMachine(): ClaudeMachine {
  const root = mkdtempSync(join(tmpdir(), 'aka-claude-account-'));
  const home = join(root, 'home');
  const cwd = join(root, 'work');
  const dataDir = join(root, 'aka');
  for (const dir of [home, cwd, dataDir]) mkdirSync(dir, { recursive: true });
  const managedSettings = join(root, 'managed', 'managed-settings.json');
  const email = fixtureEmail(`dev-${randomBytes(3).toString('hex')}`);
  const bindingHash = randomBytes(8).toString('hex');
  const layerPath: Record<SettingsLayer, string> = {
    user: join(home, '.claude', 'settings.json'),
    project: join(cwd, '.claude', 'settings.json'),
    local: join(cwd, '.claude', 'settings.local.json'),
    managed: managedSettings,
  };
  return {
    root,
    home,
    cwd,
    dataDir,
    stateDir: sessionAccountsDir(dataDir),
    transcript: join(root, 'session.jsonl'),
    sessionId: randomUUID(),
    email,
    bindingHash,
    paths: { home, managedSettings },
    writeConfig: (config) => {
      writeFileSync(join(home, '.claude.json'), JSON.stringify(config));
    },
    writeSettings: (layer, settings) => {
      const path = layerPath[layer];
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, typeof settings === 'string' ? settings : JSON.stringify(settings));
    },
    context: (options = {}) => {
      const digest = attachedUserDigestOf(options.email ?? email);
      if (digest === undefined) throw new Error('the fixture address does not normalise');
      return {
        bindingHash: options.bindingHash ?? bindingHash,
        attachedUserDigest: digest,
        workSubscriptionsOn: options.on ?? true,
        learned: (options.learned ?? []).map((identity) => ({
          kind: 'account' as const,
          identity,
          label: 'Claude work account',
          enrolledAt: new Date(T0).toISOString(),
        })),
        manual: [...(options.manual ?? [])],
        inScope: options.inScope ?? (() => false),
      };
    },
    dispose: () => {
      removeTree(root);
    },
  };
}

/** A work login's config: a company plan, `email`, and a fresh slot on the same org. */
export function workConfig(
  org: string,
  email: string,
  account: Readonly<Record<string, unknown>> = {},
  extra: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    oauthAccount: {
      organizationUuid: org,
      emailAddress: email,
      organizationType: 'claude_team',
      ...account,
    },
    clientDataCacheSlots: { [`slot-${org}`]: { data: null, at: T0, org } },
    ...extra,
  };
}
