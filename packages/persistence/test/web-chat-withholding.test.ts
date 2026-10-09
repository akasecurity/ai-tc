import { writeFileSync } from 'node:fs';

import type { AttachedCredentialAny, ControlPlaneConnection } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  controlPlaneCredentialPath,
  writeControlPlaneCredential,
} from '../src/control-plane-credential.ts';
import { DATA_FILE_MODE } from '../src/paths.ts';
import { webChatWithholding } from '../src/web-chat-withholding.ts';
import { useTempStore } from './helpers/temp-store.ts';

// When a machine records a web chat at all. It records one only when it is
// known not to be a personal device, so every state this cannot read as
// machine-wide withholds, and only an absent credential beside no stored scope,
// or a usable machine credential, records.

const store = useTempStore('aka-web-chat-withholding-');

const ENDPOINT = 'https://cp.example';
const AT = '2026-10-01T00:00:00.000Z';
// A plain word standing in for the key.
const KEY = 'placeholder';
const CONNECTION: ControlPlaneConnection = { endpoint: ENDPOINT, attachedAt: AT };
const MACHINE: AttachedCredentialAny = {
  specVersion: 1,
  endpoint: ENDPOINT,
  apiKey: KEY,
  mintedAt: AT,
};
const SCOPED: AttachedCredentialAny = {
  specVersion: 2,
  mode: 'scoped',
  endpoint: ENDPOINT,
  apiKey: KEY,
  mintedAt: AT,
};
const SCOPE = { endpoint: ENDPOINT, entries: [] };

function writeRaw(text: string): void {
  writeFileSync(controlPlaneCredentialPath(store.settingsDir), text, { mode: DATA_FILE_MODE });
}

describe('webChatWithholding records a chat', () => {
  it('on a machine that was never attached', () => {
    expect(webChatWithholding(store.settingsDir, {})).toBeNull();
  });

  it('on a machine-wide attachment', () => {
    writeControlPlaneCredential(store.settingsDir, MACHINE);
    expect(webChatWithholding(store.settingsDir, { controlPlane: CONNECTION })).toBeNull();
  });

  it('on half an attachment with no credential and no stored scope', () => {
    expect(webChatWithholding(store.settingsDir, { controlPlane: CONNECTION })).toBeNull();
  });
});

describe('webChatWithholding withholds a chat', () => {
  it('on a personal device', () => {
    writeControlPlaneCredential(store.settingsDir, SCOPED);
    expect(webChatWithholding(store.settingsDir, { controlPlane: CONNECTION })).toBe(
      'personal-device',
    );
  });

  it('on a stored scope beside a machine credential, as a scoped attach leaves it midway', () => {
    writeControlPlaneCredential(store.settingsDir, MACHINE);
    expect(
      webChatWithholding(store.settingsDir, { controlPlane: CONNECTION, attachmentScope: SCOPE }),
    ).toBe('personal-device');
  });

  it('on a stored scope with no credential yet', () => {
    expect(
      webChatWithholding(store.settingsDir, { controlPlane: CONNECTION, attachmentScope: SCOPE }),
    ).toBe('personal-device');
  });

  it('on a scoped credential whose settings name no connection', () => {
    writeControlPlaneCredential(store.settingsDir, SCOPED);
    expect(webChatWithholding(store.settingsDir, {})).toBe('personal-device');
  });

  it('on a credential that does not parse', () => {
    writeRaw('{ not json');
    expect(webChatWithholding(store.settingsDir, { controlPlane: CONNECTION })).toBe(
      'unreadable-attachment',
    );
  });

  it('on a credential for another deployment than the settings name', () => {
    writeControlPlaneCredential(store.settingsDir, MACHINE);
    expect(
      webChatWithholding(store.settingsDir, {
        controlPlane: { endpoint: 'https://other.example', attachedAt: AT },
      }),
    ).toBe('unreadable-attachment');
  });
});
