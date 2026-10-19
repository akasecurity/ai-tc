import type { CredentialSightingsRequest } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  createCredentialSightingsSender,
  CREDENTIAL_SIGHTINGS_TIMEOUT_MS,
} from '../src/sightings-sender.ts';
import { useLoopbackServer } from './helpers/loopback.ts';

const CREDENTIAL = ['test', 'plugin', 'key'].join('-');

const request: CredentialSightingsRequest = {
  sightings: [
    {
      token: ['[[aka:fp:v2.', 'B'.repeat(43), ']]'].join(''),
      ruleId: 'aws-access-key',
      category: 'secret',
      locationClass: 'project-file',
      project: { projectKey: 'a'.repeat(64), name: 'acme/widgets' },
      gitTracked: false,
      seenAt: '2026-10-14T09:00:00.000Z',
    },
  ],
};

describe('createCredentialSightingsSender', () => {
  const server = useLoopbackServer();
  const connection = () => ({ endpoint: server.origin, apiKey: CREDENTIAL });

  it('posts the batch with the credential and reads the accepted count', async () => {
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"accepted":1}');
    });

    const result = await createCredentialSightingsSender()(connection(), request);

    expect(result).toEqual({ ok: true, accepted: 1 });
    const seen = server.received.at(-1);
    expect(`${seen?.method ?? ''} ${seen?.url ?? ''}`).toBe('POST /v1/credential-sightings');
    expect(seen?.headers['x-api-key']).toBe(CREDENTIAL);
    expect(JSON.parse(seen?.body ?? '')).toEqual(request);
  });

  it('names a deployment that predates the route', async () => {
    server.reply((_req, res) => {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{}');
    });

    expect(await createCredentialSightingsSender()(connection(), request)).toEqual({
      ok: false,
      kind: 'route-absent',
    });
  });

  it('reads a refusal off its status', async () => {
    server.reply((_req, res) => {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end('{}');
    });

    expect(await createCredentialSightingsSender()(connection(), request)).toEqual({
      ok: false,
      kind: 'unauthorized',
    });
  });

  it('reports unreachable for a closed port, without throwing', async () => {
    const closed = new URL(server.origin);
    closed.port = '1';

    expect(
      await createCredentialSightingsSender()(
        { endpoint: closed.origin, apiKey: CREDENTIAL },
        request,
      ),
    ).toEqual({ ok: false, kind: 'unreachable' });
  });

  it('refuses a body its own contract rejects, before the wire', async () => {
    const before = server.received.length;
    const sighting = { ...request.sightings[0], filePath: 'src/config.ts' };

    const result = await createCredentialSightingsSender()(connection(), {
      sightings: [sighting] as CredentialSightingsRequest['sightings'],
    });

    expect(result).toEqual({ ok: false, kind: 'invalid-request' });
    expect(server.received).toHaveLength(before);
  });

  it('carries a scan-sized deadline', () => {
    expect(CREDENTIAL_SIGHTINGS_TIMEOUT_MS).toBe(15_000);
  });
});
