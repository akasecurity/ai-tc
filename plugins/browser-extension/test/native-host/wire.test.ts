import { PassThrough } from 'node:stream';

import { describe, expect, it } from 'vitest';

import { readMessages, writeMessage } from '../../src/native-host/wire.ts';

describe('native-messaging wire framing', () => {
  it('round-trips messages through the same length-prefixed framing used to write them', async () => {
    const stream = new PassThrough();
    const received: unknown[] = [];
    const reader = (async () => {
      for await (const message of readMessages(stream)) {
        received.push(message);
        if (received.length === 2) return;
      }
    })();

    await writeMessage(stream, { type: 'ping', requestId: '1' });
    await writeMessage(stream, {
      type: 'session_start',
      requestId: '2',
      sessionId: 's',
      tool: 'chatgpt',
      hostname: 'chatgpt.com',
    });
    await reader;

    expect(received).toEqual([
      { type: 'ping', requestId: '1' },
      {
        type: 'session_start',
        requestId: '2',
        sessionId: 's',
        tool: 'chatgpt',
        hostname: 'chatgpt.com',
      },
    ]);
  });

  it('reassembles a single message delivered as many separate byte-sized stream chunks', async () => {
    const stream = new PassThrough();
    const body = Buffer.from(JSON.stringify({ type: 'ping', requestId: 'x' }), 'utf8');
    const header = Buffer.alloc(4);
    header.writeUInt32LE(body.length, 0);
    const frame = Buffer.concat([header, body]);

    const reader = (async () => {
      for await (const message of readMessages(stream)) {
        return message;
      }
      return undefined;
    })();

    for (const byte of frame) {
      stream.write(Buffer.from([byte]));
    }
    stream.end();

    expect(await reader).toEqual({ type: 'ping', requestId: 'x' });
  });

  it('rejects a frame whose declared length exceeds the message size cap', async () => {
    const stream = new PassThrough();
    const header = Buffer.alloc(4);
    header.writeUInt32LE(65 * 1024 * 1024, 0); // over the 64MB read cap
    stream.write(header);
    stream.end();

    await expect(readMessages(stream).next()).rejects.toThrow(/exceeds the/);
  });
});
