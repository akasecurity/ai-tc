import type { Readable, Writable } from 'node:stream';

// Chrome's native-messaging limits are asymmetric: messages TO the host
// (extension→host, the read direction here) may be far larger than messages
// FROM the host, which Chrome caps at 1 MB and answers by killing the port.
// The read bound below exists only so a corrupt/adversarial length prefix
// fails loudly instead of buffering unbounded data — it is deliberately far
// above any legitimate prompt paste. The write direction is kept under
// Chrome's cap by the host omitting large echo fields, not by this module
// (see CaptureResponse.text in protocol.ts).
const MAX_READ_MESSAGE_BYTES = 64 * 1024 * 1024;

/**
 * Chrome's native-messaging stdio framing: each message is a 4-byte
 * little-endian length prefix followed by that many bytes of UTF-8 JSON —
 * used for both the extension→host and host→extension directions. Yields one
 * parsed message per complete frame as bytes arrive; a malformed frame (JSON
 * parse failure or an over-limit length prefix) ends the generator by
 * throwing, since the byte stream can no longer be trusted to resync.
 */
export async function* readMessages(stdin: Readable): AsyncGenerator {
  let buffer = Buffer.alloc(0);
  for await (const chunk of stdin) {
    buffer = Buffer.concat([buffer, chunk as Buffer]);
    for (;;) {
      if (buffer.length < 4) break;
      const length = buffer.readUInt32LE(0);
      if (length > MAX_READ_MESSAGE_BYTES) {
        throw new Error(
          `native-messaging: frame of ${length.toString()} bytes exceeds the ${MAX_READ_MESSAGE_BYTES.toString()}-byte limit`,
        );
      }
      if (buffer.length < 4 + length) break;
      const body = buffer.subarray(4, 4 + length);
      buffer = buffer.subarray(4 + length);
      yield JSON.parse(body.toString('utf8')) as unknown;
    }
  }
}

export function writeMessage(stdout: Writable, message: unknown): Promise<void> {
  const body = Buffer.from(JSON.stringify(message), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  return new Promise((resolve, reject) => {
    stdout.write(Buffer.concat([header, body]), (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}
