// A client for the hook server's unix socket, for the suites that drive the server
// directly. The only test file that imports `node:net`; eslint.config.mjs opts it
// out by name.
import { createConnection } from 'node:net';

/**
 * Sends one frame and returns everything the server writes back before it closes.
 * With `halfClose`, the sending side is closed after the frame, the way the shell
 * client does before it waits for the answer.
 */
export function sendFrame(socketPath: string, frame: string, halfClose = false): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let out = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      out += chunk;
    });
    socket.on('end', () => {
      resolve(out);
    });
    socket.on('error', reject);
    if (halfClose) socket.end(frame);
    else socket.write(frame);
  });
}
