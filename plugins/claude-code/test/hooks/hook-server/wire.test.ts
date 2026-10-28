import { describe, expect, it } from 'vitest';

import {
  FALLBACK_RESPONSE,
  MAX_REQUEST_BYTES,
  okResponse,
  parseRequest,
} from '../../../src/hooks/hook-server/wire.ts';

const frame = (head: string[], payload: string): Buffer =>
  Buffer.concat([
    Buffer.from(`${head.join('\n')}\nP ${String(Buffer.byteLength(payload))}\n`, 'utf8'),
    Buffer.from(payload, 'utf8'),
  ]);

describe('parseRequest', () => {
  it('reads the hook, the working directory, the variables and the payload', () => {
    const parsed = parseRequest(
      frame(
        [
          'AKA-HOOK 1 pre-tool-use',
          'C /work/dir',
          'E CLAUDE_CONFIG_DIR /home/a/.claude',
          'E X_Y 1',
        ],
        '{"tool_name":"Bash"}',
      ),
    );
    expect(parsed).toEqual({
      kind: 'request',
      request: {
        hook: 'pre-tool-use',
        cwd: '/work/dir',
        env: { CLAUDE_CONFIG_DIR: '/home/a/.claude', X_Y: '1' },
        payload: '{"tool_name":"Bash"}',
      },
    });
  });

  it('counts the payload in bytes, so multi-byte text and newlines survive whole', () => {
    const payload = '{"command":"echo héllo\\n日本語"}\nsecond line';
    const parsed = parseRequest(frame(['AKA-HOOK 1 pre-tool-use'], payload));
    expect(parsed.kind === 'request' && parsed.request.payload).toBe(payload);
  });

  it('keeps a space-containing variable value whole', () => {
    const parsed = parseRequest(
      frame(['AKA-HOOK 1 pre-tool-use', 'E CLAUDE_CODE_USER_EMAIL a b  c'], '{}'),
    );
    expect(parsed.kind === 'request' && parsed.request.env.CLAUDE_CODE_USER_EMAIL).toBe('a b  c');
  });

  it('is incomplete until the whole payload has arrived', () => {
    const whole = frame(['AKA-HOOK 1 pre-tool-use'], '{"a":1}');
    for (let cut = 0; cut < whole.length; cut += 1) {
      expect(parseRequest(whole.subarray(0, cut)).kind).toBe('incomplete');
    }
    expect(parseRequest(whole).kind).toBe('request');
  });

  it.each([
    ['a different protocol', 'AKA-HOOK 2 pre-tool-use\nP 0\n'],
    ['no magic', 'GET / HTTP/1.1\nP 0\n'],
    ['an upper-case hook name', 'AKA-HOOK 1 Pre\nP 0\n'],
    ['a path-like hook name', 'AKA-HOOK 1 ../x\nP 0\n'],
    ['a lower-case variable name', 'AKA-HOOK 1 pre-tool-use\nE path /x\nP 0\n'],
    ['a variable with no value slot', 'AKA-HOOK 1 pre-tool-use\nE NAME\nP 0\n'],
    ['an unknown line', 'AKA-HOOK 1 pre-tool-use\nZ nope\nP 0\n'],
    ['a negative length', 'AKA-HOOK 1 pre-tool-use\nP -1\n'],
    ['a non-numeric length', 'AKA-HOOK 1 pre-tool-use\nP lots\n'],
    ['a payload over the limit', `AKA-HOOK 1 pre-tool-use\nP ${String(MAX_REQUEST_BYTES + 1)}\n`],
  ])('refuses %s', (_name, text) => {
    expect(parseRequest(Buffer.from(text)).kind).toBe('invalid');
  });

  it('refuses a first line that never ends', () => {
    expect(parseRequest(Buffer.alloc(300, 0x61)).kind).toBe('invalid');
  });
});

describe('responses', () => {
  it('puts the status on its own line, then the hook output untouched', () => {
    expect(okResponse('{"a":1}')).toBe('OK\n{"a":1}');
    expect(okResponse('')).toBe('OK\n');
    expect(FALLBACK_RESPONSE).toBe('FALLBACK\n');
  });
});
