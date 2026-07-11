// The interactive-IO seam for `aka exception`. Commands take a Prompter so
// tests can script answers and capture output; terminalPrompter() is the real
// implementation. The hidden prompt is hand-rolled over raw-mode stdin (echo
// suppressed) — deliberately NO new dependency, and the value is NEVER
// accepted via argv (shell history / `ps` would record it).
import { createInterface } from 'node:readline';

export interface Prompter {
  out(text: string): void;
  err(text: string): void;
  // True only when BOTH stdin and stdout are TTYs — prompts need to read and
  // to show their question.
  readonly isInteractive: boolean;
  /** Visible question → one line of input. */
  ask(question: string): Promise<string>;
  /** Question with echo suppressed (secrets). Requires isInteractive. */
  askHidden(question: string): Promise<string>;
  /** The whole of stdin (the --stdin value channel). */
  readAllStdin(): Promise<string>;
}

// Pure hidden-input character processing, extracted from the raw-mode loop so
// backspace/enter/Ctrl+C and control-byte filtering are unit-testable without
// a TTY. `esc` tracks an in-flight ANSI escape sequence (arrow keys, function
// keys) whose bytes must never leak into the captured secret — the user can't
// see the value, so silent corruption would be unrecoverable.
export interface HiddenInputState {
  value: string;
  // 'esc' = an ESC byte just arrived; 'seq' = inside a CSI/SS3 sequence whose
  // bytes run until a final byte in '@'..'~'.
  esc: 'none' | 'esc' | 'seq';
  done?: 'submit' | 'cancel';
}

export function processHiddenChar(state: HiddenInputState, ch: string): HiddenInputState {
  if (state.done) return state;
  if (state.esc === 'esc') {
    // ESC [ (CSI) and ESC O (SS3) open multi-byte sequences; anything else is
    // a two-byte sequence (Alt+key), consumed here.
    return ch === '[' || ch === 'O' ? { ...state, esc: 'seq' } : { ...state, esc: 'none' };
  }
  if (state.esc === 'seq') {
    return ch >= '@' && ch <= '~' ? { ...state, esc: 'none' } : state;
  }
  if (ch === '\r' || ch === '\n') return { ...state, done: 'submit' };
  if (ch === '\u0003') return { ...state, done: 'cancel' }; // Ctrl+C
  if (ch === '\u007f' || ch === '\b') return { ...state, value: state.value.slice(0, -1) };
  if (ch === '\u001b') return { ...state, esc: 'esc' }; // ESC opens a sequence
  if (ch < ' ') return state; // other C0 control bytes never join a secret
  return { ...state, value: state.value + ch };
}

// Signals that would otherwise kill the process mid-prompt with raw mode still
// on — leaving the user's shell with echo disabled. Restored first, then the
// signal is re-raised with its default disposition.
const CLEANUP_SIGNALS: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];

export function terminalPrompter(): Prompter {
  return {
    out: (text) => {
      process.stdout.write(text);
    },
    err: (text) => {
      process.stderr.write(text);
    },
    isInteractive: process.stdin.isTTY && process.stdout.isTTY,

    ask(question) {
      return new Promise((resolve) => {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        rl.question(question, (answer) => {
          rl.close();
          resolve(answer);
        });
      });
    },

    // Raw mode so nothing is echoed; characters are folded through
    // processHiddenChar. The captured value stays in this closure and is
    // handed to the caller only — never written anywhere. TTY restoration is
    // guaranteed via a one-shot `restore` that also runs on stdin errors and
    // fatal signals: a security tool must never brick the terminal it was
    // invoked from.
    askHidden(question) {
      return new Promise((resolve, reject) => {
        const stdin = process.stdin;
        process.stdout.write(question);
        stdin.setRawMode(true);
        stdin.resume();
        let state: HiddenInputState = { value: '', esc: 'none' };

        let restored = false;
        const restore = () => {
          if (restored) return;
          restored = true;
          stdin.removeListener('data', onData);
          stdin.removeListener('error', onError);
          for (const sig of CLEANUP_SIGNALS) process.removeListener(sig, onSignal);
          try {
            stdin.setRawMode(false);
          } catch {
            // The TTY may already be gone (hangup) — echo dies with it.
          }
          stdin.pause();
        };
        const finish = (err?: Error) => {
          restore();
          process.stdout.write('\n');
          if (err) reject(err);
          else resolve(state.value);
        };
        const onError = (err: Error) => {
          finish(err);
        };
        const onSignal = (sig: NodeJS.Signals) => {
          restore();
          // Re-raise with default disposition now that the TTY is sane.
          process.kill(process.pid, sig);
        };
        const onData = (chunk: Buffer) => {
          try {
            for (const ch of chunk.toString('utf8')) {
              state = processHiddenChar(state, ch);
              if (state.done === 'submit') {
                finish();
                return;
              }
              if (state.done === 'cancel') {
                finish(new Error('cancelled'));
                return;
              }
            }
          } catch (err) {
            finish(err instanceof Error ? err : new Error(String(err)));
          }
        };

        stdin.on('data', onData);
        stdin.once('error', onError);
        for (const sig of CLEANUP_SIGNALS) process.once(sig, onSignal);
      });
    },

    async readAllStdin() {
      const chunks: Buffer[] = [];
      for await (const chunk of process.stdin) {
        chunks.push(chunk as Buffer);
      }
      return Buffer.concat(chunks).toString('utf8');
    },
  };
}
