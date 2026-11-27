import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { join } from 'node:path';

// Reads the string values of Codex's `config.toml` with a small TOML reader:
// tables, dotted and quoted keys, the four string forms, arrays and inline
// tables. Other scalars are skipped. Any syntax it cannot follow makes the
// whole read undefined.

export const CODEX_CONFIG_MAX_BYTES = 1024 * 1024;

const MAX_DEPTH = 32;

type KeyPath = readonly string[];

const pathKey = (path: KeyPath): string => JSON.stringify(path);

class Malformed extends Error {}

class TomlStrings {
  readonly values = new Map<string, string>();
  private i = 0;

  constructor(private readonly src: string) {}

  read(): Map<string, string> {
    let table: KeyPath = [];
    for (;;) {
      this.skipBlankLines();
      if (this.i >= this.src.length) return this.values;
      if (this.src.startsWith('[[', this.i)) {
        this.i += 2;
        this.readKey();
        this.expect(']]');
        // An array-of-tables entry is not addressable by a plain key path.
        table = ['[[]]'];
      } else if (this.src[this.i] === '[') {
        this.i += 1;
        table = this.readKey();
        this.expect(']');
      } else {
        const key = this.readKey();
        this.skipSpace();
        this.expect('=');
        this.skipSpace();
        this.readValue([...table, ...key], 0);
      }
      this.endLine();
    }
  }

  private peek(): string | undefined {
    return this.src[this.i];
  }

  private expect(token: string): void {
    this.skipSpace();
    if (!this.src.startsWith(token, this.i)) throw new Malformed();
    this.i += token.length;
  }

  private skipSpace(): void {
    while (this.peek() === ' ' || this.peek() === '\t') this.i += 1;
  }

  private skipComment(): void {
    if (this.peek() !== '#') return;
    while (this.i < this.src.length && this.peek() !== '\n') this.i += 1;
  }

  /** Whitespace, newlines and comments. */
  private skipBlankLines(): void {
    for (;;) {
      this.skipSpace();
      this.skipComment();
      if (this.peek() === '\n') this.i += 1;
      else if (this.src.startsWith('\r\n', this.i)) this.i += 2;
      else return;
    }
  }

  private endLine(): void {
    this.skipSpace();
    this.skipComment();
    if (this.i >= this.src.length) return;
    if (this.peek() === '\n') this.i += 1;
    else if (this.src.startsWith('\r\n', this.i)) this.i += 2;
    else throw new Malformed();
  }

  private readKey(): string[] {
    const parts: string[] = [];
    for (;;) {
      this.skipSpace();
      const c = this.peek();
      if (c === '"' || c === "'") {
        if (this.src.startsWith(c.repeat(3), this.i)) throw new Malformed();
        parts.push(this.readString());
      } else {
        const start = this.i;
        while (/[A-Za-z0-9_-]/.test(this.peek() ?? '')) this.i += 1;
        if (this.i === start) throw new Malformed();
        parts.push(this.src.slice(start, this.i));
      }
      this.skipSpace();
      if (this.peek() !== '.') return parts;
      this.i += 1;
    }
  }

  private readValue(path: KeyPath, depth: number): void {
    if (depth > MAX_DEPTH) throw new Malformed();
    const c = this.peek();
    if (c === '"' || c === "'") {
      this.values.set(pathKey(path), this.readString());
    } else if (c === '[') {
      this.readArray(depth);
    } else if (c === '{') {
      this.readInlineTable(path, depth);
    } else {
      const start = this.i;
      while (this.i < this.src.length && !/[\s,\]}#]/.test(this.src[this.i] ?? '')) this.i += 1;
      if (this.i === start) throw new Malformed();
    }
  }

  private readArray(depth: number): void {
    this.i += 1;
    for (;;) {
      this.skipBlankLines();
      if (this.peek() === ']') {
        this.i += 1;
        return;
      }
      this.readValue(['[]'], depth + 1);
      this.skipBlankLines();
      if (this.peek() === ',') this.i += 1;
      else if (this.peek() !== ']') throw new Malformed();
    }
  }

  private readInlineTable(path: KeyPath, depth: number): void {
    this.i += 1;
    for (;;) {
      this.skipBlankLines();
      if (this.peek() === '}') {
        this.i += 1;
        return;
      }
      const key = this.readKey();
      this.expect('=');
      this.skipSpace();
      this.readValue([...path, ...key], depth + 1);
      this.skipBlankLines();
      if (this.peek() === ',') this.i += 1;
      else if (this.peek() !== '}') throw new Malformed();
    }
  }

  private readString(): string {
    const quote = this.peek() === "'" ? "'" : '"';
    const multi = this.src.startsWith(quote.repeat(3), this.i);
    const delimiter = multi ? quote.repeat(3) : quote;
    this.i += delimiter.length;
    if (multi && this.src.startsWith('\r\n', this.i)) this.i += 2;
    else if (multi && this.peek() === '\n') this.i += 1;
    let out = '';
    for (;;) {
      if (this.i >= this.src.length) throw new Malformed();
      if (this.src.startsWith(delimiter, this.i)) {
        this.i += delimiter.length;
        return out;
      }
      const c = this.src[this.i] ?? '';
      if (c === '\n' && !multi) throw new Malformed();
      if (c === '\\' && quote === '"') {
        if (multi && /^\\[ \t]*\r?\n/.test(this.src.slice(this.i, this.i + 64))) {
          this.i += 1;
          while (/\s/.test(this.src[this.i] ?? '')) this.i += 1;
          continue;
        }
        out += this.readEscape();
        continue;
      }
      out += c;
      this.i += 1;
    }
  }

  private readEscape(): string {
    const c = this.src[this.i + 1];
    this.i += 2;
    switch (c) {
      case '"':
        return '"';
      case '\\':
        return '\\';
      case 'b':
        return '\b';
      case 'f':
        return '\f';
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case 't':
        return '\t';
      case 'u':
      case 'U': {
        const width = c === 'u' ? 4 : 8;
        const hex = this.src.slice(this.i, this.i + width);
        if (!new RegExp(`^[0-9A-Fa-f]{${String(width)}}$`).test(hex)) throw new Malformed();
        this.i += width;
        const code = Number.parseInt(hex, 16);
        if (code > 0x10ffff) throw new Malformed();
        return String.fromCodePoint(code);
      }
      default:
        throw new Malformed();
    }
  }
}

/** Every string value in a TOML document, keyed by its key path; undefined when it cannot be read. */
export function parseTomlStrings(src: string): ReadonlyMap<string, string> | undefined {
  try {
    return new TomlStrings(src).read();
  } catch (error) {
    if (error instanceof Malformed) return undefined;
    throw error;
  }
}

function readBoundedText(path: string): string | undefined {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    return undefined;
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > CODEX_CONFIG_MAX_BYTES) return undefined;
    const buffer = Buffer.alloc(stat.size);
    let read = 0;
    while (read < stat.size) {
      const n = readSync(fd, buffer, read, stat.size - read, read);
      if (n === 0) break;
      read += n;
    }
    return buffer.subarray(0, read).toString('utf8');
  } catch {
    return undefined;
  } finally {
    try {
      closeSync(fd);
    } catch {
      // already closed
    }
  }
}

/**
 * The `base_url` of the model provider `<codexHome>/config.toml` selects: the
 * active profile's `model_provider`, else the top-level one. Undefined when the
 * file is missing, unreadable, over 1 MiB or not readable as TOML, or when the
 * selected provider has no `base_url`.
 */
export function readCodexActiveProviderBaseUrl(codexHome: string): string | undefined {
  const text = readBoundedText(join(codexHome, 'config.toml'));
  if (text === undefined) return undefined;
  const values = parseTomlStrings(text);
  if (values === undefined) return undefined;
  const profile = values.get(pathKey(['profile']));
  const active =
    (profile === undefined
      ? undefined
      : values.get(pathKey(['profiles', profile, 'model_provider']))) ??
    values.get(pathKey(['model_provider']));
  if (active === undefined) return undefined;
  return values.get(pathKey(['model_providers', active, 'base_url']));
}
