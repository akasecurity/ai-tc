// Minimal edits to a JSON-with-comments document — VS Code's settings.json —
// that leave every line they do not change byte for byte, comments included.
//
// Only TOP-LEVEL properties are edited, and a property's value is replaced
// whole. That is all the VS Code installer needs: it sets two booleans and one
// object, and a comment inside the one object it rewrites is the only text an
// edit can drop.
//
// Pure string functions, so they unit-test without touching a real file.

/** A top-level property's location in the source text. */
interface PropertySpan {
  key: string;
  /** Index of the key's opening quote. */
  start: number;
  /** Index of the value's first character. */
  valueStart: number;
  /** Index one past the value's last character. */
  valueEnd: number;
}

interface Layout {
  /** Index of the root object's `{`. */
  open: number;
  /** Index of the root object's `}`. */
  close: number;
  properties: PropertySpan[];
}

/** Skip whitespace and comments from `i`; returns the next meaningful index. */
function skipTrivia(text: string, i: number): number {
  let at = i;
  for (;;) {
    while (at < text.length && /\s/u.test(text.charAt(at))) at += 1;
    if (text.startsWith('//', at)) {
      const end = text.indexOf('\n', at);
      at = end === -1 ? text.length : end + 1;
    } else if (text.startsWith('/*', at)) {
      const end = text.indexOf('*/', at + 2);
      if (end === -1) throw new Error('unterminated block comment');
      at = end + 2;
    } else {
      return at;
    }
  }
}

/** Index one past the string starting at `i` (a `"`). */
function skipString(text: string, i: number): number {
  let at = i + 1;
  while (at < text.length) {
    const ch = text.charAt(at);
    if (ch === '\\') at += 2;
    else if (ch === '"') return at + 1;
    else at += 1;
  }
  throw new Error('unterminated string');
}

/** Index one past the value starting at `i`, which must not be trivia. */
function skipValue(text: string, i: number): number {
  const ch = text.charAt(i);
  if (ch === '"') return skipString(text, i);
  if (ch === '{' || ch === '[') {
    let depth = 0;
    let at = i;
    while (at < text.length) {
      at = skipTrivia(text, at);
      const c = text.charAt(at);
      if (c === '"') {
        at = skipString(text, at);
        continue;
      }
      if (c === '{' || c === '[') depth += 1;
      else if (c === '}' || c === ']') {
        depth -= 1;
        if (depth === 0) return at + 1;
      }
      at += 1;
    }
    throw new Error('unterminated object or array');
  }
  const match = /^[^\s,}\]/]+/u.exec(text.slice(i));
  if (match === null) throw new Error(`unexpected character at offset ${String(i)}`);
  return i + match[0].length;
}

/**
 * True for a document holding nothing but whitespace and comments, which VS
 * Code reads as an empty settings object.
 */
function isBlank(text: string): boolean {
  return skipTrivia(text, 0) === text.length;
}

/**
 * The root object and its top-level properties. Throws on a non-object root,
 * and on a top-level key that appears twice: an edit to one copy while
 * `JSON.parse` reads the other would report a change that does not apply.
 */
function layout(text: string): Layout {
  const open = skipTrivia(text, 0);
  if (text.charAt(open) !== '{') throw new Error('expected a JSON object at the top level');
  const properties: PropertySpan[] = [];
  let at = skipTrivia(text, open + 1);
  for (;;) {
    if (text.charAt(at) === '}') {
      if (skipTrivia(text, at + 1) !== text.length) throw new Error('text after the root object');
      return { open, close: at, properties };
    }
    if (text.charAt(at) !== '"')
      throw new Error(`expected a property name at offset ${String(at)}`);
    const keyEnd = skipString(text, at);
    const key = JSON.parse(text.slice(at, keyEnd)) as string;
    if (properties.some((p) => p.key === key)) {
      throw new Error(`"${key}" appears more than once at the top level; remove one and run again`);
    }
    const colon = skipTrivia(text, keyEnd);
    if (text.charAt(colon) !== ':') throw new Error(`expected ':' after "${key}"`);
    const valueStart = skipTrivia(text, colon + 1);
    const valueEnd = skipValue(text, valueStart);
    properties.push({ key, start: at, valueStart, valueEnd });
    at = skipTrivia(text, valueEnd);
    if (text.charAt(at) === ',') at = skipTrivia(text, at + 1);
    else if (text.charAt(at) !== '}') throw new Error(`expected ',' or '}' after "${key}"`);
  }
}

/** Remove comments and trailing commas, leaving plain JSON. */
function stripToJson(text: string): string {
  let out = '';
  let at = 0;
  while (at < text.length) {
    const ch = text.charAt(at);
    if (ch === '"') {
      const end = skipString(text, at);
      out += text.slice(at, end);
      at = end;
    } else if (text.startsWith('//', at) || text.startsWith('/*', at)) {
      at = skipTrivia(text, at);
      out += ' ';
    } else if (ch === ',') {
      const next = skipTrivia(text, at + 1);
      if (text.charAt(next) !== '}' && text.charAt(next) !== ']') out += ',';
      at += 1;
    } else {
      out += ch;
      at += 1;
    }
  }
  return out;
}

/**
 * Parse a JSONC document. A document of only whitespace and comments is an
 * empty object, which is how VS Code treats a fresh settings.json.
 */
export function parseJsonc(text: string): Record<string, unknown> {
  if (isBlank(text)) return {};
  layout(text);
  // A leading byte-order mark is whitespace to VS Code and to `layout`, but
  // not to JSON.parse.
  return JSON.parse(stripToJson(text.replace(/^\uFEFF/u, ''))) as Record<string, unknown>;
}

/** The indent of the first property, or four spaces, VS Code's own default. */
function indentOf(text: string, spans: readonly PropertySpan[]): string {
  const first = spans[0];
  if (first === undefined) return '    ';
  const lineStart = text.lastIndexOf('\n', first.start) + 1;
  const indent = text.slice(lineStart, first.start);
  return /^[ \t]+$/u.test(indent) ? indent : '    ';
}

/** The document's line ending: CRLF when it uses one, else LF. */
function eolOf(text: string): string {
  return text.includes('\r\n') ? '\r\n' : '\n';
}

/** `value` as JSON, its continuation lines indented to sit under `indent`. */
function render(value: unknown, indent: string, eol: string): string {
  return JSON.stringify(value, null, indent).replaceAll('\n', `${eol}${indent}`);
}

/** Set a top-level property, replacing its value or appending it. */
export function setProperty(text: string, key: string, value: unknown): string {
  const fresh = eolOf(text);
  const source =
    text.trim() === ''
      ? `{${fresh}}${fresh}`
      : isBlank(text)
        ? `${text.trimEnd()}${fresh}{${fresh}}${fresh}`
        : text;
  const { close, properties } = layout(source);
  const indent = indentOf(source, properties);
  const eol = eolOf(source);
  const existing = properties.find((p) => p.key === key);
  if (existing !== undefined) {
    return (
      source.slice(0, existing.valueStart) +
      render(value, indent, eol) +
      source.slice(existing.valueEnd)
    );
  }
  const entry = `${indent}${JSON.stringify(key)}: ${render(value, indent, eol)}`;
  const last = properties.at(-1);
  if (last === undefined) {
    return `${source.slice(0, close).replace(/\s*$/u, '')}${eol}${entry}${eol}${source.slice(close)}`;
  }
  // After the last value, past any comma already there, so the edit adds one
  // comma at most and keeps a trailing comment on that line in place.
  const afterLast = source.slice(last.valueEnd, close);
  // A comma may sit after a comment that follows the value.
  const hasComma = source.charAt(skipTrivia(source, last.valueEnd)) === ',';
  const insertAt = close - (afterLast.length - afterLast.trimEnd().length);
  const lead = hasComma ? '' : ',';
  const head = source.slice(0, last.valueEnd) + lead + source.slice(last.valueEnd, insertAt);
  return `${head}${eol}${entry}${source.slice(insertAt)}`;
}

/** Remove a top-level property, and the comma that separated it. */
export function removeProperty(text: string, key: string): string {
  if (isBlank(text)) return text;
  const { properties } = layout(text);
  const index = properties.findIndex((p) => p.key === key);
  const target = properties[index];
  if (target === undefined) return text;
  const lineStart = text.lastIndexOf('\n', target.start) + 1;
  const start = /^[ \t]*$/u.test(text.slice(lineStart, target.start)) ? lineStart : target.start;
  let end = target.valueEnd;
  // The separating comma, past any comment between it and the value. The
  // comment goes with the property it annotates.
  const commaAt = skipTrivia(text, end);
  const afterComma = text.charAt(commaAt) === ',' ? commaAt + 1 : null;
  if (afterComma !== null) end = afterComma;
  const spaces = /^[ \t]*(?=\r?\n)/u.exec(text.slice(end));
  if (afterComma !== null && spaces !== null) end += spaces[0].length;
  if (text.startsWith('\r\n', end)) end += 2;
  else if (text.charAt(end) === '\n') end += 1;
  let result = text.slice(0, start) + text.slice(end);
  // The last property had no comma of its own; drop the one before it.
  if (afterComma === null && index > 0) {
    const previous = properties[index - 1];
    if (previous !== undefined) {
      const tail = result.slice(previous.valueEnd);
      result = result.slice(0, previous.valueEnd) + tail.replace(/^([ \t]*),/u, '$1');
    }
  }
  return result;
}
