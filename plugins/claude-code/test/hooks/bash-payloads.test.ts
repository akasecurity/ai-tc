import { describe, expect, it } from 'vitest';

import { bashWrittenPayloads } from '../../src/hooks/bash-payloads.ts';

// path and text only; the span is checked on its own.
const read = (command: string) => {
  const { payloads, incomplete } = bashWrittenPayloads(command);
  return { incomplete, payloads: payloads.map(({ path, text }) => ({ path, text })) };
};
const paths = (command: string) => bashWrittenPayloads(command).payloads.map((p) => p.path);

describe('bashWrittenPayloads', () => {
  it('takes a heredoc written to a file, either redirect order, and says where it sits', () => {
    const a = "cat > app.py <<'EOF'\nx = 1\nEOF\n";
    const b = 'cat <<EOF >> out.sql\nSELECT 1\nEOF';
    expect(read(a).payloads).toEqual([{ path: 'app.py', text: 'x = 1' }]);
    expect(read(b).payloads).toEqual([{ path: 'out.sql', text: 'SELECT 1' }]);
    const p = bashWrittenPayloads(a).payloads[0];
    expect(a.slice(p?.start, p?.end)).toBe('x = 1');
  });

  it('takes a heredoc piped into tee, and a <<- body with tab-indented end', () => {
    expect(read('tee -a notes.md <<EOF\nhi\nEOF').payloads).toEqual([
      { path: 'notes.md', text: 'hi' },
    ]);
    expect(read('cat > a.sh <<-EOF\n\tbody\n\tEOF').payloads).toEqual([
      { path: 'a.sh', text: '\tbody' },
    ]);
  });

  it('takes a quoted echo or printf written to a file', () => {
    expect(read(`echo 'select * from t where a = ' + x > q.py`).payloads).toEqual([]);
    expect(read(`echo "a = 1" > conf.py`).payloads).toEqual([{ path: 'conf.py', text: 'a = 1' }]);
    expect(read(`printf 'a = 1\\n' > conf.py`).payloads).toEqual([
      { path: 'conf.py', text: 'a = 1\\n' },
    ]);
    const cmd = `echo "a = 1" > conf.py; ls`;
    const p = bashWrittenPayloads(cmd).payloads[0];
    expect(cmd.slice(p?.start, p?.end)).toBe(`echo "a = 1" > conf.py`);
  });

  it('does not read a printf format as the text written', () => {
    expect(read(`printf '%s\\n' > x.txt`).payloads).toEqual([]);
    expect(read(`printf '%s\\n' 'eval(request.body)' > f.py`).payloads).toEqual([]);
    expect(read(`printf '100%%\\n' > pct.txt`).payloads).toEqual([
      { path: 'pct.txt', text: '100%%\\n' },
    ]);
  });

  it('reads the redirect outside quotes, never from inside a quoted string', () => {
    expect(paths("cat <<EOF > 'my file.py'\nx = 1\nEOF")).toEqual(['my file.py']);
    expect(paths("echo 'a > b' <<EOF\nx = 1\nEOF")).toEqual([]);
    expect(paths('cat <<EOF # > c.py\nx = 1\nEOF')).toEqual([]);
  });

  it('ends a CRLF heredoc at its delimiter, so the next write is its own payload', () => {
    const cmd = 'cat > f.py <<EOF\r\nEVIL1\r\nEOF\r\ncat > g.py <<EOF\r\nEVIL2\r\nEOF';
    expect(read(cmd).payloads).toEqual([
      { path: 'f.py', text: 'EVIL1' },
      { path: 'g.py', text: 'EVIL2' },
    ]);
  });

  it('does not take a decoded body as code, but a file named base64.py is not a decoder', () => {
    expect(read('base64 -d > f.py <<EOF\nZXZhbCh4KQ==\nEOF').payloads).toEqual([]);
    expect(read('cat <<EOF > base64.py\nx = 1\nEOF').payloads).toEqual([
      { path: 'base64.py', text: 'x = 1' },
    ]);
  });

  it('leaves a heredoc fed to a command unextracted, whatever its stdout goes to', () => {
    expect(read("psql <<'EOF'\nselect * from t where id = '%s'\nEOF")).toEqual({
      incomplete: false,
      payloads: [],
    });
    expect(read('python - <<EOF\nprint(1)\nEOF').payloads).toEqual([]);
    expect(read('python - <<EOF > out.txt\nimport pickle\nEOF').payloads).toEqual([]);
    expect(read('sudo -u root python3 <<EOF > out.txt\nx\nEOF').payloads).toEqual([]);
    expect(read('echo "x" > /dev/null').payloads).toEqual([]);
    expect(read('echo "x" 2>&1').payloads).toEqual([]);
    expect(read('grep "select * from t" file.txt').payloads).toEqual([]);
  });

  it('reads a heredoc marker inside a body as text, not a second heredoc', () => {
    const cmd = 'cat > a.txt <<A\ncat <<B > b.txt\nB\nA\n';
    expect(read(cmd).payloads).toEqual([{ path: 'a.txt', text: 'cat <<B > b.txt\nB' }]);
  });

  it('takes both heredocs opened on one line, each with its own file', () => {
    const cmd = 'cat <<A > a.txt; cat <<B > b.py\nbody a\nA\nbody b\nB\n';
    expect(read(cmd).payloads).toEqual([
      { path: 'a.txt', text: 'body a' },
      { path: 'b.py', text: 'body b' },
    ]);
    const same = 'cat <<A > a.txt && cat <<B | tee b.py\nbody a\nA\nbody b\nB\n';
    expect(paths(same)).toEqual(['a.txt', 'b.py']);
  });

  it('skips stderr, fd and /dev/null redirects when naming the file', () => {
    expect(paths('cat <<EOF 2>/dev/null > app.py\nx = 1\nEOF')).toEqual(['app.py']);
    expect(paths('cat <<EOF 2>err.log >out.py\nx = 1\nEOF')).toEqual(['out.py']);
    expect(paths('cat <<EOF >&2\nx = 1\nEOF')).toEqual([]);
    expect(paths('cat <<EOF > /dev/null\nx = 1\nEOF')).toEqual([]);
    expect(paths('cat <<EOF &> both.py\nx = 1\nEOF')).toEqual(['both.py']);
  });

  it('takes a body written to a name it cannot resolve as code with no path', () => {
    const r = bashWrittenPayloads('cat > "$F" <<EOF\nx = 1\nEOF');
    expect(r.incomplete).toBe(false);
    expect(r.payloads).toHaveLength(1);
    expect(r.payloads[0]?.path).toBeUndefined();
    expect(r.payloads[0]?.text).toBe('x = 1');
    expect(bashWrittenPayloads('cat <<EOF > out/$(date).py\nx\nEOF').payloads[0]?.path).toBe(
      undefined,
    );
  });

  it('reads delimiter forms: escaped, hyphen, dot, and ignores here-strings and quoted markers', () => {
    expect(paths('cat <<\\EOF > a.py\nx\nEOF')).toEqual(['a.py']);
    expect(paths('cat <<MY-END > a.py\nx\nMY-END')).toEqual(['a.py']);
    expect(paths('cat <<END.1 > a.py\nx\nEND.1')).toEqual(['a.py']);
    expect(paths('cat <<<x > f.py')).toEqual([]);
    expect(read('cat <<<x > f.py\ncat <<EOF > g.py\ny\nEOF').payloads).toEqual([
      { path: 'g.py', text: 'y' },
    ]);
    expect(read('echo "<<EOF" > a.py\nfoo\nEOF').payloads).toEqual([
      { path: 'a.py', text: '<<EOF' },
    ]);
    expect(paths("echo '<<EOF' && cat <<EOF > b.py\nz\nEOF")).toEqual(['b.py']);
  });

  it('leaves an unquoted body with command substitution unextracted, a quoted one extracted', () => {
    expect(paths('cat <<EOF > a.py\nx = $(id)\nEOF')).toEqual([]);
    expect(paths('cat <<EOF > a.py\nx = `id`\nEOF')).toEqual([]);
    expect(paths("cat <<'EOF' > a.py\nx = $(id)\nEOF")).toEqual(['a.py']);
    expect(paths('cat <<\\EOF > a.py\nx = $(id)\nEOF')).toEqual(['a.py']);
  });

  it('is incomplete, with nothing returned, when a heredoc cannot be followed or ends unterminated', () => {
    expect(read('cat <<$D > a.py\nx\n$D')).toEqual({ incomplete: true, payloads: [] });
    expect(read('cat > a.py <<EOF\nx = 1\n')).toEqual({ incomplete: true, payloads: [] });
  });

  it('is incomplete past each cap, with nothing returned', () => {
    const many = 'cat <<A >f\nx\nA\n'.repeat(65);
    expect(bashWrittenPayloads(many)).toEqual({ incomplete: true, payloads: [] });
    const echoes = 'echo "a" > f.py\n'.repeat(33);
    expect(bashWrittenPayloads(echoes)).toEqual({ incomplete: true, payloads: [] });
    const big = `echo "a" > f.py\n${'#'.repeat(256 * 1024)}`;
    expect(bashWrittenPayloads(big)).toEqual({ incomplete: true, payloads: [] });
    const longLine = `cat <<A > f.py ${'x '.repeat(3000)}\nbody\nA\n`;
    expect(bashWrittenPayloads(longLine)).toEqual({ incomplete: true, payloads: [] });
    expect(bashWrittenPayloads('cat <<A\nx\nA\n'.repeat(64))).toEqual({
      incomplete: false,
      payloads: [],
    });
  });

  it('stays linear and bounded on hostile whitespace and repetition, for every pattern', () => {
    const inputs = [
      'cat <<EOF >f\n'.repeat(20_000),
      'echo "x'.repeat(40_000),
      `tee${' '.repeat(100_000)}`,
      `cat <<EOF | tee${' '.repeat(100_000)}\nx\nEOF`,
      `cat <<EOF >${' '.repeat(100_000)}\nx\nEOF`,
      `echo${' '.repeat(100_000)}"a" > f`,
      `echo "a"${' '.repeat(100_000)}> f`,
      `echo "a" >${' '.repeat(100_000)}`,
      `echo ${'-a '.repeat(30_000)}"a"`,
      '> '.repeat(50_000),
      `cat <<EOF ${'1'.repeat(100_000)}\nx\nEOF`,
      `cat <<EOF ${'& '.repeat(50_000)}\nx\nEOF`,
      `cat <<EOF ${'|'.repeat(100_000)}\nx\nEOF`,
      `${' '.repeat(100_000)}<<${' '.repeat(100_000)}EOF`,
      `cat <<EOF >f\n${'\t'.repeat(100_000)}x\nEOF`,
    ];
    for (const input of inputs) {
      const start = performance.now();
      const out = bashWrittenPayloads(input);
      expect(performance.now() - start).toBeLessThan(500);
      expect(out.payloads.length).toBeLessThanOrEqual(32);
    }
  });
});
