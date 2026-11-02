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
    const cmd = `cd d; echo "a = 1" > conf.py`;
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

  it('takes nothing from a CRLF command, whose carriage returns bash keeps in its words', () => {
    const cmd = 'cat > f.py <<EOF\r\nEVIL1\r\nEOF\r\ncat > g.py <<EOF\r\nEVIL2\r\nEOF';
    expect(read(cmd).payloads).toEqual([]);
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
    expect(paths('cat <<EOF 2>err.log >out.py\nx = 1\nEOF')).toEqual([]);
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
    expect(paths('cat <<<x > f.py\ncat <<EOF > g.py\ny\nEOF')).toEqual([]);
    expect(read(`echo "<<EOF" > a.py`).payloads).toEqual([{ path: 'a.py', text: '<<EOF' }]);
    expect(paths("true '<<EOF' && cat <<EOF > b.py\nz\nEOF")).toEqual(['b.py']);
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

  it('does not take a body whose stdout a later pipeline stage reads', () => {
    expect(paths("cat <<'EOF' | sh > out.txt\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' | tee f.txt | sh\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' > f.txt | sh\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' > f.txt | tee g.txt | sh\nx\nEOF")).toEqual([]);
    expect(paths("tee f.txt <<'EOF' | sh\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' | tee f.txt\nx\nEOF")).toEqual(['f.txt']);
    expect(paths("cat <<'EOF' | tee -a f.txt > /dev/null\nx\nEOF")).toEqual(['f.txt']);
  });

  it('does not take a heredoc from a stage it cannot positively read as a writer', () => {
    expect(paths("<<'EOF' > f.py\nx\nEOF")).toEqual([]);
    expect(paths("python3 <<'EOF' > f.py\nx\nEOF")).toEqual([]);
    expect(paths("> f.py cat <<'EOF'\nx\nEOF")).toEqual(['f.py']);
  });

  it('does not take a heredoc under an assignment, substitution or subshell', () => {
    expect(paths("X=$(python3 <<'EOF' > out.txt\nx\nEOF\n)")).toEqual([]);
    expect(paths("X=`python3 <<'EOF' > out.txt\nx\nEOF\n`")).toEqual([]);
    expect(paths("(python3 <<'EOF' > out.txt\nx\nEOF\n)")).toEqual([]);
    expect(paths("cat <<'EOF' > $(echo f.py)\nx\nEOF")).toEqual([]);
  });

  it('is incomplete across a line continuation, ANSI-C quoting, or a heredoc with no line end', () => {
    expect(read("python3 - <<'EOF' \\\n> out.txt\nx\nEOF")).toEqual({
      incomplete: true,
      payloads: [],
    });
    expect(bashWrittenPayloads('echo hi \\\n && echo "a" > f.txt').incomplete).toBe(true);
    expect(bashWrittenPayloads("echo $'a\\x27b' > f.txt").incomplete).toBe(true);
    expect(bashWrittenPayloads('cat <<EOF > a.py').incomplete).toBe(true);
  });

  it('does not take a double-quoted echo that runs a substitution', () => {
    expect(paths('echo "$(python3 -c x)" > f.txt')).toEqual([]);
    expect(paths('echo "`id`" > f.txt')).toEqual([]);
    expect(paths("echo '$(id)' > f.txt")).toEqual(['f.txt']);
  });

  it("takes a quoted write only at command position, never inside another command's string", () => {
    expect(paths(`sh -c "echo 'X' > f.txt"`)).toEqual([]);
    expect(paths(`bash -c 'echo "X" > f.txt'`)).toEqual([]);
    expect(paths(`python -c "import os; os.system('echo \\"X\\" > f.txt')"`)).toEqual([]);
    expect(paths(`eval "echo 'X' > f.txt"`)).toEqual([]);
    expect(paths(`echo hi # echo "a" > f.txt`)).toEqual([]);
    expect(paths(`cat <<'EOF' > g.txt\necho "a" > f.txt\nEOF`)).toEqual(['g.txt']);
    expect(paths(`echo "a"\n> f.txt`)).toEqual([]);
    expect(paths(`echo "a" > f.txt <<'EOF'\nx\nEOF`)).toEqual([]);
    expect(paths(`cd d; echo "a" > f.txt && echo 'b' >> g.txt`)).toEqual(['f.txt', 'g.txt']);
    expect(paths(`cd d\necho "a" > f.txt`)).toEqual(['f.txt']);
  });

  it('does not take a heredoc whose command word follows the operator', () => {
    expect(paths("> o.txt <<'EOF' python3\nx\nEOF")).toEqual([]);
    expect(paths("2>/dev/null <<'EOF' python3 > o.txt\nx\nEOF")).toEqual([]);
    expect(paths("<<'EOF' python3 > o.txt\nx\nEOF")).toEqual([]);
    expect(paths("> o.txt <<'EOF'\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' python3 > o.txt\nx\nEOF")).toEqual([]);
    expect(paths("cat <<<'x' python3 > o.txt")).toEqual([]);
    expect(paths("cat <<'EOF' > o.txt 2>&1\nx\nEOF")).toEqual(['o.txt']);
    expect(paths("cat <<'EOF' >o.txt 1>&2\nx\nEOF")).toEqual(['o.txt']);
  });

  it('does not take a quoted write that a later redirect or process substitution overrides', () => {
    expect(paths("echo '<code>' > o.txt &> >(python3)")).toEqual([]);
    expect(paths("echo '<code>' > o.txt &>>(python3)")).toEqual([]);
    expect(paths("echo '<code>' > o.txt &> p.txt")).toEqual([]);
    expect(paths("echo '<code>' > o.txt 1>&2")).toEqual([]);
    expect(paths("echo '<code>' >| o.txt")).toEqual([]);
    expect(paths("echo '<code>' > o.txt <<<x")).toEqual([]);
    expect(paths("echo '<code>' > o.txt & ls")).toEqual([]);
    expect(paths("echo '<code>' > o.txt && cd d")).toEqual(['o.txt']);
  });

  it.each([
    ["{\ncat <<'EOF' | tee f1.txt\nx\nEOF\n} | sh"],
    ["eval $(\ncat <<'EOF' | tee f2.txt\nx\nEOF\n)"],
    ["sh <(\ncat <<'EOF' > f3.txt\nx\nEOF\n)"],
    ["while true; do\ntee f7.txt <<'EOF'\nx\nEOF\nbreak; done | sh"],
    ["(\ncat <<'EOF' > f8.txt\nx\nEOF\n) | bash"],
    ["if true; then\ncat <<'EOF' > f9.txt\nx\nEOF\nfi"],
    ["for i in 1; do\ncat <<'EOF' > f10.txt\nx\nEOF\ndone"],
    ["f() {\ncat <<'EOF' > f11.txt\nx\nEOF\n}\nf"],
    ["cat(){ sh; }\ncat <<'EOF' > f4.txt\nx\nEOF"],
    ['echo(){ sh -c "$1"; }; echo \'<payload>\' > f5.txt'],
    ["alias cat=sh\ncat <<'EOF' > f.txt\nx\nEOF"],
    ["shopt -s expand_aliases; alias echo=sh; echo '<payload>' > f.txt"],
    ["export BASH_ENV=/tmp/e\ncat <<'EOF' > f.txt\nx\nEOF"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\nsh f6.txt"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\n. f6.txt"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\nsource f6.txt"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\nbash f6.txt"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\nchmod +x f6.txt; ./f6.txt"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\nexec f6.txt"],
    ["echo '<payload>' > f6.txt; sh f6.txt"],
    ["true || cat <<'EOF' > f.txt\nx\nEOF"],
    ["cat <<'EOF' > f.txt &\nx\nEOF"],
    ["cat <<'EOF' > f.txt\nx\nEOF\nls"],
  ])('takes nothing when the command is more than writers and inert statements: %s', (command) => {
    expect(read(command)).toEqual({ incomplete: true, payloads: [] });
  });

  it('keeps regions for a flat sequence of plain writers and inert statements', () => {
    const cmd =
      "cd d && mkdir -p out\ncat <<'EOF' > out/a.txt\nx\nEOF\ntouch b; : ; true\n# note\n";
    expect(read(cmd)).toEqual({
      incomplete: false,
      payloads: [{ path: 'out/a.txt', text: 'x' }],
    });
    const mixed = paths(`echo "a" > f.txt; cat <<A > g.txt\nb\nA\ncd "x y" # c`);
    expect([...mixed].sort()).toEqual(['f.txt', 'g.txt']);
  });

  it.each([
    ['cat <<EOF > a.txt\nhello\nEO\\\nF\necho RAN\nEOF\n'],
    ['cat <<EOF > b.txt\nv=$\\\n(echo RAN)\nEOF\n'],
    ['cat <<EOF > b.txt\nv=$\\\r\n(echo RAN)\nEOF\n'],
    ["bash -c 'sleep 1; python3 x.py' | cat <<'EOF' > x.py\n<payload>\nEOF\n"],
    ["true | cat <<'EOF' > x.py\n<payload>\nEOF\n"],
    ["true | echo '<payload>' > x.py"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ntrue\v#; python3 c.py\n"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ntrue\f#; python3 c.py\n"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ntrue\u00a0#; python3 c.py\n"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ntrue\u2003#; python3 c.py\n"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ntrue\r#; python3 c.py\n"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ncd café\n"],
  ])('takes nothing from a command bash reads differently: %j', (command) => {
    expect(bashWrittenPayloads(command).payloads).toEqual([]);
  });

  it('still takes a quoted-delimiter body with a backslash-newline, and a real comment', () => {
    expect(paths("cat <<'EOF' > a.txt\nline \\\nmore\nEOF\n")).toEqual(['a.txt']);
    expect(paths('cat <<EOF > a.txt\nplain\nEOF\ntrue # note; python3 a.txt\n')).toEqual(['a.txt']);
    expect(paths("cat <<'EOF' | tee a.txt\nx\nEOF")).toEqual(['a.txt']);
  });

  it.each([
    ["tee a.txt a.py <<'EOF'\nx\nEOF"],
    ["tee a.py > a.txt <<'EOF'\nx\nEOF"],
    ["tee a.py <<'EOF' > a.txt\nx\nEOF"],
    ["cat <<'EOF' | tee a.py > a.txt\nx\nEOF"],
    ["cat <<'EOF' > a.py > a.txt\nx\nEOF"],
    ["cat <<'EOF' > a.txt 2>a.py\nx\nEOF"],
    ["cat <<'EOF' > a.py | tee a.txt\nx\nEOF"],
    ["cat f.py - <<'EOF' > a.txt\nx\nEOF"],
    ["cat -n <<'EOF' > a.txt\nx\nEOF"],
    ["tee -p a.txt <<'EOF'\nx\nEOF"],
    ["tee <<'EOF'\nx\nEOF"],
    ["true x <<'EOF' > a.txt\nx\nEOF"],
    ["sponge a.txt <<'EOF'\nx\nEOF"],
  ])('takes no path from a writer with more than one file or unread arguments: %j', (command) => {
    expect(paths(command)).toEqual([]);
  });

  it('still takes the one file of a plain cat, tee or true', () => {
    expect(paths("cat - <<'EOF' > a.txt\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("tee -a a.txt <<'EOF'\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("tee a.txt <<'EOF' >/dev/null\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("true <<'EOF' > a.txt\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("cat <<'EOF' | tee -a a.txt 2>/dev/null\nx\nEOF")).toEqual(['a.txt']);
  });

  it('does not take a writer behind an assignment or wrapper word', () => {
    expect(paths("PATH=/tmp/d cat <<'EOF' > f.txt\nx\nEOF")).toEqual([]);
    expect(paths("BASH_ENV=/tmp/e cat <<'EOF' > f.txt\nx\nEOF")).toEqual([]);
    expect(paths("env cat <<'EOF' > f.txt\nx\nEOF")).toEqual([]);
    expect(paths("/tmp/d/cat <<'EOF' > f.txt\nx\nEOF")).toEqual([]);
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
