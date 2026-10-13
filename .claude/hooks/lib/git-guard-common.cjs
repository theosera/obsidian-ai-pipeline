'use strict';
/**
 * PreToolUse(Bash) の git ガード 3 本（block-secret-git / block-git-add-all /
 * block-secret-egress）が共有する、コマンドの読み取りの部品。
 *
 * コマンド文字列を正規表現 1 本で当てるのでなく、シェルの語に分けて（引用符・`\`・
 * 空の引用符を戻して）から、git の呼び出しごとに global option と subcommand を分ける。
 * `$(…)`・`` `…` ``・`<(…)` の中と、シェルに流すヒアドキュメントの本文も、コマンドとして読む。
 * 読みきれない形（変数や置換で作られた語・知らない global option・文字列でシェルに渡した
 * git など）は problems に入れ、各 hook は fail-closed で拒む。
 *
 * 3 本の hook は同じ読みを使う（片方だけ古くなると、hook ごとに見える形が食い違うため）。
 */
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

/** Read the hook payload; an unreadable stdin is treated as an empty payload. */
function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch { return ''; }
}

/** Emit an explicit policy/unknown reason on the existing deny wire, bounded and flushed before exit. */
function deny(reason, category = 'UNKNOWN') {
  const message = typeof reason === 'string' ? reason : 'hook が入力を検査できないため実行をブロックします (fail-closed)。';
  // Only an explicit enum and a usable reason may claim a confirmed policy prohibition.
  const prefix = category === 'FORBIDDEN' && typeof reason === 'string' ? '[禁止] ' : '[判断不能] ';
  const classified = prefix + message;
  // 512 UTF-16 units stay below 4 KiB even when JSON escapes every unit as \uXXXX.
  const bounded = classified.length > 512 ? classified.slice(0, 511) + '…' : classified;
  fs.writeFileSync(1, JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: bounded,
    },
  }));
  process.exit(0);
}

/**
 * 入力の JSON からコマンドと実行場所を取る。Bash の cwd は呼び出しをまたいで残るので、
 * CLAUDE_PROJECT_DIR より入力の cwd を優先する。読めない入力と例外は deny にする。
 */
function readInput(guardLabel) {
  // ここから後で例外が起きて hook が落ちると、Claude Code はコマンドを止めない（fail-open）。
  // 落ちる代わりに拒む（v3）。
  process.on('uncaughtException', (e) => {
    deny(`${guardLabel}がコマンドを読む途中で例外が起きました（${(e && e.name) || 'Error'}）(fail-closed)。実行をブロックします。`);
  });
  let j;
  try {
    j = JSON.parse(readStdin() || '{}');
  } catch {
    deny(`hook 入力を解釈できませんでした (fail-closed)。${guardLabel}を通せないため実行をブロックします。`);
  }
  // JSON がオブジェクトでない入力（null・配列・数・文字列・真偽）は読めないので拒む（v3.5.4）。
  // main は null を拒んでいた（j.tool_input の TypeError を catch して拒む）。
  if (j === null || typeof j !== 'object' || Array.isArray(j)) {
    deny(`hook 入力が JSON のオブジェクトではありません (fail-closed)。${guardLabel}を通せないため実行をブロックします。`);
  }
  const cmd = (j && j.tool_input && typeof j.tool_input.command === 'string') ? j.tool_input.command : '';
  const inputCwd = (j && typeof j.cwd === 'string' && j.cwd !== '') ? j.cwd : null;
  const baseDir = inputCwd || process.env.CLAUDE_PROJECT_DIR || process.cwd();
  return { cmd, baseDir };
}

// ---------------------------------------------------------------------------
// シェルの語への分け方
// ---------------------------------------------------------------------------

const MAX_DEPTH = 16;
// 変数や置換の所に置く印（実行するまで中身が決まらない）。
const DYN = '\u0000';

/** Skip consecutive shell line continuations before checking the next token character. */
function skipLC(src, k) {
  while (src[k] === '\\' && src[k + 1] === '\n') k += 2;
  return k;
}
/** Determine whether line continuations join the current position to a given character. */
const joinedByLC = (src, k, ch) => src[k] === '\\' && src[k + 1] === '\n' && src[skipLC(src, k)] === ch;

// コマンドの位置を変えない予約語。この後の `((` は算術、`(` はサブシェル（v3.5.2）。
const CMD_LEAD = new Set(['!', '{', 'if', 'then', 'elif', 'else', 'while', 'until', 'do', 'time']);
/** Recognize a command position after static reserved words, without reinterpreting quoted text. */
const atCmdPos = (words) => words.every((w) => !w.quoted && !w.dynamic && CMD_LEAD.has(w.text));

/** Find Bash 5.3's reserved closing brace without interpreting quotes or nested groups as its boundary. */
function alternateSubstitutionEnd(src, start) {
  let braces = 0;
  let parentheses = 0;
  let terminator = false;
  for (let k = start; k < src.length; k++) {
    const ch = src[k];
    if (ch === '\\') { k++; terminator = false; continue; }
    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch;
      for (k++; k < src.length && src[k] !== quote; k++) if (src[k] === '\\' && quote !== "'") k++;
      if (k >= src.length) return -1;
      terminator = false;
      continue;
    }
    if (ch === '(') parentheses++;
    else if (ch === ')' && parentheses) parentheses--;
    else if (ch === '{') braces++;
    else if (ch === '}') {
      if (braces) braces--;
      else if (!parentheses && terminator) return k;
    }
    if (ch === ';' || ch === '\n' || ch === '&') terminator = true;
    else if (!/[ \t]/.test(ch)) terminator = false;
  }
  return -1;
}

/** Decode Bash ANSI-C bytes without execution; uncertain encodings retain an explicit argument marker. */
function decodeAnsiC(body) {
  const chunks = [];
  let unknown = false;
  let truncated = false;
  const append = (value) => {
    const bytes = typeof value === 'number' ? Buffer.from([value & 255]) : Buffer.from(value, 'utf8');
    const nul = bytes.indexOf(0);
    chunks.push(nul < 0 ? bytes : bytes.subarray(0, nul));
    if (nul >= 0) truncated = true;
  };
  const simple = { a: 7, b: 8, e: 27, E: 27, f: 12, n: 10, r: 13, t: 9, v: 11,
    '\\': 92, "'": 39, '"': 34, '?': 63 };
  for (let k = 0; k < body.length && !truncated; k++) {
    const ch = body[k];
    if (ch !== '\\') {
      const codepoint = body.codePointAt(k);
      append(String.fromCodePoint(codepoint));
      if (codepoint > 65535) k++;
      continue;
    }
    const escape = body[++k];
    if (escape === undefined) { unknown = true; break; }
    if (Object.hasOwn(simple, escape)) { append(simple[escape]); continue; }
    if (/[0-7]/.test(escape)) {
      const digits = /^[0-7]{1,3}/.exec(body.slice(k))[0];
      append(parseInt(digits, 8)); k += digits.length - 1; continue;
    }
    if (escape === 'x' || escape === 'u' || escape === 'U') {
      const width = { x: 2, u: 4, U: 8 }[escape];
      const digits = new RegExp('^[0-9a-fA-F]{1,' + width + '}').exec(body.slice(k + 1));
      if (!digits) { append('\\' + escape); continue; }
      const value = parseInt(digits[0], 16);
      k += digits[0].length;
      if (escape === 'x') append(value);
      else {
        // Bash 3.2 preserves Unicode escapes, while newer Bash decodes them depending on LC_CTYPE.
        // Raw UTF-8 and valid escaped byte sequences have deterministic argv bytes across versions.
        unknown = true;
      }
      continue;
    }
    if (escape === 'c') {
      if (k + 1 >= body.length) { unknown = true; break; }
      let control = body[++k];
      if (control === '?' || control === '\\' || control.charCodeAt(0) > 127) { unknown = true; continue; }
      control = control.toUpperCase();
      append(control === '?' ? 127 : control.charCodeAt(0) & 31);
      continue;
    }
    append('\\' + escape); // Bash preserves unrecognized escapes as literal data.
  }
  const bytes = Buffer.concat(chunks);
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) unknown = true;
  return { text, unknown };
}

/** Scan one expansion and collect executable substitutions in child shell scopes. */
function scanExpansion(src, i, out, depth, scope, effects, inDoubleQuotes = false) {
  const n = src.length;
  // `${…}` と `$((…))` の入れ子は parseSeq を通らずに呼び合うので、ここでも深さを見る（v3）。
  if (depth > MAX_DEPTH) { out.errors.push('入れ子が深すぎる'); return { end: n, dynamic: true }; }
  if (src[i] === '`') {
    let j = i + 1;
    let inner = '';
    while (j < n && src[j] !== '`') {
      if (src[j] === '\\' && j + 1 < n) {
        const e = src[j + 1];
        inner += (e === '`' || e === '\\' || e === '$') ? e : src[j] + e;
        j += 2;
        continue;
      }
      inner += src[j];
      j++;
    }
    if (j >= n) { out.errors.push('閉じていない `…`'); return { end: n, dynamic: true }; }
    parseSeq(inner, 0, out, depth + 1, false, { parent: scope }, effects);
    return { end: j + 1, dynamic: true };
  }
  // `$` の直後の行の継続: シェルは継続を消してから `$(`・`${`・`$[`・`$'`・`$name` と読む（v3.5.2）。
  if (src[i + 1] === '\\' && src[i + 2] === '\n') {
    out.errors.push('$ の直後に行の継続がある');
    return { end: i + 1, dynamic: true };
  }
  const c1 = src[i + 1];
  if (c1 === '(') {
    if (src[i + 2] === '(') {
      // $(( 算術 ))。中の $(…) は実行されるので読む。
      let j = i + 3;
      let d = 0;
      while (j < n) {
        if (src[j] === '(') d++;
        else if (src[j] === ')') {
          if (d === 0 && src[j + 1] === ')') break;
          d--;
        }
        j++;
      }
      if (j >= n) { out.errors.push('閉じていない $(( … ))'); return { end: n, dynamic: true }; }
      const expression = src.slice(i + 3, j);
      scanSubsts(expression, out, depth + 1, scope, effects);
      return { end: j + 2, dynamic: true, evaluations: [{ kind: 'arithmetic', text: expression }] };
    }
    const close = parseSeq(src, i + 2, out, depth + 1, true, { parent: scope }, effects);
    if (close >= n) { out.errors.push('閉じていない $( … )'); return { end: n, dynamic: true }; }
    return { end: close + 1, dynamic: true };
  }
  if (c1 === '[') {
    // $[ … ]（古い書き方の算術・v3.5）。中の置換だけを読む（`<<` はシフトでヒアドキュメントではない）。
    let j = i + 2;
    let d = 0;
    while (j < n) {
      if (src[j] === '[') d++;
      else if (src[j] === ']') {
        if (d === 0) break;
        d--;
      }
      j++;
    }
    if (j >= n) { out.errors.push('閉じていない $[ … ]'); return { end: n, dynamic: true }; }
    const expression = src.slice(i + 2, j);
    scanSubsts(expression, out, depth + 1, scope, effects);
    return { end: j + 1, dynamic: true, evaluations: [{ kind: 'arithmetic', text: expression }] };
  }
  if (c1 === '{') {
    if (/[ \t\n|]/.test(src[i + 2] || '')) {
      const end = alternateSubstitutionEnd(src, i + 2);
      if (end < 0) {
        out.evaluationUnknown = true;
        return { end: n, dynamic: true, evaluations: [{ kind: 'source', text: null }] };
      }
      const source = src.slice(i + 2, end).replace(/^\|/, '');
      const first = out.cmds.length;
      parseSeq(source, 0, out, depth + 1, false, scope, effects);
      for (let k = first; k < out.cmds.length; k++) out.cmds[k].mediated = true;
      return { end: end + 1, dynamic: true, evaluations: [{ kind: 'source', text: source }] };
    }
    let j = i + 2;
    let d = 0;
    let multiWord = false;
    const evaluations = [];
    while (j < n) {
      const ch = src[j];
      if (ch === '\\') { j += 2; continue; }
      if (ch === "'") {
        const q = src.indexOf("'", j + 1);
        if (q < 0) { j = n; break; }
        // 外側が二重引用の ${…} では、この単一引用内の置換も実行されうる。
        multiWord = scanSubsts(src.slice(j + 1, q), out, depth + 1, scope, effects, evaluations) || multiWord;
        j = q + 1;
        continue;
      }
      if (ch === '"') {
        j++;
        while (j < n && src[j] !== '"') {
          if (src[j] === '\\') { j += 2; continue; }
          if (src[j] === '$' || src[j] === '`') {
            const r = scanExpansion(src, j, out, depth + 1, scope, effects);
            evaluations.push(...(r.evaluations || []));
            multiWord = multiWord || !!r.multiWord;
            j = r.end;
            continue;
          }
          j++;
        }
        if (j >= n) break;
        j++;
        continue;
      }
      if (ch === '$' || ch === '`') {
        const r = scanExpansion(src, j, out, depth + 1, scope, effects);
        evaluations.push(...(r.evaluations || []));
        multiWord = multiWord || !!r.multiWord;
        j = r.end;
        continue;
      }
      if (ch === '{') d++;
      else if (ch === '}') {
        if (d === 0) break;
        d--;
      }
      j++;
    }
    if (j >= n) { out.errors.push('閉じていない ${ … }'); return { end: n, dynamic: true }; }
    const body = src.slice(i + 2, j);
    {
      const prompt = /^([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?|[@*0-9])@P$/.exec(body);
      if (prompt) evaluations.push({ kind: 'prompt', text: prompt[1] });
      else if (/^!?[A-Za-z_][A-Za-z0-9_]*(?:\[.*\])?@P$/.test(body)) evaluations.push({ kind: 'prompt', text: null });
      const parameter = /^!?([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?(.*)$/s.exec(body);
      if (parameter) {
        if (parameter[2] !== undefined && !/^[@*]$/.test(parameter[2])) {
          evaluations.push({ kind: 'arithmetic', text: parameter[2], arrayName: parameter[1] });
        }
        // Substring offset/length are arithmetic; :- / := / :? / :+ are ordinary parameter operators.
        if (/^:(?![-=+?])/.test(parameter[3])) {
          evaluations.push({ kind: 'arithmetic', text: parameter[3].slice(1).replace(/:/g, ';') });
        }
      }
    }
    // "$@"・"${a[@]}"・"${!prefix@}" は、二重引用されていても複数の語になりうる。
    multiWord = multiWord || /\[@\]/.test(body) || /^@(?::|$)/.test(body) || /^![A-Za-z_][A-Za-z0-9_]*@$/.test(body);
    return { end: j + 1, dynamic: true, multiWord, evaluations };
  }
  if (c1 === "'") {
    if (inDoubleQuotes) return { end: i + 1, dynamic: false, literal: '$' };
    let j = i + 2;
    while (j < n && src[j] !== "'") {
      if (src[j] === '\\') j++;
      j++;
    }
    if (j >= n) { out.errors.push("閉じていない $'…'"); return { end: n, dynamic: true }; }
    const decoded = decodeAnsiC(src.slice(i + 2, j));
    return { end: j + 1, dynamic: decoded.unknown, ansiCUnknown: decoded.unknown,
      literal: decoded.text, noSplit: true, quoted: true, ansiCQuoted: true };
  }
  if (c1 === '"') return { end: i + 1, dynamic: true }; // $"…": 続く "…" は呼び出し側が読む
  if (c1 !== undefined && /[A-Za-z_]/.test(c1)) {
    let j = i + 1;
    while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
    return { end: j, dynamic: true };
  }
  if (c1 !== undefined && /[0-9@*#?$!-]/.test(c1)) return { end: i + 2, dynamic: true, multiWord: c1 === '@' };
  return { end: i + 1, dynamic: false, literal: '$' };
}

/** Return a matching arithmetic `))`, or -1 when the parentheses describe another shell form. */
function arithEnd(src, j) {
  let d = 0;
  for (let k = j; k < src.length; k++) {
    const ch = src[k];
    if (ch === '\\') { k++; continue; }
    if (ch === "'" || ch === '"') {
      const q = src.indexOf(ch, k + 1);
      if (q < 0) return -1;
      k = q;
      continue;
    }
    if (ch === '(') d++;
    else if (ch === ')') {
      if (d === 0) return src[k + 1] === ')' ? k : -1;
      d--;
    }
  }
  return -1;
}

/** Collect expansions from arithmetic or heredoc text without treating its operators as commands. */
function scanSubsts(text, out, depth, scope, effects, evaluations = []) {
  let k = 0;
  let multiWord = false;
  while (k < text.length) {
    const ch = text[k];
    if (ch === '\\') { k += 2; continue; }
    if (ch === '$' || ch === '`') {
      const r = scanExpansion(text, k, out, depth, scope, effects);
      evaluations.push(...(r.evaluations || []));
      multiWord = multiWord || !!r.multiWord;
      k = r.end;
      continue;
    }
    k++;
  }
  return multiWord;
}

/** Recognize unquoted brace lists or valid ranges; quoted/escaped segments are opaque markers. */
function hasBraceExpansion(source) {
  const stack = [];
  for (let k = 0; k < source.length; k++) {
    if (source[k] === '{') stack.push({ start: k, comma: false });
    else if (source[k] === ',' && stack.length) stack[stack.length - 1].comma = true;
    else if (source[k] === '}' && stack.length) {
      const group = stack.pop();
      const body = source.slice(group.start + 1, k);
      if (group.comma || /^[+-]?\d+\.\.[+-]?\d+(?:\.\.[+-]?\d+)?$/.test(body) ||
          /^[A-Za-z]\.\.[A-Za-z](?:\.\.[+-]?\d+)?$/.test(body)) return true;
    }
  }
  return false;
}

/**
 * Tokenize a shell sequence into commands with scope metadata and redirections.
 * For substitutions, stop at the unmatched closing parenthesis; otherwise consume the source.
 */
function parseSeq(src, start, out, depth, stopAtParen, scope, parentEffects = []) {
  const n = src.length;
  if (depth > MAX_DEPTH) { out.errors.push('入れ子が深すぎる'); return n; }
  let i = start;
  let words = [];
  let cur = null;
  let parenDepth = 0;
  // 開いている括弧の種類（'sub' = コマンドの位置のサブシェル・'other' = それ以外・v3.5.2）。
  const parenKinds = [];
  const parenScopes = [];
  const parenEffects = [];
  const braceEffects = [];
  const compoundEffects = [];
  const newEffect = () => ({ pipeline: false, unsafeSetup: false, conditional: false });
  let inheritedEffects = parentEffects;
  let pipeline = newEffect();
  let closedGroup = null;
  const currentEffects = () => inheritedEffects.concat(pipeline);
  let redirNext = null;
  let redirs = [];
  let piped = false;
  const heredocs = [];
  let definitionName = null;

  const startWord = () => {
    if (!cur) cur = { text: '', braceSource: '', dynamic: false, dynamicMaySplit: false, quoted: false, start: i, evaluations: [] };
  };
  const endWord = () => {
    if (!cur) return;
    cur.raw = src.slice(cur.start, i);
    cur.braceExpanded = hasBraceExpansion(cur.braceSource);
    cur.globExpanded = /[*?\[]/.test(cur.braceSource);
    cur.tildeExpanded = /^~/.test(cur.braceSource) ||
      /^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=~/.test(cur.braceSource);
    delete cur.braceSource;
    if (cur.braceExpanded) { cur.dynamic = true; cur.dynamicMaySplit = true; }
    if (!redirNext && !cur.quoted && !cur.dynamic && atCmdPos(words)) {
      const close = { if: 'fi', while: 'done', until: 'done', for: 'done', select: 'done', case: 'esac' }[cur.text];
      if (close) {
        const group = newEffect();
        group.kind = cur.text;
        group.conditional = true; // A conditional/loop body may never update positional parameters.
        compoundEffects.push({ close, inheritedEffects, pipeline, group });
        inheritedEffects = currentEffects().concat(group);
        pipeline = newEffect();
      } else if (compoundEffects.length && compoundEffects[compoundEffects.length - 1].close === cur.text) {
        const group = compoundEffects.pop();
        inheritedEffects = group.inheritedEffects;
        pipeline = group.pipeline;
        closedGroup = group.group;
      }
    }
    if (redirNext) {
      redirs.push({ op: redirNext, word: cur });
      redirNext = null;
    } else {
      words.push(cur);
    }
    cur = null;
  };
  const endCmd = () => {
    endWord();
    redirNext = null;
    if (words.length || redirs.length) {
      const c = { words, redirs, piped, heredocBodies: [], scope, definitionName, effects: currentEffects(), arrayInitializer: scope.arrayInitializer };
      out.cmds.push(c);
      for (const h of heredocs) if (!h.cmd) h.cmd = c;
    }
    words = [];
    redirs = [];
    piped = false;
    definitionName = null;
    closedGroup = null;
  };
  const appendExpansion = (r, quoted = false) => {
    cur.evaluations.push(...(r.evaluations || []));
    if (r.quoted) cur.quoted = true;
    if (r.ansiCQuoted) cur.ansiCQuoted = true;
    if (r.ansiCUnknown) cur.ansiCUnknown = true;
    if (r.dynamic) {
      cur.dynamic = true;
      cur.braceSource += DYN;
      if ((!quoted && !r.noSplit) || r.multiWord) cur.dynamicMaySplit = true;
      cur.text += DYN;
    } else { cur.text += r.literal || ''; }
  };

  while (i < n) {
    const c = src[i];
    if (c === '\\') {
      if (src[i + 1] === '\n') { i += 2; continue; }
      startWord();
      cur.quoted = true;
      cur.braceSource += DYN;
      if (i + 1 < n) { cur.text += src[i + 1]; i += 2; } else { i++; }
      continue;
    }
    if (c === "'") {
      startWord();
      cur.quoted = true;
      cur.braceSource += DYN;
      const j = src.indexOf("'", i + 1);
      if (j < 0) { out.errors.push("閉じていない '…'"); return n; }
      cur.text += src.slice(i + 1, j);
      i = j + 1;
      continue;
    }
    if (c === '"') {
      startWord();
      cur.quoted = true;
      cur.braceSource += DYN;
      i++;
      while (i < n && src[i] !== '"') {
        const d = src[i];
        if (d === '\\' && i + 1 < n) {
          const e = src[i + 1];
          if (e !== '\n') cur.text += ('"\\$`'.includes(e)) ? e : d + e;
          i += 2;
          continue;
        }
        if (d === '$' || d === '`') {
          const r = scanExpansion(src, i, out, depth, scope, currentEffects(), true);
          appendExpansion(r, true);
          i = r.end;
          continue;
        }
        cur.text += d;
        i++;
      }
      if (i >= n) { out.errors.push('閉じていない "…"'); return n; }
      i++;
      continue;
    }
    if (c === '$' || c === '`') {
      startWord();
      const r = scanExpansion(src, i, out, depth, scope, currentEffects());
      appendExpansion(r);
      i = r.end;
      continue;
    }
    // `#` をコメントと読むのは、入力の先頭か空白・改行・`;`・`&`・`|` の後だけ（v3.3）。
    // zsh では語の途中の `(` の後の `#` は普通の文字なので、ここで読み飛ばすとシェルとずれる。
    if (c === '#' && !cur && (i === start || /[ \t\n;&|]/.test(src[i - 1]))) {
      const j = src.indexOf('\n', i);
      i = j < 0 ? n : j;
      continue;
    }
    if (c === '\n') {
      endCmd();
      pipeline = newEffect();
      i++;
      // 改行の後にヒアドキュメントの本文が来る。
      while (heredocs.length) {
        const h = heredocs.shift();
        const bodyStart = i;
        let bodyEnd = n;
        let lcLine = false;
        while (i < n) {
          const j = src.indexOf('\n', i);
          const lineEnd = j < 0 ? n : j;
          let line = src.slice(i, lineEnd);
          if (h.strip) line = line.replace(/^\t+/, '');
          if (line === h.delim) {
            bodyEnd = i;
            i = j < 0 ? n : j + 1;
            break;
          }
          // 引用符の無い本文の行末の `\`: シェルは次の行とつなぐので、終わりの語の行の見え方が変わる（v3.5.2）。
          if (!h.quoted && line.endsWith('\\')) lcLine = true;
          i = j < 0 ? n : j + 1;
        }
        // 終わりの語が見つからない（v3.5）。読み違えた始まりなら、後ろの行を読み飛ばしている。
        if (bodyEnd === n) out.errors.push('ヒアドキュメントの終わりの語が無い');
        if (lcLine) out.errors.push('引用符の無いヒアドキュメントの本文の行末に \\ がある');
        const body = src.slice(bodyStart, Math.min(bodyEnd, n));
        if (!h.quoted) {
          const evaluations = [];
          scanSubsts(body, out, depth + 1, scope, h.cmd ? h.cmd.effects : currentEffects(), evaluations);
          if (h.cmd) h.cmd.evaluations = (h.cmd.evaluations || []).concat(evaluations);
        }
        if (h.cmd) h.cmd.heredocBodies.push({ body, quoted: h.quoted });
      }
      continue;
    }
    // CR（\r）は bash / zsh と同じく語の文字として扱う（区切りにしない・v3）。
    if (c === ' ' || c === '\t') {
      endWord();
      i++;
      continue;
    }
    if (c === ';' || c === '|' || (c === '&' && src[i + 1] !== '>')) {
      if (c === '&' && src[i + 1] !== '&') out.async = true;
      const isPipe = c === '|' && src[i + 1] !== '|';
      endWord(); // fi/done/esac closes its outer segment before a trailing pipe.
      if (isPipe) pipeline.pipeline = true;
      if (c === '&' && src[i + 1] !== '&') pipeline.conditional = true;
      endCmd();
      if (!isPipe) pipeline = newEffect();
      if ((c === '&' || c === '|') && src[i + 1] === c) pipeline.conditional = true;
      piped = isPipe;
      if ((c === ';' || c === '|' || c === '&') && src[i + 1] === c) i += 2;
      else if (c === '|' && src[i + 1] === '&') i += 2;
      else i++;
      continue;
    }
    if (c === '{' && !cur && atCmdPos(words) && /[ \t\n;]/.test(src[i + 1] || '')) {
      endCmd();
      const group = newEffect();
      braceEffects.push({ inheritedEffects, pipeline, group });
      inheritedEffects = currentEffects().concat(group);
      pipeline = newEffect();
      i++;
      continue;
    }
    if (c === '}' && !cur && braceEffects.length && /[ \t\n;&|)]|^$/.test(src[i + 1] || '')) {
      endCmd();
      const group = braceEffects.pop();
      inheritedEffects = group.inheritedEffects;
      pipeline = group.pipeline;
      closedGroup = group.group;
      i++;
      continue;
    }
    if (c === '(') {
      const header = words.concat(cur ? [cur] : []);
      const fn = header[header.length - 1];
      if (/^\([ \t\n]*\)/.test(src.slice(i)) && fn && !fn.quoted && !fn.dynamic &&
          /^[A-Za-z_][A-Za-z0-9_]*$/.test(fn.text) &&
          (header.length === 1 || (header.length === 2 && header[0].text === 'function' && !header[0].quoted))) {
        definitionName = fn.text;
      }
      // `(` と `(` の間の行の継続: シェルは `((` と読む（v3.5.2）。
      if (joinedByLC(src, i + 1, '(')) out.errors.push('( と ( の間に行の継続がある');
      // コマンドの頭（予約語の後を含む・v3.5.2）か `for` の後の `((…))` は算術（v3.5）。シェルと同じく対の `))` まで
      // 生の文字として読み、中の置換だけを読む（`<<` はシフトでヒアドキュメントではない）。対にならなければ括弧として読む。
      const atCmd = !cur && atCmdPos(words);
      const arrayInitializer = !atCmd && fn && /^([A-Za-z_][A-Za-z0-9_]*)\+?=$/.exec(fn.text);
      const arithAt = atCmd || (!cur && words.length === 1 && !words[0].quoted && words[0].text === 'for');
      if (src[i + 1] === '(' && arithAt) {
        const end = arithEnd(src, i + 2);
        if (end >= 0) {
          const expression = src.slice(i + 2, end);
          scanSubsts(expression, out, depth + 1, scope, currentEffects());
          out.cmds.push({ words: [], redirs: [], piped: false, heredocBodies: [], scope,
            effects: currentEffects(), evaluations: [{ kind: 'arithmetic', text: expression }] });
          i = end + 2;
          continue;
        }
      }
      // サブシェルとみるのは、コマンドの位置の `(`（`((` でない）だけ（v3.5.2）。語の後の `(`（zsh の glob など）や
      // 算術にならなかった `((` の外側の中では、`<<` がヒアドキュメントかをシェルと同じに決められない。
      parenKinds.push(atCmd && src[i + 1] !== '(' ? 'sub' : 'other');
      endCmd();
      const group = newEffect();
      parenEffects.push({ inheritedEffects, pipeline, group });
      inheritedEffects = currentEffects().concat(group);
      pipeline = newEffect();
      parenScopes.push(scope);
      scope = { parent: scope, ...(arrayInitializer ? { arrayInitializer: arrayInitializer[1] } : {}) };
      parenDepth++;
      i++;
      continue;
    }
    if (c === ')') {
      if (parenDepth === 0 && stopAtParen) {
        // 本文を読む前に `$(…)`・`<(…)` が閉じたヒアドキュメント（v3.5.2）。シェルによっては括弧の外の行を本文にする。
        if (heredocs.length) out.errors.push('本文より前に括弧が閉じたヒアドキュメント');
        endCmd();
        return i;
      }
      endCmd();
      if (parenDepth > 0) {
        parenDepth--; parenKinds.pop(); scope = parenScopes.pop();
        const group = parenEffects.pop();
        inheritedEffects = group.inheritedEffects;
        pipeline = group.pipeline;
        closedGroup = group.group;
      }
      i++;
      continue;
    }
    if (c === '<' || c === '>' || c === '&') {
      if (closedGroup) closedGroup.unsafeSetup = true;
      // `<` と `<` の間の行の継続: シェルは `<<` と読む（v3.5.2）。
      if (c === '<' && joinedByLC(src, i + 1, '<')) out.errors.push('< と < の間に行の継続がある');
      if ((c === '<' || c === '>') && src[i + 1] === '(') {
        // プロセス置換 <( … ) / >( … )
        startWord();
        const close = parseSeq(src, i + 2, out, depth + 1, true, { parent: scope }, currentEffects());
        if (close >= n) { out.errors.push('閉じていない <( … )'); return n; }
        cur.dynamic = true;
        cur.braceSource += DYN;
        cur.text += DYN;
        i = close + 1;
        continue;
      }
      // fd の番号（2> など）は語にしない。
      if (cur && !cur.quoted && !cur.dynamic && /^\d+$/.test(cur.text)) cur = null;
      else endWord();
      if (closedGroup) closedGroup.unsafeSetup = true;
      if (c === '<' && src[i + 1] === '<' && src[i + 2] !== '<') {
        // ヒアドキュメント: 区切りの語を読み、本文は次の改行の後で読む。
        i += 2;
        let strip = false;
        if (src[i] === '-') { strip = true; i++; }
        while (src[i] === ' ' || src[i] === '\t') i++;
        let delim = '';
        let quoted = false;
        // 区切りの語は bash と同じく、空白・タブ・改行と演算子の文字だけで切る（v3.1）。
        // JS の \s で切ると FF・VT・NBSP なども切れ目になり、本文の終わりの行が bash と食い違う。
        while (i < n && !/[ \t\n;&|<>()]/.test(src[i])) {
          const d = src[i];
          if (d === "'" || d === '"') {
            const j = src.indexOf(d, i + 1);
            if (j < 0) { out.errors.push('閉じていないヒアドキュメントの区切り'); return n; }
            delim += src.slice(i + 1, j);
            quoted = true;
            i = j + 1;
            continue;
          }
          if (d === '\\') { delim += src[i + 1] || ''; quoted = true; i += 2; continue; }
          delim += d;
          i++;
        }
        if (!delim) { out.errors.push('ヒアドキュメントの区切りが無い'); return n; }
        heredocs.push({ delim, strip, quoted, cmd: null });
        // サブシェルと決められない括弧の中のヒアドキュメント（v3.5.2）。
        if (parenKinds.some((k) => k !== 'sub')) out.errors.push('サブシェルと決められない括弧の中のヒアドキュメント');
        continue;
      }
      // ほかのリダイレクト（> >> < <> >| >& <& &> &>> <<<）: 次の語は対象。
      let j = i;
      while (j < n && '<>&|'.includes(src[j]) && j - i < 3) j++;
      redirNext = src.slice(i, j);
      i = j;
      continue;
    }
    startWord();
    cur.braceSource += c;
    cur.text += c;
    i++;
  }
  endCmd();
  return n;
}

/** Parse shell source without executing it, retaining errors and isolated child scopes. */
function parseShell(src) {
  const out = { cmds: [], errors: [], scope: { parent: null }, async: false, evaluationUnknown: false };
  parseSeq(src, 0, out, 0, false, out.scope);
  return out;
}

// ---------------------------------------------------------------------------
// コマンドの名前（ラッパーを外す）
// ---------------------------------------------------------------------------

const RESERVED = new Set(['!', '{', '}', 'then', 'else', 'elif', 'fi', 'do', 'done', 'if', 'while', 'until']);
/** Assignment syntax is recognized from source, where quoting can change its shell meaning. */
const isAssignWord = (w) => /^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=/.test(w.raw);
/** Extract the variable name from an assignment, including the shell's += form. */
const assignName = (w) => w.raw.split('=')[0].replace(/\+$/, '').replace(/\[.*$/, '');

const LAUNCHER_OPTIONS = {
  setsid: {
    long: { ctty: 'c', fork: 'f', wait: 'w', help: 'h', version: 'V' },
    values: '', selectors: '', operands: 0,
  },
  taskset: {
    long: { 'all-tasks': 'a', pid: 'p', 'cpu-list': 'c', help: 'h', version: 'V' },
    values: '', selectors: 'p', operands: 1,
  },
  ionice: {
    long: { classdata: 'n', class: 'c', pid: 'p', pgid: 'P', uid: 'u', ignore: 't', help: 'h', version: 'V' },
    values: 'ncpPu', selectors: 'pPu', operands: 0,
  },
};

/** Read util-linux launchers' option arity without treating process selectors as children. */
function launcherArgs(rest, info, name) {
  const spec = LAUNCHER_OPTIONS[name];
  const shorts = new Set(Object.values(spec.long));
  let k = 0;
  let selector = false;
  let terminal = false;
  info.launcherArgs.push(...rest);
  const apply = (ch, value, attached) => {
    if (spec.selectors.includes(ch)) selector = true;
    if ('hV'.includes(ch)) terminal = true;
    if (spec.values.includes(ch) && (!value || value.dynamicMaySplit ||
        (attached && value.dynamic && !value.text.replaceAll(DYN, '')))) info.launcherUnknown = true;
  };
  while (k < rest.length && rest[k].text.startsWith('-') && rest[k].text !== '-') {
    const w = rest[k];
    const t = w.text;
    if (t === '--') { k++; break; }
    if (w.dynamicMaySplit) info.launcherUnknown = true;
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const option = t.slice(2, eq < 0 ? undefined : eq);
      const names = Object.keys(spec.long);
      const matches = names.includes(option) ? [option] : names.filter((n) => n.startsWith(option));
      if (matches.length !== 1) info.launcherUnknown = true;
      else {
        const ch = spec.long[matches[0]];
        let value;
        if (spec.values.includes(ch)) value = eq < 0 ? rest[++k] : { ...w, text: t.slice(eq + 1) };
        else if (eq >= 0) info.launcherUnknown = true;
        apply(ch, value, false);
      }
    } else {
      for (let p = 1; p < t.length; p++) {
        const ch = t[p];
        if (!shorts.has(ch)) { info.launcherUnknown = true; break; }
        let value;
        const attached = p + 1 < t.length;
        if (spec.values.includes(ch)) value = attached ? { ...w, text: t.slice(p + 1) } : rest[++k];
        apply(ch, value, attached);
        if (spec.values.includes(ch)) break;
      }
    }
    k++;
  }
  if (!info.launcherUnknown && (terminal || selector)) return -1;
  if (!info.launcherUnknown && rest.length - k <= spec.operands) return -1; // query or bad usage, no child
  for (let n = 0; n < spec.operands; n++) {
    // A variable mask can instead become another launcher option, moving the child boundary.
    if (!rest[k] || rest[k].dynamic) info.launcherUnknown = true;
    k++;
  }
  return k;
}

const WRAPPERS = {
  setsid: (rest, info) => launcherArgs(rest, info, 'setsid'),
  taskset: (rest, info) => launcherArgs(rest, info, 'taskset'),
  ionice: (rest, info) => launcherArgs(rest, info, 'ionice'),
  command: (rest) => {
    let k = 0;
    while (k < rest.length && /^-[pvV]+$/.test(rest[k].text)) {
      if (/[vV]/.test(rest[k].text)) return -1; // command -v は実行しない
      k++;
    }
    return k;
  },
  builtin: () => 0,
  exec: (rest) => {
    let k = 0;
    while (k < rest.length && rest[k].text.startsWith('-')) {
      if (rest[k].text === '-a') k++;
      k++;
    }
    return k;
  },
  nohup: () => 0,
  time: (rest) => {
    let k = 0;
    while (k < rest.length && rest[k].text === '-p') k++;
    return k;
  },
  nice: (rest) => {
    let k = 0;
    while (k < rest.length && rest[k].text.startsWith('-')) {
      if (rest[k].text === '-n') k++;
      k++;
    }
    return k;
  },
  stdbuf: (rest) => {
    let k = 0;
    while (k < rest.length && rest[k].text.startsWith('-')) {
      if (/^-[ioe]$/.test(rest[k].text)) k++;
      k++;
    }
    return k;
  },
  timeout: (rest) => {
    let k = 0;
    while (k < rest.length && rest[k].text.startsWith('-')) {
      if (/^-[sk]$/.test(rest[k].text)) k++;
      k++;
    }
    return k + 1; // DURATION
  },
  caffeinate: (rest) => {
    let k = 0;
    while (k < rest.length && rest[k].text.startsWith('-')) {
      if (/^-[tw]$/.test(rest[k].text)) k++;
      k++;
    }
    return k;
  },
  sudo: (rest, info) => {
    let k = 0;
    while (k < rest.length && rest[k].text.startsWith('-')) {
      const t = rest[k].text;
      if (t === '--') { k++; break; }
      if (/^-[ugCDhprtTU]$/.test(t)) {
        if (t === '-D') info.cdLike = true;
        k++;
      } else if (/^--chdir=/.test(t) || /^-D./.test(t)) {
        info.cdLike = true;
      }
      k++;
    }
    return k;
  },
  doas: (rest) => {
    let k = 0;
    while (k < rest.length && rest[k].text.startsWith('-')) {
      if (/^-[uC]$/.test(rest[k].text)) k++;
      k++;
    }
    return k;
  },
  env: (rest, info) => {
    const longNames = ['ignore-environment', 'null', 'unset', 'chdir', 'split-string', 'argv0', 'debug',
      'default-signal', 'ignore-signal', 'block-signal', 'list-signal-handling', 'help', 'version'];
    const required = new Set(['unset', 'chdir', 'split-string', 'argv0']);
    const apply = (name, value) => {
      if (name === 'ignore-environment') info.envOps.push({ clear: true });
      if (name === 'chdir') info.cdLike = true;
      if (name === 'split-string') {
        info.splitString = true;
        if (value) info.splitWords.push(value);
      }
      if (value && value.dynamicMaySplit) info.envUnknown = true;
      if (name === 'unset' && value && !value.dynamic) info.envOps.push({ unset: value.text });
    };
    let k = 0;
    while (k < rest.length) {
      const w = rest[k];
      const t = rest[k].text;
      if (t === '--') { k++; break; }
      if (t === '-') { apply('ignore-environment'); k++; continue; }
      if (t.startsWith('--')) {
        const eq = t.indexOf('=');
        const name = t.slice(2, eq < 0 ? undefined : eq);
        const matches = longNames.includes(name) ? [name] : longNames.filter((n) => n.startsWith(name));
        if (matches.length !== 1) { info.envUnknown = true; k++; continue; }
        const full = matches[0];
        if (full === 'help' || full === 'version') return -1;
        let value;
        if (eq >= 0) value = { ...w, text: t.slice(eq + 1) };
        else if (required.has(full)) value = rest[++k];
        if (required.has(full) && !value) info.envUnknown = true;
        apply(full, value);
        k++;
        continue;
      }
      if (t.startsWith('-')) {
        for (let p = 1; p < t.length; p++) {
          const ch = t[p];
          if (ch === 'i') { apply('ignore-environment'); continue; }
          if ('0v'.includes(ch)) continue;
          if ('SCuaP'.includes(ch)) {
            const name = { S: 'split-string', C: 'chdir', u: 'unset', a: 'argv0', P: 'path' }[ch];
            const value = p + 1 < t.length ? { ...w, text: t.slice(p + 1) } : rest[++k];
            if (!value) info.envUnknown = true;
            apply(name, value);
            break;
          }
          info.envUnknown = true;
          break;
        }
        k++;
        continue;
      }
      break;
    }
    // env 自身が読む代入はシェルの代入語と違い、引用された NAME=value も有効。
    while (k < rest.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[k].text)) {
      if (rest[k].dynamicMaySplit) info.envUnknown = true;
      const name = rest[k].text.split('=')[0];
      info.assigns.push(name);
      info.assignRaws.push(rest[k].raw);
      info.envOps.push({ set: name });
      k++;
    }
    return k;
  },
  xargs: (rest, info) => {
    info.incomplete = true; // 引数の一部が標準入力から来る
    const required = ['arg-file', 'delimiter', 'max-args', 'max-chars', 'max-procs', 'process-slot-var'];
    const optional = ['eof', 'replace', 'max-lines'];
    const flags = ['null', 'open-tty', 'interactive', 'no-run-if-empty', 'show-limits', 'verbose', 'version', 'help', 'exit'];
    const longNames = required.concat(optional, flags);
    let k = 0;
    while (k < rest.length && rest[k].text.startsWith('-')) {
      const t = rest[k].text;
      if (t === '--') { k++; break; }
      if (t.startsWith('--')) {
        const eq = t.indexOf('=');
        const name = t.slice(2, eq < 0 ? undefined : eq);
        const matches = longNames.includes(name) ? [name] : longNames.filter((n) => n.startsWith(name));
        // optional long values only attach with '='; a separate word is the command.
        if (matches.length === 1 && required.includes(matches[0]) && eq < 0) k++;
      } else {
        // A required short value consumes the rest of its bundle, or the next word.
        for (let p = 1; p < t.length; p++) {
          if ('adEIJLnPRsS'.includes(t[p])) { if (p === t.length - 1) k++; break; }
          if ('eil'.includes(t[p])) break; // optional short values attach only
        }
      }
      k++;
    }
    return k;
  },
};

/** Unwrap known launchers and retain the invocation's ordered environment changes. */
function resolveCommand(words) {
  const info = {
    name: null, nameWord: null, args: [], assigns: [], assignRaws: [],
    cdLike: false, incomplete: false, nonExec: false, dynamicName: false, splitString: false,
    envOps: [], wrapped: false, wrapperNames: [], persistsEnv: false, envUnknown: false, splitWords: [],
    launcherUnknown: false, launcherArgs: [],
  };
  let k = 0;
  for (;;) {
    while (k < words.length && !words[k].quoted && !words[k].dynamic && RESERVED.has(words[k].text)) k++;
    while (k < words.length && isAssignWord(words[k])) {
      info.assigns.push(assignName(words[k]));
      info.assignRaws.push(words[k].raw);
      info.envOps.push({ set: assignName(words[k]) });
      k++;
    }
    if (k >= words.length) return info;
    const w = words[k];
    if (w.dynamic) {
      info.dynamicName = true;
      info.nameWord = w;
      info.args = words.slice(k + 1);
      return info;
    }
    const base = path.posix.basename(w.text);
    const rest = words.slice(k + 1);
    const wrapper = Object.prototype.hasOwnProperty.call(WRAPPERS, base) ? WRAPPERS[base] : null;
    if (wrapper) {
      // exec は POSIX special builtin。プログラムを付けない形でも代入が残りうる。
      if (base === 'exec' && !info.wrapped) info.persistsEnv = true;
      info.wrapped = true;
      info.wrapperNames.push(base);
      const r = wrapper(rest, info);
      if (r < 0) { info.nonExec = true; info.name = base; return info; }
      k = k + 1 + r;
      continue;
    }
    info.name = base;
    info.nameWord = w;
    info.args = rest;
    return info;
  }
}

// ---------------------------------------------------------------------------
// git の呼び出し
// ---------------------------------------------------------------------------

// subcommand の前に置ける git の global option（git 2.54 の `git --help`）。
const GIT_FLAG_OPTS = new Set([
  '-p', '--paginate', '-P', '--no-pager', '--no-replace-objects', '--no-lazy-fetch',
  '--no-optional-locks', '--no-advice', '--bare', '--literal-pathspecs', '--glob-pathspecs',
  '--noglob-pathspecs', '--icase-pathspecs',
]);
// pathspec の当て方を変える global option（v3: commit・add・stage と同じコマンドでは拒む）。
const PATHSPEC_FLAG_OPTS = new Set(['--literal-pathspecs', '--glob-pathspecs', '--noglob-pathspecs', '--icase-pathspecs']);
// 値を次の語か `=` の後に取る option。
const GIT_VALUE_OPTS = new Set(['--git-dir', '--work-tree', '--namespace', '--config-env', '--attr-source']);
// これだけで終わる（subcommand を走らせない）option。
const GIT_TERMINAL_OPTS = new Set(['-v', '--version', '-h', '--help', '--html-path', '--man-path', '--info-path', '--exec-path']);

// 読むだけの subcommand（index・ref・作業木を書かない）。
const READ_ONLY_SUBS = new Set([
  'status', 'log', 'diff', 'show', 'rev-parse', 'ls-files', 'ls-tree', 'cat-file', 'describe',
  'shortlog', 'blame', 'grep', 'merge-base', 'rev-list', 'for-each-ref', 'show-ref', 'name-rev',
  'count-objects', 'var', 'version', 'help', 'check-ignore', 'check-attr', 'cherry', 'whatchanged',
  'diff-tree', 'diff-index', 'diff-files',
]);

// git の builtin（git 2.54 の `git --list-cmds=builtins`）。alias はこれらの名前を上書きできない。
const BUILTIN_SUBS = new Set((
  'add am annotate apply archive backfill bisect blame branch bugreport bundle cat-file check-attr ' +
  'check-ignore check-mailmap check-ref-format checkout checkout-index cherry cherry-pick clean clone ' +
  'column commit commit-graph commit-tree config count-objects credential credential-cache ' +
  'credential-store describe diagnose diff diff-files diff-index diff-pairs diff-tree difftool ' +
  'fast-export fast-import fetch fetch-pack fmt-merge-msg for-each-ref for-each-repo format-patch fsck ' +
  'fsck-objects gc get-tar-commit-id grep hash-object help history hook index-pack init init-db ' +
  'interpret-trailers last-modified log ls-files ls-remote ls-tree mailinfo mailsplit maintenance merge ' +
  'merge-base merge-file merge-index merge-ours merge-recursive merge-recursive-ours ' +
  'merge-recursive-theirs merge-subtree merge-tree mktag mktree multi-pack-index mv name-rev notes ' +
  'pack-objects pack-redundant pack-refs patch-id pickaxe prune prune-packed pull push range-diff ' +
  'read-tree rebase receive-pack reflog refs remote repack replace replay repo rerere reset restore ' +
  'rev-list rev-parse revert rm send-pack shortlog show show-branch show-index show-ref ' +
  'sparse-checkout stage stash status switch symbolic-ref tag unpack-file unpack-objects update-index ' +
  'update-ref update-server-info upload-archive upload-pack var verify-commit verify-pack verify-tag ' +
  'version whatchanged worktree write-tree'
).split(' '));

// 変数や置換で作られたコマンドの名前が、git を作っているかもしれない目印の subcommand。
const RISKY_SUBS = new Set([
  'add', 'stage', 'rm', 'mv', 'commit', 'commit-tree', 'mktree', 'update-ref', 'update-index',
  'read-tree', 'apply', 'checkout', 'restore', 'reset', 'stash', 'merge', 'cherry-pick', 'revert',
  'am', 'push', 'send-pack', 'http-push', 'fast-import', 'remote', 'config',
]);

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'fish']);
const CD_LIKE = new Set(['cd', 'pushd', 'popd']);
const EXPORT_LIKE = new Set(['export', 'declare', 'typeset', 'local', 'readonly']);
const CONFIG_ROOT_ENV = new Set(['HOME', 'XDG_CONFIG_HOME']);
/** Include Git's configuration-root variables in per-invocation environment effects. */
const affectsGitEnvironment = (name) => /^GIT_/.test(name) || CONFIG_ROOT_ENV.has(name);
/** Shell declaration options stop at the first operand; later strings are variable names or values. */
function declarationOptions(args) {
  const options = [];
  for (const word of args) {
    if (word.dynamic || word.text === '--' || !/^[-+][A-Za-z]+$/.test(word.text)) break;
    options.push(word.text);
  }
  return options;
}
// POSIX モードでは prefix の代入が、通常のコマンドと違い special builtin の後にも残る。
const SPECIAL_BUILTINS = new Set([':', '.', 'break', 'continue', 'eval', 'exit', 'export', 'readonly', 'return', 'set', 'shift', 'times', 'trap', 'unset']);
const COMMAND_SEARCH_MUTATORS = new Set(['alias', 'unalias', 'hash', 'rehash', 'enable', 'autoload', 'functions']);

// commit や add と同じコマンドの git に付けてよい `-c` / `--config-env` の鍵（短い allowlist）。
// 設定の中には、git に別のプログラムを走らせるものがある。そのため、ここに無い鍵は
// commit や add と同じコマンドでは検査できないとして拒む。足すときは、表示や名前だけを
// 変える鍵に限る。
const CONFIG_KEY_ALLOW = [/^core\.quotepath$/, /^color\./, /^advice\./, /^user\.name$/, /^user\.email$/];
/** Extract the case-insensitive Git configuration key from a key=value argument. */
const configKey = (v) => v.split('=')[0].toLowerCase();
/** Only display and identity settings are safe beside staging or commit commands. */
const configKeyAllowed = (v) => CONFIG_KEY_ALLOW.some((re) => re.test(configKey(v)));
const STAGING_OR_COMMIT = new Set(['commit', 'add', 'stage']);

/** Match Git as a word rather than as a substring of names such as digit. */
const hasGitText = (s) => /(^|[^a-z])git([^a-z]|$)/i.test(s);
/** Detect Git in source, outer-shell text, and the quoting removed by a mediated shell. */
const wordHasGit = (w) => hasGitText(w.raw) || hasGitText(w.text) || hasGitText(w.text.replace(/['"\\]/g, ''));

/** Separate Git global options, the subcommand, and its arguments without evaluating values. */
function parseGit(args) {
  const g = {
    sub: null, args: [], cdirs: [], configs: [], configEnvs: [], gitDir: false, workTree: false,
    dynamicOpt: false, terminal: false, problems: [], pathspecFlags: [], pagerForced: false, pagerDisabled: false,
  };
  let k = 0;
  while (k < args.length) {
    const w = args[k];
    const t = w.text;
    if (w.dynamic) {
      g.problems.push('git の global option か subcommand が変数や置換で作られていて、読みきれない');
      return g;
    }
    if (!t.startsWith('-')) break;
    if (t === '-C' || t === '-c') {
      const v = args[k + 1];
      if (!v) { g.problems.push(`git の ${t} に値が無い`); return g; }
      if (v.dynamicMaySplit) { g.problems.push(`git の ${t} の値が複数の語になりうるため、subcommand を決められない`); return g; }
      if (v.dynamic) g.dynamicOpt = true;
      if (t === '-C') g.cdirs.push(v.text); else g.configs.push(v.text);
      k += 2;
      continue;
    }
    if (GIT_FLAG_OPTS.has(t)) {
      if (t === '-p' || t === '--paginate') g.pagerForced = true;
      if (t === '-P' || t === '--no-pager') g.pagerForced = false;
      if (t === '-p' || t === '--paginate') g.pagerDisabled = false;
      if (t === '-P' || t === '--no-pager') g.pagerDisabled = true;
      if (PATHSPEC_FLAG_OPTS.has(t)) g.pathspecFlags.push(t);
      k++;
      continue;
    }
    if (GIT_TERMINAL_OPTS.has(t)) {
      g.terminal = true;
      g.helpKind = t === '--help' && k + 1 < args.length ? 'manual' : 'stdout';
      return g;
    }
    const eq = t.indexOf('=');
    const name = eq < 0 ? t : t.slice(0, eq);
    if (GIT_VALUE_OPTS.has(name) || (name === '--exec-path' && eq >= 0) || (name === '--list-cmds' && eq >= 0)) {
      let value;
      if (eq >= 0) { value = t.slice(eq + 1); k++; } else {
        const v = args[k + 1];
        if (!v) { g.problems.push(`git の ${t} に値が無い`); return g; }
        if (v.dynamicMaySplit) { g.problems.push(`git の ${t} の値が複数の語になりうるため、subcommand を決められない`); return g; }
        if (v.dynamic) g.dynamicOpt = true;
        value = v.text;
        k += 2;
      }
      if (name === '--git-dir') g.gitDir = true;
      if (name === '--work-tree') g.workTree = true;
      if (name === '--config-env') g.configEnvs.push(value);
      if (name === '--list-cmds') { g.terminal = true; g.helpKind = 'stdout'; return g; }
      continue;
    }
    g.problems.push(`git の知らない global option（${t}）が subcommand の前にある`);
    return g;
  }
  if (k >= args.length) return g;
  g.sub = args[k].text;
  g.args = args.slice(k + 1);
  return g;
}

/** Locate shell source using option arity, preserving subsequent positional arguments as data. */
function shellInvocation(args, name) {
  const scripts = [];
  let commandMode = false;
  let stdin = false;
  let unknown = false;
  let k = 0;
  const fishLong = {
    command: 'c', 'init-command': 'C', features: 'f', debug: 'd', 'debug-output': 'o',
    'debug-stack-frames': 'D', profile: 'p', 'profile-startup': 'p', interactive: 'i',
    login: 'l', 'no-config': 'N', 'no-execute': 'n', 'print-rusage-self': 'r',
    'print-debug-categories': 'r', private: 'P', help: 'h', version: 'v',
  };
  const fishValue = (ch, value) => {
    if (!value || value.dynamicMaySplit) unknown = true;
    if (ch === 'c') commandMode = true;
    if ('cC'.includes(ch) && value) scripts.push(value);
  };
  for (; k < args.length; k++) {
    const w = args[k];
    const t = w.text;
    if (t === '--' || t === '-') { k++; break; }
    if (w.dynamicMaySplit || (w.dynamic && !/^[+-]/.test(t))) { unknown = true; break; }
    if (!/^[+-]/.test(t) || (name === 'fish' && t[0] === '+')) break;
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const option = t.slice(2, eq < 0 ? undefined : eq);
      if (name === 'fish') {
        const names = Object.keys(fishLong);
        const matches = names.includes(option) ? [option] : names.filter((n) => n.startsWith(option));
        if (matches.length !== 1) { unknown = true; continue; }
        const ch = fishLong[matches[0]];
        if ('cCdofpD'.includes(ch)) fishValue(ch, eq < 0 ? args[++k] : { ...w, text: t.slice(eq + 1) });
        else if (eq >= 0) unknown = true;
      } else if (['rcfile', 'init-file', 'emulate'].includes(option)) {
        const value = eq < 0 ? args[++k] : { ...w, text: t.slice(eq + 1) };
        if (!value || value.dynamicMaySplit) unknown = true;
      } else if (!['debugger', 'dump-po-strings', 'dump-strings', 'help', 'login', 'noediting',
        'noprofile', 'norc', 'posix', 'restricted', 'verbose', 'version'].includes(option) || eq >= 0) unknown = true;
      continue;
    }
    for (let p = 1; p < t.length; p++) {
      const ch = t[p];
      if (!/[A-Za-z]/.test(ch)) { unknown = true; break; }
      if (name === 'fish') {
        if ('cCdofpD'.includes(ch)) {
          const attached = t.slice(p + 1);
          const value = attached ? { ...w, text: attached } : args[++k];
          fishValue(ch, value);
          if (attached && value.dynamic && !value.text.replaceAll(DYN, '')) unknown = true;
          break;
        }
        if (!'hPilNnv'.includes(ch)) unknown = true;
      } else if (ch === 'o' || ch === 'O') {
        // -o / -O take an optional option name; attached text is that name, not more flags.
        if (p + 1 === t.length && args[k + 1] && !/^[+-]/.test(args[k + 1].text)) {
          if (args[++k].dynamic) unknown = true;
        }
        break;
      } else if (t[0] === '-') {
        if (ch === 'c') commandMode = true;
        if (ch === 's') stdin = true;
      }
    }
  }
  if (name !== 'fish' && commandMode) {
    if (args[k]) scripts.push(args[k]);
    else unknown = true;
  }
  const operand = args[k];
  const readsStdin = !commandMode && (stdin || !operand || (!operand.dynamic &&
    (operand.text === '-' || ['/dev/stdin', '/dev/fd/0', '/proc/self/fd/0', '/proc/thread-self/fd/0']
      .includes(path.posix.normalize(operand.text)))));
  const positionals = commandMode ? args.slice(k + (name === 'fish' ? 0 : 2))
    : stdin ? args.slice(k) : operand ? args.slice(k + 1) : [];
  return { scripts, commandMode, readsStdin, unknown, positionals };
}

/** Detect Git text that a shell can expose after tokenization, without executing its input. */
function shellInputHasGit(source) {
  return hasGitText(source.replace(/['"\\]/g, '')) ||
    parseShell(source).cmds.some((c) => c.words.some(wordHasGit));
}

/** Select only a registered trap action; queries, signal operands and reset forms are data. */
function trapInvocation(args) {
  let k = 0;
  let query = false;
  let unknown = false;
  while (k < args.length && args[k].text.startsWith('-') && args[k].text !== '-') {
    const word = args[k];
    if (word.text === '--') { k++; break; }
    if (word.text === '--help') { query = true; k++; continue; }
    if (!word.dynamic && /^-[pl]+$/.test(word.text)) query = true;
    else { unknown = true; break; }
    k++;
  }
  const action = args[k];
  if (query || !action || args.length - k < 2 || (!action.dynamic &&
      (action.text === '' || action.text === '-' || /^\d+$/.test(action.text)))) return { scripts: [], query, unknown: false };
  return { scripts: [action], query: false, unknown };
}

/** Select alias definitions' executable values; query names and dump/reset forms stay data. */
function aliasInvocation(args) {
  const scripts = [];
  let options = true;
  let unknown = false;
  for (const word of args) {
    if (options && word.text === '--' && !word.dynamic) { options = false; continue; }
    if (options && word.text.startsWith('-')) {
      if (word.dynamic || !/^-[p]+$/.test(word.text)) unknown = true;
      continue;
    }
    options = false;
    const definition = /^([^=]+)=(.*)$/s.exec(word.text);
    if (definition) scripts.push({ ...word, text: definition[2] });
    else if (word.dynamic) unknown = true;
  }
  return { scripts, unknown };
}

/** Read a variable assignment's cooked literal value, retaining an indexed target for arithmetic checks. */
function scalarAssignment(word) {
  const match = /^([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?(\+?=)(.*)$/s.exec(word.text);
  return match && { name: match[1], index: match[2], append: match[3] === '+=', value: word.dynamic || word.tildeExpanded ? null : match[4] };
}

/** Prove arithmetic contains only numbers, operators and recursively known numeric values; never evaluate it. */
function numericArithmetic(source, state, seen = new Set(), depth = 0) {
  if (typeof source !== 'string' || seen.size > MAX_DEPTH || depth > MAX_DEPTH) return false;
  let unknownExpansion = false;
  source = source.replace(/\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})/g, (_match, plain, braced) => {
    const name = plain || braced;
    const next = new Set(seen); next.add(name);
    if (state.valuesTainted || seen.has(name) || !state.values.has(name) ||
        !numericArithmetic(state.values.get(name), state, next, depth + 1)) unknownExpansion = true;
    return '0';
  });
  if (unknownExpansion || /[$`'"\\]/.test(source)) return false;
  const values = new Map(state.values);
  const proveValue = (name) => {
    if (seen.has(name) || !values.has(name) || values.get(name) === null) return false;
    const next = new Set(seen); next.add(name);
    return numericArithmetic(values.get(name), { ...state, values }, next, depth + 1);
  };
  for (let part of source.split(/[;,]/)) {
    // A statically numeric assignment makes its target safe for subsequent clauses of arithmetic for/let.
    const assignment = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)(.*)$/s.exec(part);
    if (assignment) {
      if (!numericArithmetic(assignment[2], { ...state, values }, seen, depth + 1)) return false;
      values.set(assignment[1], '0');
      continue;
    }
    let k = 0;
    while (k < part.length) {
      const rest = part.slice(k);
      const number = /^(?:[0-9]+#[A-Za-z0-9@_]+|0[xX][0-9A-Fa-f]+|[0-9]+)/.exec(rest);
      if (number) { k += number[0].length; continue; }
      const identifier = /^[A-Za-z_][A-Za-z0-9_]*/.exec(rest);
      if (identifier) {
        if (state.valuesTainted) return false;
        let name = identifier[0]; k += name.length;
        if (part[k] === '[') {
          const end = part.indexOf(']', k + 1);
          if (end < 0) return false;
          const index = part.slice(k + 1, end).trim();
          if (!numericArithmetic(index, { ...state, values }, seen, depth + 1) || !/^(?:0|[1-9]\d*)$/.test(index)) return false;
          name += '[' + index + ']'; k = end + 1;
        }
        if (!proveValue(name)) return false;
        continue;
      }
      if (!/[ \t\n()+\-*\/%<>=!~&|^?:]/.test(part[k])) return false;
      k++;
    }
  }
  return true;
}

/** Keep literal scalar/array values in their shell scope; conditional overwrites require agreement. */
function rememberValue(state, assignment, conditional) {
  let key = assignment.name;
  if (assignment.index !== undefined) {
    if (!/^(?:0|[1-9]\d*)$/.test(assignment.index)) {
      state.values.delete(key);
      for (const entry of state.values.keys()) if (entry.startsWith(key + '[')) state.values.set(entry, null);
      return;
    }
    key += '[' + assignment.index + ']';
  } else {
    // A scalar assignment can overwrite element zero of a previously created array.
    state.values.set(key + '[0]', null);
  }
  let value = assignment.value;
  if (assignment.append) value = value !== null && state.values.has(key) && state.values.get(key) !== null
    ? state.values.get(key) + value : null;
  if (conditional && (!state.values.has(key) || state.values.get(key) !== value)) value = null;
  state.values.set(key, value);
  if (assignment.index === undefined && typeof value === 'string' && !state.valuesTainted &&
      !state.integers.has(key) && !state.associatives.has(key)) state.pathProofs.add(key);
  else state.pathProofs.delete(assignment.name);
}

/** Read one arithmetic operand after a simple scalar expansion, without treating its value as shell text. */
function arithmeticOperand(word, state) {
  if (!word.dynamic) return word.text;
  const scalar = /^"?\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})"?$/.exec(word.raw);
  if (scalar && !state.valuesTainted) return state.values.get(scalar[1] || scalar[2]);
  return null;
}

/** Select printf's assignment target and format; attached -v names have the same effects as -v names. */
function printfValueEffect(args) {
  const first = args[0];
  const targetWord = first && first.text === '-v' ? args[1] : first && first.text.startsWith('-v')
    ? { ...first, text: first.text.slice(2) } : null;
  const format = first && first.text === '-v' ? args[2] : targetWord ? args[1]
    : first && first.text === '--' ? args[1] : first;
  const unknownFormat = !!format && (format.dynamic || /%[-+# 0]*(?:\*|\d+)?(?:\.(?:\*|\d+))?n/.test(format.text));
  return { targetWord, unknownFormat };
}

/** Select read's variable targets without treating prompt/delimiter values as environment assignments. */
function readEnvironmentTargets(args) {
  let array = null;
  let k = 0;
  for (; k < args.length; k++) {
    const word = args[k];
    const text = word.text;
    if (word.dynamic) return { targets: [], unknown: true };
    if (text === '--help') return { targets: [], unknown: false };
    if (text === '--') { k++; break; }
    if (!text.startsWith('-')) break;
    if (text.length < 2) return { targets: [], unknown: true };
    for (let p = 1; p < text.length; p++) {
      const option = text[p];
      if ('eErs'.includes(option)) continue;
      if (!'adinNptu'.includes(option)) return { targets: [], unknown: true };
      const value = p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : args[++k];
      if (!value || (value.dynamic && value.dynamicMaySplit !== false)) return { targets: [], unknown: true };
      if (option === 'a') array = value;
      break;
    }
  }
  const targets = array ? [array] : args.slice(k);
  return { targets, unknown: targets.some((word) => word.dynamic) };
}

/** Delayed code which can assign shell values invalidates proofs made before registration. */
function sourceChangesValues(inner) {
  return inner.invocations.some((entry) => {
    if (entry.assignments.length) return true;
    if (entry.name === 'printf') {
      const effect = printfValueEffect(entry.args);
      return !!effect.targetWord || effect.unknownFormat;
    }
    return ['set', 'read', 'readarray', 'mapfile', 'getopts', 'declare', 'typeset', 'local', 'readonly', 'unset', 'let'].includes(entry.name);
  });
}

/** Read set's positional operands without confusing option queries or consumed -o names with argv. */
function positionalSet(args) {
  let k = 0;
  let explicit = false;
  let unknown = false;
  while (k < args.length) {
    const word = args[k];
    const text = word.text;
    if (text === '--') { k++; explicit = true; break; }
    if (text === '-') { k++; break; }
    if (word.dynamic) { unknown = true; break; }
    if (!/^[+-]/.test(text)) break;
    for (let p = 1; p < text.length; p++) {
      if (text[p] === 'o') {
        if (p + 1 === text.length && args[k + 1] && !/^[+-]/.test(args[k + 1].text)) {
          if (args[++k].dynamic) unknown = true;
        }
        break;
      }
      if (!/[A-Za-z]/.test(text[p])) unknown = true;
    }
    k++;
  }
  if (!explicit && k >= args.length) return null;
  return { words: args.slice(k), unknown };
}

/** Detect positional expansion in executable position, including scalar and sliced forms. */
const positionalExecutable = (word) => word && word.dynamic &&
  /\$(?:[@*1-9]|\{(?:[@*]|[1-9][0-9]*)(?:\}|[:#%/+-]))/.test(word.raw);
/** Quoted @ preserves the known tuple's word boundaries, unlike unquoted expansions and $*. */
const exactQuotedAt = (word) => /^"\$(?:@|\{@\})"$/.test(word.raw);
/** Preserve expanded argv as literal words: its contents are not shell assignments or reserved words. */
const expandedLiteral = (word) => ({ ...word, raw: "'" + word.text.replace(/'/g, "'\\''") + "'", quoted: true });
/** Only fully known words with preserved boundaries can be reused as positional argv. */
const knownPositionals = (words) => words.every((word) => !word.dynamic &&
  (word.quoted || !/[?*\[]/.test(word.text))) ? words : null;

/** Inspect an executable source string conservatively while leaving ordinary command arguments as data. */
function inspectMediatedSource(source, depth = 0) {
  const word = typeof source === 'string' ? { text: source, dynamic: false } : source;
  if (!word || word.dynamic) return { gits: [], invocations: [], problems: ['実行する source 文字列が動的で、中身を検査できない'] };
  const inner = inspect(word.text, { sourceDepth: depth + 1 });
  const opaque = inner.invocations.some((invocation) => invocation.dynamicName || invocation.definitionName ||
    ['.', 'source', 'eval'].includes(invocation.name) || COMMAND_SEARCH_MUTATORS.has(invocation.name) ||
    invocation.shellSourceUnknown || invocation.shellScripts.some((script) => script.dynamic) ||
    (SHELLS.has(invocation.name) && !invocation.shellCommandMode && !invocation.heredocBodies.length &&
      !invocation.redirs.some((redir) => redir.op === '<<<' && !redir.word.dynamic)));
  if (inner.gits.length || opaque) inner.problems.push('文字列から実行する git や不明な実行先は、場所・環境・helper を検査できない');
  return inner;
}

let trustedGitPaths;
/** Permit system Git and the exact executable used by this hook's unchanged PATH lookup. */
function trustedGitExecutable(word) {
  if (!trustedGitPaths) {
    trustedGitPaths = new Set();
    const remember = (p) => { try { trustedGitPaths.add(fs.realpathSync(p)); } catch {} };
    remember('/usr/bin/git');
    remember('/bin/git');
    for (const dir of (process.env.PATH || '').split(path.delimiter)) {
      const candidate = path.resolve(dir || '.', 'git');
      try {
        fs.accessSync(candidate, fs.constants.X_OK);
        if (!fs.statSync(candidate).isFile()) continue;
        remember(candidate);
        break;
      } catch {}
    }
  }
  if (word.text === 'git') return trustedGitPaths.size > 0;
  if (!path.isAbsolute(word.text)) return false;
  try { return trustedGitPaths.has(fs.realpathSync(word.text)); } catch { return false; }
}

let inspectionSerial = 0;

/** Inspect executable Git invocations, associating preceding scope changes with each invocation. */
function inspect(cmd, options = {}) {
  const sourceDepth = options.sourceDepth || 0;
  const inspectionId = ++inspectionSerial;
  const pipelineIds = new Map();
  const res = {
    gits: [], problems: [], cdLike: false, gitEnvNames: [], cmdCount: 0, invocations: [], async: false,
  };
  res.commands = res.invocations;
  if (sourceDepth > MAX_DEPTH) { res.problems.push('source 文字列の入れ子が深すぎる'); return res; }
  const normalized = cmd.replace(/['"\\]/g, '');
  const gitContext = hasGitText(normalized);
  // CR（\r）を含むコマンドは、シェルと同じに語へ分けられる保証が無い（v3・fail-closed）。
  if (cmd.includes('\r') && gitContext) {
    res.problems.push('コマンドに CR（\\r）があり、シェルと同じに語へ分けられる保証が無い');
  }
  const parsed = parseShell(cmd);
  if (parsed.evaluationUnknown) res.problems.push('Bash の実行する置換の source 境界を読みきれない');
  res.async = parsed.async;
  if (parsed.errors.length && gitContext) {
    res.problems.push(`コマンドの引用符や括弧が閉じていない（${parsed.errors[0]}）`);
  }
  const assignRawsAll = [];
  const queue = parsed.cmds.map((c) => ({ c, origin: 'top' }));
  const resolved = [];
  for (let qi = 0; qi < queue.length; qi++) {
    const { c } = queue[qi];
    const info = resolveCommand(c.words);
    resolved.push({ c, info });
    assignRawsAll.push(...info.assignRaws);
  }
  // 代入の値に git の語がある（`G=git` のように、後で変数からコマンドを作りうる）。
  const gitInAssign = assignRawsAll.some((raw) => hasGitText(raw.slice(raw.indexOf('=') + 1).replace(/['"\\]/g, '')));

  // スコープの状態は最初のコマンドを訪れた時に親から写す。置換とサブシェルの変更は親へ戻さない。
  const scopeStates = new Map();
  const emptyState = () => ({ env: new Set(), cd: false, pathChanged: false, searchChanged: false, unknownContext: false, gitShadowed: false, positionals: null, positionalsTainted: false, values: new Map(), integers: new Set(), associatives: new Set(), valuesTainted: false, loopBindings: new Map(), pathProofs: new Set() });
  const copyState = (s) => ({ ...s, env: new Set(s.env), values: new Map(s.values), integers: new Set(s.integers), associatives: new Set(s.associatives), loopBindings: new Map(s.loopBindings), pathProofs: new Set(s.pathProofs) });
  const stateFor = (scope) => {
    if (!scopeStates.has(scope)) {
      scopeStates.set(scope, scope && scope.parent ? copyState(stateFor(scope.parent)) : emptyState());
    }
    return scopeStates.get(scope);
  };
  const seedScope = (scope, env, cd, inherited) => scopeStates.set(scope, copyState({ ...emptyState(), ...inherited, env: new Set(env), cd }));
  if (Array.isArray(options.initialPositionals)) scopeStates.set(parsed.scope, { ...emptyState(), positionals: knownPositionals(options.initialPositionals) });
  const updatePositionals = (state, c, next) => {
    const conditional = (c.effects || []).some((effect) => effect.conditional || effect.pipeline);
    const same = state.positionals && next && state.positionals.length === next.length &&
      state.positionals.every((word, index) => word.text === next[index].text);
    state.positionals = conditional && !same ? null : next;
  };

  const visit = (c, info, depth) => {
    if (depth > MAX_DEPTH) { res.problems.push('入れ子が深すぎる'); return; }
    const state = stateFor(c.scope);
    for (const [frame, name] of state.loopBindings) if (!(c.effects || []).includes(frame)) {
      state.values.set(name, null); state.loopBindings.delete(frame); state.pathProofs.delete(name);
    }
    let loopBinding = false;
    if (info.name === 'for' && info.args[0] && info.args[1]?.text === 'in') {
      state.values.set(info.args[0].text, null); state.pathProofs.delete(info.args[0].text);
    }
    if (info.name === 'for' && info.args.length === 3 && !info.args.some((word) => word.dynamic) &&
        /^[A-Za-z_][A-Za-z0-9_]*$/.test(info.args[0].text) && info.args[1].text === 'in' &&
        !info.args[2].braceExpanded && !info.args[2].tildeExpanded &&
        (info.args[2].quoted || !/[?*\[]/.test(info.args[2].text))) {
      const frame = (c.effects || []).findLast((effect) => effect.kind === 'for');
      if (frame) {
        state.values.set(info.args[0].text, info.args[2].text); state.loopBindings.set(frame, info.args[0].text);
        state.pathProofs.add(info.args[0].text); loopBinding = true;
      }
    }
    const conditional = (c.effects || []).some((effect) => effect.conditional || effect.pipeline);
    const checkEvaluation = (evaluation, valuesState) => {
      if (evaluation.kind === 'arithmetic' && !(evaluation.arrayName && valuesState.associatives.has(evaluation.arrayName)) &&
          !numericArithmetic(evaluation.text, valuesState)) {
        res.problems.push('算術で再評価される変数・添字・式が静的な数値と確かめられず、保存された source の実行を検査できない');
      } else if (evaluation.kind === 'prompt') {
        const value = valuesState.values.get(evaluation.text);
        if (valuesState.valuesTainted || typeof value !== 'string' || /[$`\\]/.test(value)) {
          res.problems.push('@P で再評価する prompt の値を確かめられず、保存された source の実行を検査できない');
        }
      } else if (evaluation.kind === 'source') {
        const inner = inspectMediatedSource(evaluation.text, sourceDepth);
        if (inner.problems.length) res.problems.push(`Bash の current-environment command substitution を検査できない（${inner.problems[0]}）`);
      }
    };
    for (const evaluation of c.evaluations || []) checkEvaluation(evaluation, state);
    // Assignment-only commands expand assignments in order. Prefix assignments to other commands
    // are not proofs for those commands' argument expansions.
    const expansionState = copyState(state);
    // Flattened current-environment bodies may have changed a value before an earlier outer-word
    // expansion is inspected. Do not certify a saved value from that reordered visit.
    if (c.words.some((word) => (word.evaluations || []).some((evaluation) => evaluation.kind === 'source'))) {
      expansionState.valuesTainted = true;
      state.pathProofs.clear();
    }
    for (const word of c.words.concat(c.redirs.map((redir) => redir.word))) {
      for (const evaluation of word.evaluations || []) checkEvaluation(evaluation, expansionState);
      const assignment = scalarAssignment(word);
      if (!info.name && !info.dynamicName && assignment) rememberValue(expansionState, assignment, conditional);
    }
    if (c.arrayInitializer) {
      for (const word of c.words) {
        const indexed = /^\[([^\]]*)\]=(.*)$/s.exec(word.text);
        if (indexed && !state.associatives.has(c.arrayInitializer) && !numericArithmetic(indexed[1], state)) {
          res.problems.push('配列の compound assignment の添字を静的な数値と確かめられない');
        }
        if (state.integers.has(c.arrayInitializer) && !numericArithmetic(word.dynamic ? null : indexed ? indexed[2] : word.text, state)) {
          res.problems.push('整数配列の compound assignment の値を静的な数値と確かめられない');
        }
      }
      return; // Initializer elements are data; their direct substitutions were collected separately.
    }
    const positionalExec = positionalExecutable(info.nameWord);
    const positionalsBefore = state.positionals;
    let positionalUnknown = !!positionalExec && (state.positionalsTainted || state.searchChanged);
    if (positionalExec && !positionalUnknown) {
      let replacement;
      const scalar = /^"\$(?:([1-9])|\{([1-9][0-9]*)\})"$/.exec(info.nameWord.raw);
      if (state.positionals && exactQuotedAt(info.nameWord)) replacement = state.positionals;
      else if (state.positionals && scalar) {
        replacement = [state.positionals[Number(scalar[1] || scalar[2]) - 1] || { text: '', dynamic: false, quoted: true }];
      } else if (state.positionals && !state.positionals.length && /^\$(?:[@*]|\{[@*]\})$/.test(info.nameWord.raw)) replacement = [];
      else if (state.positionals && !state.positionals.length && /^"\$(?:\*|\{\*\})"$/.test(info.nameWord.raw)) replacement = [{ text: '', dynamic: false, quoted: true }];
      else positionalUnknown = true;
      if (replacement) {
        const index = c.words.indexOf(info.nameWord);
        info = resolveCommand(c.words.slice(0, index).concat(replacement.map(expandedLiteral), c.words.slice(index + 1)));
      }
    }
    const env = new Set(state.env);
    let pathChanged = state.pathChanged;
    for (const op of info.envOps) {
      if (op.clear) { env.clear(); for (const root of CONFIG_ROOT_ENV) env.add(root); pathChanged = false; }
      if (op.unset) {
        if (CONFIG_ROOT_ENV.has(op.unset)) env.add(op.unset); else env.delete(op.unset);
        if (op.unset === 'PATH') pathChanged = false;
      }
      if (op.set && affectsGitEnvironment(op.set)) env.add(op.set);
      if (op.set === 'PATH' || op.set === 'FPATH') pathChanged = true;
    }
    const cdBefore = state.cd || info.cdLike;
    const shell = SHELLS.has(info.name) ? shellInvocation(info.args, info.name) : null;
    const builtin = info.wrapperNames.every((name) => name === 'command' || name === 'builtin');
    const trap = info.name === 'trap' && builtin ? trapInvocation(info.args) : null;
    const alias = info.name === 'alias' && builtin ? aliasInvocation(info.args) : null;
    const invocation = {
      order: res.invocations.length, name: info.name, nameWord: info.nameWord, args: info.args,
      words: c.words, redirs: c.redirs, heredocBodies: c.heredocBodies, scope: c.scope, incomplete: info.incomplete,
      wrapped: info.wrapped, nonExec: info.nonExec, dynamicName: info.dynamicName,
      wrapperNames: info.wrapperNames,
      launcherUnknown: info.launcherUnknown, launcherArgs: info.launcherArgs,
      positionalExec: !!positionalExec, positionalUnknown, positionalsBefore,
      splitString: info.splitString, splitWords: info.splitWords, envUnknown: info.envUnknown,
      definitionName: c.definitionName || (info.name === 'function' ? (info.args[0] && info.args[0].text) : null),
      assignments: info.assigns, gitEnvNames: [...env], cdLikeBefore: cdBefore,
      pathChangedBefore: pathChanged || state.searchChanged,
      unknownContextBefore: state.unknownContext,
      pipelineParticipant: (c.effects || []).some((e) => e.pipeline),
      pipelineIds: (c.effects || []).filter((effect) => effect.pipeline).map((effect) => {
        if (!pipelineIds.has(effect)) pipelineIds.set(effect, `${inspectionId}:${pipelineIds.size}`);
        return pipelineIds.get(effect);
      }),
      unsafeGroupSetup: (c.effects || []).some((e) => e.unsafeSetup),
      shellScripts: shell ? shell.scripts : [], shellCommandMode: shell ? shell.commandMode : false,
      shellSourceUnknown: shell ? shell.unknown : false, shellReadsStdin: shell ? shell.readsStdin : false,
      shellPositionals: shell && !shell.unknown ? shell.positionals : null,
      trapScripts: trap ? trap.scripts : [], trapSourceUnknown: trap ? trap.unknown : false,
      aliasScripts: alias ? alias.scripts : [], aliasSourceUnknown: alias ? alias.unknown : false,
      // Carrier offsets allow template/data evidence to be mapped back to a known executable body.
      // Its output is dynamic, but these selected source bytes are literal and already visited above.
      expansionScripts: c.words.flatMap((word) => {
        const sources = (word.evaluations || []).filter((evaluation) => evaluation.kind === 'source');
        return sources.length && sources.every((source) => typeof source.text === 'string')
          ? [{ ...word, text: sources.map((source) => source.text).join(';\n'), dynamic: false }] : [];
      }),
    };
    res.invocations.push(invocation);
    const persistentValues = (!info.name && !info.dynamicName && !info.wrapped) ||
      info.persistsEnv || (builtin && (SPECIAL_BUILTINS.has(info.name) || EXPORT_LIKE.has(info.name)));
    const declaration = builtin && EXPORT_LIKE.has(info.name);
    const declOptions = declaration ? declarationOptions(info.args) : [];
    const declarationQuery = ['declare', 'typeset', 'local'].includes(info.name) &&
      declOptions.some((option) => /^-[A-Za-z]*p[A-Za-z]*$/.test(option));
    const integerDeclaration = !declarationQuery && declOptions.some((option) => /^-[A-Za-z]*i[A-Za-z]*$/.test(option));
    const associativeDeclaration = !declarationQuery && declOptions.some((option) => /^-[A-Za-z]*A[A-Za-z]*$/.test(option));
    if (builtin && !declarationQuery && ['declare', 'typeset', 'local'].includes(info.name) &&
        declOptions.some((option) => /^-[A-Za-z]*n[A-Za-z]*$/.test(option))) state.valuesTainted = true;
    const valueWords = c.words.filter((word) => info.assignRaws.includes(word.raw))
      .concat(declaration && !declarationQuery ? info.args : []);
    for (const word of valueWords) {
      const assignment = scalarAssignment(word);
      const prefix = info.assignRaws.includes(word.raw) && !info.args.includes(word);
      const valueConditional = conditional || (!!info.name && prefix);
      const canRemember = prefix ? ((!info.name && !info.dynamicName && !info.wrapped) || info.persistsEnv ||
        (builtin && SPECIAL_BUILTINS.has(info.name))) : persistentValues;
      if (!assignment) {
        if (integerDeclaration && /^[A-Za-z_][A-Za-z0-9_]*$/.test(word.text)) state.integers.add(word.text);
        if (associativeDeclaration && !conditional && /^[A-Za-z_][A-Za-z0-9_]*$/.test(word.text)) state.associatives.add(word.text);
        continue;
      }
      if (associativeDeclaration && !prefix && !conditional) state.associatives.add(assignment.name);
      if (assignment.index !== undefined && !state.associatives.has(assignment.name) && !numericArithmetic(assignment.index, state)) {
        res.problems.push('配列の添字が静的な数値と確かめられず、添字で評価する source を検査できない');
      }
      if ((!prefix && integerDeclaration) || state.integers.has(assignment.name)) {
        state.integers.add(assignment.name);
        if (!numericArithmetic(assignment.value, state)) {
          res.problems.push('整数属性への代入が静的な数値と確かめられず、保存された source の再評価を検査できない');
        }
        if (canRemember) rememberValue(state, { ...assignment, value: '0' }, valueConditional);
      } else if (canRemember) rememberValue(state, assignment, valueConditional);
    }
    if (builtin && info.name === 'let') {
      for (const word of info.args) {
        if (!numericArithmetic(word.dynamic ? null : word.text, state)) {
          res.problems.push('let の式が静的な数値と確かめられず、保存された source の再評価を検査できない');
        }
      }
    }
    if (builtin && info.name === '[[') {
      for (let k = 1; k + 1 < info.args.length; k++) {
        if (!/^-(?:eq|ne|lt|le|gt|ge)$/.test(info.args[k].text)) continue;
        for (const word of [info.args[k - 1], info.args[k + 1]]) {
          if (!numericArithmetic(arithmeticOperand(word, state), state)) res.problems.push('[[ ]] の数値比較で再評価する式を検査できない');
        }
      }
    }
    // Builtins which can assign/read unknown text invalidate cached literal proofs.
    if (builtin && ['read', 'readarray', 'mapfile', 'unset'].includes(info.name)) {
      if (info.name === 'read') {
        const read = readEnvironmentTargets(info.args);
        if (read.unknown) {
          // An unresolved target can replace config roots or command lookup, even for a later Git read.
          for (const root of CONFIG_ROOT_ENV) state.env.add(root);
          state.pathChanged = true;
        }
        for (const word of read.targets) {
          const target = /^([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?$/.exec(word.text);
          if (!target) continue;
          if (affectsGitEnvironment(target[1])) state.env.add(target[1]);
          if (target[1] === 'PATH' || target[1] === 'FPATH') state.pathChanged = true;
        }
      }
      if (info.args.some((word) => word.dynamic)) { state.valuesTainted = true; state.associatives.clear(); }
      if (!info.args.length && info.name === 'read') state.values.set('REPLY', null);
      for (const word of info.args) {
        const target = /^([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?$/.exec(word.text);
        if (!target) continue;
        if (target[2] !== undefined && !numericArithmetic(target[2], state)) res.problems.push('builtin が評価する配列の添字を検査できない');
        state.values.set(target[1], null);
        if (info.name === 'unset') state.associatives.delete(target[1]);
        for (const key of state.values.keys()) if (key.startsWith(target[1] + '[')) state.values.set(key, null);
      }
    }
    if (builtin && info.name === 'printf') {
      const { targetWord, unknownFormat } = printfValueEffect(info.args);
      if (unknownFormat) state.valuesTainted = true;
      const target = targetWord && /^([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?$/.exec(targetWord.text);
      if (targetWord && (!target || targetWord.dynamic)) {
        state.valuesTainted = true;
        res.problems.push('printf -v の代入先が不明で、配列の添字で評価する source を検査できない');
      }
      if (target) {
        if (target[2] !== undefined && !numericArithmetic(target[2], state)) res.problems.push('printf -v が評価する配列の添字を検査できない');
        state.values.set(target[1], null);
        state.pathProofs.delete(target[1]);
        if (affectsGitEnvironment(target[1])) state.env.add(target[1]);
        if (target[1] === 'PATH' || target[1] === 'FPATH') state.pathChanged = true;
        for (const key of state.values.keys()) if (key.startsWith(target[1] + '[')) state.values.set(key, null);
      }
    }
    if (builtin && info.name === 'getopts') {
      const targetWord = info.args[1];
      const target = targetWord && /^([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?$/.exec(targetWord.text);
      for (const name of ['OPTARG', 'OPTIND', ...(target ? [target[1]] : [])]) {
        state.values.set(name, null); state.pathProofs.delete(name);
        if (affectsGitEnvironment(name)) state.env.add(name);
        if (name === 'PATH' || name === 'FPATH') state.pathChanged = true;
      }
      if (!target || targetWord.dynamic) { state.valuesTainted = true; res.problems.push('getopts の代入先を検査できない'); }
      else if (target[2] !== undefined && !numericArithmetic(target[2], state)) res.problems.push('getopts の配列の添字を検査できない');
    }
    const literalBinding = valueWords.some((word) => {
      const assignment = scalarAssignment(word);
      return assignment && !word.dynamic && !conditional && !info.name;
    }) || (declaration && !declarationQuery && valueWords.some((word) =>
      info.args.includes(word) && scalarAssignment(word) && !word.dynamic));
    if (info.name && info.name !== 'git' && !info.nonExec && !loopBinding && !literalBinding && !declarationQuery) state.pathProofs.clear();
    if (info.name && !info.nonExec && !['git', 'for', ':', 'true', 'false', 'echo', 'printf', 'pwd', 'test', '[', '[[',
      'cd', 'pushd', 'popd', 'export', 'declare', 'typeset', 'local', 'readonly', 'unset', 'read', 'readarray', 'mapfile',
      'getopts', 'let', 'set', 'shift', 'trap', 'alias'].includes(info.name)) state.valuesTainted = true;
    if (info.cdLike) res.cdLike = true;
    for (const a of info.assigns) if (affectsGitEnvironment(a) && !res.gitEnvNames.includes(a)) res.gitEnvNames.push(a);
    if (!info.name && !info.dynamicName && !info.wrapped) { state.env = env; state.pathChanged = pathChanged; }
    if (info.persistsEnv || (!info.wrapped && SPECIAL_BUILTINS.has(info.name))) {
      for (const a of env) state.env.add(a);
      state.pathChanged = state.pathChanged || pathChanged;
    }
    if (invocation.definitionName) {
      state.unknownContext = true;
      state.positionalsTainted = true;
      state.valuesTainted = true;
      if (invocation.definitionName === 'git') state.gitShadowed = true;
    }
    if (info.envUnknown && (gitContext || c.words.some(wordHasGit))) {
      res.problems.push('env の option が不明・曖昧、または値が複数の語になりうるため、git の実行を検査できない');
      return;
    }
    if (info.launcherUnknown && (gitContext || c.words.some(wordHasGit))) {
      res.problems.push('launcher の option や引数の個数を読みきれず、git の実行先を確かめられない');
      return;
    }
    if (positionalUnknown || (positionalExec && info.name === 'git')) {
      res.problems.push('位置引数から実行する git や不明なコマンドは、引数と実行先を検査できない');
      return;
    }
    if (info.dynamicName) {
      if (wordHasGit(info.nameWord) || gitInAssign ||
          info.args.some((w) => !w.dynamic && path.posix.basename(w.text) === 'git') ||
          info.args.some((w) => !w.dynamic && RISKY_SUBS.has(w.text))) {
        res.problems.push('コマンドの名前が変数や置換で作られていて、git かどうかを決められない');
      }
      return;
    }
    if (info.splitString && c.words.concat(info.splitWords).some((w) => wordHasGit(w) || (w.dynamic && gitContext))) {
      res.problems.push('env -S の文字列に入れた git は、中身を検査できない');
    }
    if (!info.name || info.nonExec) return;
    if (/[ \t\n\r]/.test(info.nameWord.text) && wordHasGit(info.nameWord)) {
      res.problems.push('空白を含むコマンド名に git があり、文字列がどう分割されるか検査できない');
      return;
    }
    const name = info.name;
    if (builtin && name === 'set') {
      const change = positionalSet(info.args);
      if (change) {
        const words = change.words.flatMap((word) => state.positionals && exactQuotedAt(word) ? state.positionals : [word]);
        updatePositionals(state, c, change.unknown ? null : knownPositionals(words));
      }
      return; // Stored positional operands are data until an executable expansion uses them.
    }
    if (builtin && name === 'shift') {
      const count = info.args.length ? info.args[0] : { text: '1', dynamic: false };
      if (info.args.length > 1 || (!count.dynamic && !/^\d+$/.test(count.text))) { /* invalid shift leaves argv unchanged */ }
      else if (!state.positionals || count.dynamic) updatePositionals(state, c, null);
      else if (Number(count.text) <= state.positionals.length) updatePositionals(state, c, state.positionals.slice(Number(count.text)));
    }
    if (trap) {
      if (trap.unknown) res.problems.push('trap の action の位置を読みきれず、実行する source を検査できない');
      for (const script of trap.scripts) {
        const inner = inspectMediatedSource(script, sourceDepth);
        if (inner.problems.length) res.problems.push(`trap の action を検査できない（${inner.problems[0]}）`);
        if (sourceChangesValues(inner)) state.valuesTainted = true;
        if (inner.invocations.some((entry) =>
          (entry.name === 'set' && positionalSet(entry.args)) ||
          (entry.name === 'shift' && (!entry.args[0] || entry.args[0].dynamic || entry.args[0].text !== '0')))) state.positionalsTainted = true;
      }
      if (trap.scripts.length) state.unknownContext = true; // A DEBUG/signal action may run before a later write.
      return;
    }
    if (alias) {
      if (alias.unknown) res.problems.push('alias の定義の位置や値を読みきれず、実行する source を検査できない');
      for (const script of alias.scripts) {
        const inner = inspectMediatedSource(script, sourceDepth);
        if (inner.problems.length) res.problems.push(`alias の値を検査できない（${inner.problems[0]}）`);
        if (sourceChangesValues(inner)) state.valuesTainted = true;
      }
      if (alias.scripts.length || alias.unknown) state.searchChanged = true;
      return;
    }
    if (name === '.' || name === 'source' || name === 'eval') {
      state.unknownContext = true;
      state.positionalsTainted = true;
      state.valuesTainted = true;
      state.searchChanged = true; // 未読のコードは PATH や関数による command lookup も変えうる。
    }
    if (COMMAND_SEARCH_MUTATORS.has(name)) state.searchChanged = true;
    if ((name === 'hash' && info.args.some((word) => word.dynamic || /^-[^-]*p/.test(word.text))) ||
        (name === 'enable' && info.args.some((word) => word.dynamic || /^-[^-]*f/.test(word.text))) ||
        (name === 'autoload' && info.args.some((word) => word.dynamic || !word.text.startsWith('-')))) {
      res.problems.push('command lookup に未検査の実行先や source を登録する形は、中身を検査できない');
      state.valuesTainted = true;
    }
    if (CD_LIKE.has(name)) { res.cdLike = true; state.cd = true; }
    if (EXPORT_LIKE.has(name)) {
      const print = declOptions.some((option) => /^-[A-Za-z]*p[A-Za-z]*$/.test(option));
      const query = ['declare', 'typeset', 'local'].includes(name) && print;
      for (const w of info.args) {
        if (query) continue;
        const nm = w.text.split('=')[0];
        if (affectsGitEnvironment(nm) && (w.text.includes('=') || !print)) {
          res.gitEnvNames.push(nm); state.env.add(nm);
        }
        if (nm === 'PATH' || nm === 'FPATH') state.pathChanged = true;
      }
    }
    if (name === 'unset') for (const word of info.args) {
      if (CONFIG_ROOT_ENV.has(word.text)) { state.env.add(word.text); res.gitEnvNames.push(word.text); }
    }
    // unset は && / || の分岐で実行されないことがあるので、永続状態からは消さない。
    if (SHELLS.has(name)) {
      const inputGit = c.heredocBodies.some((h) => shellInputHasGit(h.body)) ||
        c.redirs.some((r) => r.op === '<<<' && wordHasGit(r.word));
      if (shell.unknown && (gitContext || inputGit)) {
        res.problems.push(`${name} の option や source の位置を読みきれず、git の実行を検査できない`);
        return;
      }
      if ((shell.commandMode && inputGit) || shell.scripts.some((script) => wordHasGit(script) || (script.dynamic && gitContext))) {
        res.problems.push(`${name} に渡す source 文字列の git は、中身を検査できない`);
      }
      if (!shell.commandMode) {
        // 標準入力（ヒアドキュメント・here-string・パイプ）から読むシェル。
        const reads = shell.readsStdin;
        if (reads) {
          for (const h of c.heredocBodies) {
            const inner = parseShell(h.body);
            for (const ic of inner.cmds) ic.effects.push(...(c.effects || []));
            res.async = res.async || inner.async;
            seedScope(inner.scope, env, cdBefore, { ...state, pathChanged, positionals: shell.unknown ? null : knownPositionals(shell.positionals) });
            if (inner.errors.length && shellInputHasGit(h.body)) {
              res.problems.push(`${name} に流すヒアドキュメントを読みきれない`);
            }
            for (const ic of inner.cmds) visit(ic, resolveCommand(ic.words), depth + 1);
          }
          for (const r of c.redirs) {
            if (r.op === '<<<' && (wordHasGit(r.word) || (r.word.dynamic && gitContext))) {
              if (r.word.dynamic) res.problems.push(`${name} に流す文字列の git は、中身を検査できない`);
              else {
                const inner = parseShell(r.word.text);
                for (const ic of inner.cmds) ic.effects.push(...(c.effects || []));
                res.async = res.async || inner.async;
                seedScope(inner.scope, env, cdBefore, { ...state, pathChanged, positionals: shell.unknown ? null : knownPositionals(shell.positionals) });
                if (inner.errors.length) res.problems.push(`${name} に流す文字列の git を読みきれない`);
                for (const ic of inner.cmds) visit(ic, resolveCommand(ic.words), depth + 1);
              }
            }
          }
          if (c.piped && gitContext) {
            res.problems.push(`パイプで ${name} に流したコマンドは、中身を検査できない`);
          }
        } else if (inputGit) {
          res.problems.push(`${name} の script 引数が標準入力を読むか確かめられず、入力に git がある`);
        }
      }
      return;
    }
    if (name === 'eval') {
      if (info.args.some((w) => wordHasGit(w) || (w.dynamic && gitContext))) {
        res.problems.push('eval に渡した git は、中身を検査できない');
      }
      return;
    }
    if (name === 'find') {
      for (let k = 0; k < info.args.length; k++) {
        if (/^-(exec|execdir|ok|okdir)$/.test(info.args[k].text)) {
          let e = k + 1;
          while (e < info.args.length && info.args[e].text !== ';' && info.args[e].text !== '+') e++;
          const sub = resolveCommand(info.args.slice(k + 1, e));
          sub.incomplete = true;
          const scope = { parent: null };
          seedScope(scope, env, cdBefore, { ...state, pathChanged });
          visit({ words: info.args.slice(k + 1, e), redirs: [], piped: false, heredocBodies: [], scope, effects: c.effects }, sub, depth + 1);
          k = e;
        }
      }
      return;
    }
    if (name !== 'git') {
      // Literal printf/echo argv is data, including in a tuple or inspected source string.
      if ((positionalExec || sourceDepth > 0 || c.mediated || info.args.some((word) => word.ansiCQuoted)) &&
          ['echo', 'printf'].includes(name) &&
          [name, '/bin/' + name, '/usr/bin/' + name].includes(info.nameWord.text)) return;
      // git 以外の名前で包んで git を走らせる形（`arch -arm64 git commit …` など・v3）。
      // `git` の語の後が書き込む側の subcommand（または読みきれない語の後に目印の subcommand）
      // のときだけ、git のコマンドとして読む（`grep -rn git .` や `which git` は止めない）。
      const gi = info.args.findIndex((w) => !w.dynamic && path.posix.basename(w.text) === 'git');
      if (gi >= 0) {
        const tail = info.args.slice(gi);
        const tg = parseGit(tail.slice(1));
        // v3.2: builtin でなくても名前の形の subcommand（alias かもしれない）なら git として読み、
        // 直接の git と同じく secret-git の alias の確かめに回す（`grep -rn git .` の `.` は名前の形でない）。
        const writes = tg.sub && !tg.terminal && !READ_ONLY_SUBS.has(tg.sub) &&
          (BUILTIN_SUBS.has(tg.sub) || /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(tg.sub));
        const unclear = tg.problems.length && tail.some((w) => !w.dynamic && RISKY_SUBS.has(w.text));
        if (writes || unclear) {
          // 外側が xargs / find なら、未知 wrapper を外しても追加引数の不確定性を保つ。
          const scope = { parent: null };
          seedScope(scope, env, cdBefore, { ...state, pathChanged });
          const sub = resolveCommand(tail);
          sub.incomplete = info.incomplete || sub.incomplete;
          visit({ words: tail, redirs: [], piped: false, heredocBodies: [], scope, effects: c.effects }, sub, depth + 1);
        }
      }
      return;
    }
    const g = parseGit(info.args);
    if (g.problems.length) { res.problems.push(...g.problems); return; }
    g.args = g.args.map((word) => {
      const variable = /^"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})"$/.exec(word.raw);
      const name = variable && (variable[1] || variable[2]);
      const known = name && state.pathProofs.has(name) && !state.valuesTainted && state.values.get(name);
      return typeof known === 'string' ? { ...word, literalValue: known } : word;
    });
    if (g.sub === 'commit') {
      const parsedCommit = parseCommitArgs(g.args);
      if (parsedCommit.terminal) { g.terminal = true; g.helpKind = parsedCommit.helpKind; }
    }
    if (['add', 'stage'].includes(g.sub)) {
      const parsedAdd = parseAddArgs(g.args);
      if (parsedAdd.terminal) { g.terminal = true; g.helpKind = parsedAdd.helpKind; }
    }
    if (BUILTIN_SUBS.has(g.sub) && g.args.length === 1 && !g.args[0].dynamic &&
        ['-h', '--help'].includes(g.args[0].text)) {
      g.terminal = true; g.helpKind = g.args[0].text === '-h' ? 'stdout' : 'manual';
    }
    if (info.args.some((word) => word.ansiCUnknown) && !g.terminal) {
      res.problems.push('git の ANSI-C 引用の値を確定できず、option や pathspec を検査できない');
      return;
    }
    g.incomplete = info.incomplete;
    if (info.nameWord.ansiCQuoted && g.sub && !g.terminal && !READ_ONLY_SUBS.has(g.sub) && !readOnlyGitMode(g)) {
      res.problems.push('ANSI-C 引用で作った git の名前からの書込みは、直接の git guard の対象と確かめられない');
      return;
    }
    const rootSafe = !g.pagerForced && ((g.terminal && g.helpKind === 'stdout') ||
      (g.sub === 'config' && !g.terminal && readOnlyGitMode(g, false, !g.pagerDisabled)) ||
      (g.sub === 'version' && !g.terminal && (g.args.length === 0 ||
        (g.args.length === 1 && !g.args[0].dynamic && g.args[0].text === '--build-options'))));
    if ([...env].some((name) => CONFIG_ROOT_ENV.has(name)) && !rootSafe) {
      res.problems.push('HOME / XDG_CONFIG_HOME の設定・解除で git の設定ファイルの場所が変わり、書込みや helper の実行を検査できない');
      return;
    }
    if (!trustedGitExecutable(info.nameWord) || pathChanged || state.searchChanged || state.gitShadowed) {
      res.problems.push('git の実行ファイルやコマンド探索が変わっていて、検査に使う git と同じ実行先か確かめられない');
      return;
    }
    if (state.unknownContext && g.sub && !g.terminal && !READ_ONLY_SUBS.has(g.sub)) {
      res.problems.push('source / eval / 関数定義の後の git 書込みは、実行前の場所と環境を確かめられない');
      return;
    }
    if (['add', 'stage'].includes(g.sub) && g.args.some((w) => w.braceExpanded)) {
      res.problems.push('git add / stage の引数に brace expansion があり、追加される pathspec を検査できない');
      return;
    }
    if (g.dynamicOpt && !(g.sub && READ_ONLY_SUBS.has(g.sub))) {
      res.problems.push('git の -C / -c などの値が変数や置換で作られていて、読みきれない');
      return;
    }
    const aliasCfg = g.configs.concat(g.configEnvs).find((v) => /^(alias\.|include\.|includeif\.)/i.test(v));
    if (aliasCfg) {
      res.problems.push(`git の -c / --config-env で alias や include を足す形は、中身を検査できない（${aliasCfg.split('=')[0]}）`);
      return;
    }
    g.incomplete = info.incomplete;
    g.invocationOrder = invocation.order;
    g.unknownContextBefore = state.unknownContext;
    g.pipelineParticipant = invocation.pipelineParticipant;
    g.pipelineIds = invocation.pipelineIds;
    g.unsafeGroupSetup = invocation.unsafeGroupSetup;
    g.gitEnvNames = [...env];
    g.cdLikeBefore = cdBefore;
    res.gits.push(g);
  };

  for (const { c, info } of resolved) visit(c, info, 0);
  res.cmdCount = resolved.length;
  const finalRoot = stateFor(parsed.scope);
  if (res.gits.length && (finalRoot.pathChanged || finalRoot.searchChanged || finalRoot.gitShadowed)) {
    res.problems.push('git と同じ入力で永続する PATH / コマンド探索の変更があり、後続の実行先を保証できない');
  }

  // commit や add と同じコマンドでは、どの git の `-c` / `--config-env` も allowlist の鍵に限る。
  if (res.gits.some((g) => STAGING_OR_COMMIT.has(g.sub))) {
    // pathspec の当て方を変える global option は、検査（ls-files など）と当て方がそろう保証が無い（v3）。
    const psf = res.gits.find((g) => g.pathspecFlags.length);
    if (psf) {
      res.problems.push(`commit や add と同じコマンドの git に、pathspec の当て方を変える global option（${psf.pathspecFlags[0]}）がある`);
    }
    for (const g of res.gits) {
      const cfgs = g.configs.concat(g.configEnvs);
      if (cfgs.some((v) => v.includes(DYN))) {
        res.problems.push('commit や add と同じコマンドの git の -c / --config-env の値が変数や置換で作られていて、読みきれない');
        break;
      }
      const bad = cfgs.find((v) => !configKeyAllowed(v));
      if (bad) {
        res.problems.push(
          `commit や add と同じコマンドの git の -c / --config-env の鍵（${configKey(bad)}）は、allowlist の外なので検査できない` +
          '（使える鍵: core.quotepath・color.*・advice.*・user.name・user.email）',
        );
        break;
      }
    }
  }
  return res;
}

/** Give a shared fail-closed explanation for a parser limitation. */
function problemMessage(problems, guardLabel) {
  return `git のコマンドを${guardLabel}で検査できない形のためブロックしました (fail-closed): ${problems[0]}。\n` +
    'git は `git <subcommand> …` の形でそのまま書き、変数・置換・文字列のシェルを通さずに実行してください。';
}

/** Reject configured aliases because their executable body is outside the inspected command. */
function aliasProblem(g, baseDir) {
  if (!g.sub || BUILTIN_SUBS.has(g.sub)) return null;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(g.sub)) return `git の subcommand の形を読めない（${g.sub}）`;
  if (g.gitDir || g.workTree) return `--git-dir / --work-tree を付けた builtin でない subcommand（${g.sub}）は検査できない`;
  const dir = resolveDir(baseDir, g.cdirs);
  try {
    execFileSync('git', ['config', '--get', `alias.${g.sub}`], { cwd: dir, stdio: ['ignore', 'ignore', 'ignore'] });
    return `git の alias（${g.sub}）は、中身を検査できない`;
  } catch (e) {
    if (e && e.status === 1) return null;
    return `git の alias かどうかを確かめられない（${g.sub}・${dir}）`;
  }
}

/** Resolve repeated Git -C paths sequentially, as Git does for relative paths. */
function resolveDir(baseDir, cdirs) {
  return cdirs.reduce((d, c) => path.resolve(d, c), baseDir);
}

// ---------------------------------------------------------------------------
// git commit の引数（git 2.54 の `git commit -h`）
// ---------------------------------------------------------------------------

const COMMIT_SHORT_VALUE = new Set(['F', 'm', 'c', 'C', 't', 'U']);
const COMMIT_SHORT_ATTACHED = new Set(['S', 'u']); // 値は束の残り（無くてもよい）
const COMMIT_SHORT_FLAGS = new Set(['q', 'v', 's', 'e', 'a', 'i', 'p', 'o', 'n', 'z']);
// v = 値を取る（`--x=v` か `--x v`）・o = 値は `=` でだけ・f = 値を取らない。
// n = `--no-` を付けた形もある。
const COMMIT_LONG = {
  quiet: 'fn', verbose: 'fn', file: 'vn', author: 'vn', date: 'vn', message: 'vn', 'reedit-message': 'vn',
  'reuse-message': 'vn', fixup: 'vn', squash: 'vn', 'reset-author': 'fn', trailer: 'vn', signoff: 'fn',
  template: 'vn', edit: 'fn', cleanup: 'vn', status: 'fn', 'gpg-sign': 'on', all: 'fn', include: 'fn',
  interactive: 'fn', patch: 'fn', unified: 'v', 'inter-hunk-context': 'v', only: 'fn', 'no-verify': 'f',
  verify: 'f', 'dry-run': 'fn', short: 'fn', branch: 'fn', 'ahead-behind': 'fn', porcelain: 'fn',
  long: 'fn', null: 'fn', amend: 'fn', 'no-post-rewrite': 'f', 'post-rewrite': 'f',
  'allow-empty': 'fn', 'allow-empty-message': 'fn', // -h に出ない（隠し）が受ける
  'untracked-files': 'on', 'pathspec-from-file': 'vn', 'pathspec-file-nul': 'fn',
};
const COMMIT_LONG_NAMES = Object.keys(COMMIT_LONG).concat(
  Object.keys(COMMIT_LONG).filter((k) => COMMIT_LONG[k].includes('n')).map((k) => `no-${k}`),
);

/** Resolve an exact or unambiguous abbreviated commit option, including supported negations. */
function resolveCommitLong(name) {
  if (COMMIT_LONG_NAMES.includes(name)) return name;
  const c = COMMIT_LONG_NAMES.filter((k) => k.startsWith(name));
  return c.length === 1 ? c[0] : null;
}

/** Describe a selected message-file argv value without reading it or applying Git pathspec escapes. */
function messageFileSource(kind, value, attached = false) {
  const word = value && typeof value.literalValue === 'string'
    ? { ...value, text: value.literalValue, dynamic: false, dynamicMaySplit: false } : value || null;
  const text = word && word.text;
  const normalized = typeof text === 'string' ? path.posix.normalize(text) : null;
  const descriptor = normalized && /^(?:\/dev\/fd|\/proc\/(?:self|thread-self|[0-9]+)\/fd)\/[0-9]+$/.test(normalized);
  const stdin = !!word && !word.dynamic && ((kind === 'file' && text === '-') ||
    normalized === '/dev/stdin' || (descriptor && /\/0$/.test(normalized)));
  const unknown = !word || word.dynamic || word.dynamicMaySplit || word.ansiCUnknown ||
    word.braceExpanded || word.tildeExpanded || word.globExpanded || stdin || descriptor;
  return { kind, word, stdin, attached, unknown: !!unknown };
}

/** Identify commit-time staging and pathspecs while accepting single-word dynamic option values. */
function parseCommitArgs(words) {
  const r = { all: false, patch: false, fromFile: false, noVerify: false, terminal: false, dynamic: false, unknown: [], pathspecs: [],
    messageFiles: [], messageFileUnknown: false, messageFileSelectionUnknown: false };
  let inlineMessage = false;
  let reusedMessage = false;
  let sourceOverride = false;
  const finish = () => {
    r.messageFileUnknown = r.dynamic || r.unknown.length > 0 || r.messageFiles.some((source) => source.unknown);
    r.messageFileSelectionUnknown = r.messageFiles.length > 1 ||
      (r.messageFiles.length > 0 && (inlineMessage || reusedMessage || sourceOverride));
    return r;
  };
  let k = 0;
  let afterDD = false;
  while (k < words.length) {
    const w = words[k];
    const t = w.text;
    if (afterDD) {
      if (w.dynamic) r.dynamic = true; else r.pathspecs.push(t);
      k++;
      continue;
    }
    // 引用された展開を既知 option の値だけに使う形は、option/pathspec を増やさない。
    // 引用されていない展開は語分割で追加の引数になりうるため、値でも読みきれない。
    if (w.dynamicMaySplit) { r.dynamic = true; k++; continue; }
    if (t === '--') { afterDD = true; k++; continue; }
    if (t === '--help' && !w.dynamic) {
      if (!r.dynamic && !r.unknown.length) { r.terminal = true; r.helpKind = 'manual'; }
      return finish();
    }
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const nm = eq < 0 ? t.slice(2) : t.slice(2, eq);
      if (nm.includes(DYN)) { r.dynamic = true; k++; continue; }
      const full = resolveCommitLong(nm);
      if (!full) { r.unknown.push(t); k++; continue; }
      const base = full.startsWith('no-') && !COMMIT_LONG[full] ? full.slice(3) : full;
      const kind = COMMIT_LONG[base] || 'f';
      if (full === 'message') inlineMessage = true;
      if (['reedit-message', 'reuse-message'].includes(full)) reusedMessage = true;
      if (['no-file', 'no-template', 'no-message', 'no-reedit-message', 'no-reuse-message'].includes(full)) sourceOverride = true;
      if (full === 'all') r.all = true;
      if (full === 'patch' || full === 'interactive') r.patch = true;
      if (full === 'pathspec-from-file') r.fromFile = true;
      if (full === 'no-verify') r.noVerify = true;
      const takesValue = !full.startsWith('no-') && (kind.startsWith('v') || kind.startsWith('o'));
      if (w.dynamic && !takesValue) r.dynamic = true;
      if (full === 'file' || full === 'template') {
        const value = eq < 0 ? words[k + 1] : { ...w, text: t.slice(eq + 1) };
        r.messageFiles.push(messageFileSource(full, value, eq >= 0));
      }
      if (kind.startsWith('v') && !full.startsWith('no-') && eq < 0) {
        if (words[k + 1] && words[k + 1].dynamicMaySplit) r.dynamic = true;
        k += 2; continue;
      }
      k++;
      continue;
    }
    if (t.startsWith('-') && t.length > 1) {
      for (let p = 1; p < t.length; p++) {
        const ch = t[p];
        if (ch === DYN) { r.dynamic = true; break; }
        // 不明な先行引数が -m 等になると、この -h は値として消費されうる。
        if (ch === 'h') { if (!r.dynamic && !r.unknown.length) { r.terminal = true; r.helpKind = 'stdout'; } break; }
        if (COMMIT_SHORT_VALUE.has(ch)) {
          if (ch === 'm') inlineMessage = true;
          if (ch === 'c' || ch === 'C') reusedMessage = true;
          if (ch === 'F' || ch === 't') {
            const value = p + 1 < t.length ? { ...w, text: t.slice(p + 1) } : words[k + 1];
            r.messageFiles.push(messageFileSource(ch === 'F' ? 'file' : 'template', value, p + 1 < t.length));
          }
          if (p === t.length - 1) {
            if (words[k + 1] && words[k + 1].dynamicMaySplit) r.dynamic = true;
            k++; // 値は次の語
          } else if (w.dynamic && !t.slice(p + 1).replaceAll(DYN, '') && k + 1 < words.length) {
            // -m"$MSG" は MSG が空なら -m になり、次の語を値として消費する。
            r.dynamic = true;
          }
          break;
        }
        if (COMMIT_SHORT_ATTACHED.has(ch)) break;
        if (ch === 'a') r.all = true;
        if (ch === 'p') r.patch = true;
        if (ch === 'n') r.noVerify = true;
        if (!COMMIT_SHORT_FLAGS.has(ch)) { r.unknown.push(t); break; }
      }
      k++;
      continue;
    }
    if (w.dynamic) r.dynamic = true; else r.pathspecs.push(t);
    k++;
  }
  return finish();
}

/** Select merge's real file-message operands while keeping option values and refs as DATA. */
function parseMergeMessageArgs(words) {
  const r = { terminal: false, messageFiles: [], messageFileUnknown: false, messageFileSelectionUnknown: false };
  const required = new Set(['file', 'message', 'strategy', 'strategy-option', 'into-name', 'cleanup']);
  const optional = new Set(['log', 'gpg-sign']);
  const flags = new Set(['stat', 'summary', 'compact-summary', 'squash', 'commit', 'edit', 'ff', 'ff-only',
    'rerere-autoupdate', 'verify-signatures', 'abort', 'quit', 'continue', 'allow-unrelated-histories',
    'progress', 'autostash', 'overwrite-ignore', 'signoff', 'no-verify', 'quiet', 'verbose']);
  const names = [...required, ...optional, ...flags];
  names.push(...names.filter((name) => !['file', 'ff-only'].includes(name)).map((name) =>
    name.startsWith('no-') ? name.slice(3) : `no-${name}`));
  let unknown = false;
  let inlineMessage = false;
  let sourceOverride = false;
  let afterDD = false;
  const finish = () => {
    r.messageFileUnknown = unknown || r.messageFiles.some((source) => source.unknown);
    r.messageFileSelectionUnknown = r.messageFiles.length > 1 ||
      (r.messageFiles.length > 0 && (inlineMessage || sourceOverride));
    return r;
  };
  const consume = (option, value, carrier, attached, emptyCanShift = false) => {
    if (!value || value.dynamicMaySplit || value.braceExpanded || value.globExpanded || value.tildeExpanded) unknown = true;
    if (option === 'message') inlineMessage = true;
    if (option === 'file') {
      const selected = value && attached ? { ...value } : value;
      if (selected && attached) delete selected.literalValue;
      r.messageFiles.push(messageFileSource('file', selected, attached));
    }
    // An attached empty expansion can leave a required short option without its value.
    if (emptyCanShift && carrier.dynamic && !value.text.replaceAll(DYN, '')) unknown = true;
  };
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    const t = w.text;
    if (afterDD) continue;
    if (w.dynamicMaySplit || w.ansiCUnknown || w.braceExpanded || w.globExpanded || w.tildeExpanded) {
      unknown = true;
      continue;
    }
    if (t === '--') { afterDD = true; continue; }
    if (t === '--help' && !w.dynamic) { if (!unknown) r.terminal = true; return finish(); }
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const name = t.slice(2, eq < 0 ? undefined : eq);
      const matches = names.filter((candidate) => candidate.startsWith(name));
      const option = names.includes(name) ? name : matches.length === 1 ? matches[0] : null;
      if (!option || name.includes(DYN)) { unknown = true; continue; }
      if (option === 'no-message') sourceOverride = true;
      if (required.has(option)) {
        if (eq >= 0) consume(option, { ...w, text: t.slice(eq + 1) }, w, true);
        else consume(option, words[++i], w, false);
      } else if (optional.has(option)) {
        if (eq >= 0 && (w.dynamicMaySplit || w.ansiCUnknown)) unknown = true;
      } else if (eq >= 0 || w.dynamic) unknown = true;
      continue;
    }
    if (t.startsWith('-') && t !== '-') {
      for (let j = 1; j < t.length; j++) {
        const ch = t[j];
        if (ch === 'h') { if (!unknown) r.terminal = true; return finish(); }
        const option = { F: 'file', m: 'message', s: 'strategy', X: 'strategy-option' }[ch];
        if (option) {
          if (j + 1 < t.length) consume(option, { ...w, text: t.slice(j + 1) }, w, true, i + 1 < words.length);
          else consume(option, words[++i], w, false);
          break;
        }
        if (ch === 'S') break; // Its key is optional and attached only.
        if (!['n', 'e', 'q', 'v'].includes(ch) || w.dynamic) { unknown = true; break; }
      }
    } else if (w.dynamic) unknown = true;
  }
  return finish();
}

/** Limit stash queries to static, understood read options; every other action stays unsupported. */
function parseStashRoute(g) {
  const words = g.args;
  const empty = { messageFiles: [], messageFileUnknown: false, messageFileSelectionUnknown: false };
  if (!words.length) return { ...empty, mode: 'write', action: 'push' };
  const staticWord = (word) => word && !word.dynamic && !word.dynamicMaySplit && !word.ansiCUnknown &&
    !word.braceExpanded && !word.globExpanded && !word.tildeExpanded;
  const help = (word) => staticWord(word) && ['-h', '--help'].includes(word.text);
  if (help(words[0])) return { ...empty, mode: 'terminal', action: null };
  if (!staticWord(words[0])) return { ...empty, mode: 'unknown', action: null };
  const action = words[0].text;
  const writers = new Set(['push', 'save', 'create', 'store', 'import', 'drop', 'clear', 'apply', 'pop', 'branch']);
  if (writers.has(action)) {
    return { ...empty, mode: words.length === 2 && help(words[1]) ? 'terminal' : 'write', action };
  }
  if (!['list', 'show'].includes(action)) return { ...empty, mode: 'unknown', action };
  const required = new Set(action === 'list'
    ? ['format', 'max-count', 'skip', 'date', 'since', 'until', 'author', 'committer', 'grep'] : []);
  const optional = new Set(action === 'list' ? ['pretty'] : []);
  const flags = new Set(action === 'list'
    ? ['oneline', 'reverse', 'no-decorate', 'no-abbrev-commit', 'abbrev-commit', 'all']
    : ['include-untracked', 'only-untracked', 'no-include-untracked', 'stat', 'shortstat', 'numstat',
      'name-only', 'name-status', 'summary', 'patch', 'no-patch', 'raw', 'no-ext-diff', 'no-textconv']);
  let positional = 0;
  let afterDD = false;
  for (let i = 1; i < words.length; i++) {
    const w = words[i];
    if (!staticWord(w)) return { ...empty, mode: 'unknown', action };
    const t = w.text;
    if (afterDD) { positional++; continue; }
    if (help(w)) return { ...empty, mode: 'terminal', action };
    if (t === '--') { afterDD = true; continue; }
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const option = t.slice(2, eq < 0 ? undefined : eq);
      if (required.has(option)) {
        if (eq < 0 && !staticWord(words[++i])) return { ...empty, mode: 'unknown', action };
      } else if (!optional.has(option) && (!flags.has(option) || eq >= 0)) return { ...empty, mode: 'unknown', action };
      continue;
    }
    if (t.startsWith('-') && t !== '-') {
      if (action === 'list' && /^-n(?:\d+)?$/.test(t)) {
        if (t === '-n' && (!staticWord(words[++i]) || !/^\d+$/.test(words[i].text))) return { ...empty, mode: 'unknown', action };
      } else if (!(action === 'show' && /^-[puz]+$/.test(t))) return { ...empty, mode: 'unknown', action };
    } else positional++;
  }
  return { ...empty, mode: positional > (action === 'show' ? 1 : 0) ? 'unknown' : 'query', action };
}

const SECRET_PATH_RE = [
  /(^|\/)\.env($|[.*?\s])/i,        // .env / .env.local / .env.production / glob の .env* ...
  /(^|\/)x_tokens\.json$/i,
  /(^|\/)data\/tokens\.json$/i,
  /(^|\/)pkce_state\.json$/i,
  /(^|\/)credentials[^/]*\.json$/i,
  /(^|\/)service-account[^/]*\.json$/i,
  /[^/]*token[^/]*\.json$/i,        // *token*.json
  /(^|\/)pipeline_config\.json$/i,
  /\.(key|pem)$/i,
  /(^|\/)id_(rsa|ed25519)$/i,
  /(^|\/)secrets\.(json|ya?ml)$/i,
  /(^|\/)secrets(\/|$)/i,           // secrets/ 配下（末尾 / を伴わない裸のディレクトリ名も）
];

// .env.example だけは許可（テンプレート）。
const secretTemplateAllowed = (p) => /(^|\/)\.env\.example$/i.test(p);
/** Match the existing secret inventory, retaining the exact .env.example template exception. */
const isSecretPath = (p) => !!p && !secretTemplateAllowed(p) && SECRET_PATH_RE.some((re) => re.test(p));

const ADD_SHORT_FLAGS = new Set('nvip efuNA'.replace(/ /g, ''));
const ADD_LONG = {
  'dry-run': 'f', verbose: 'f', interactive: 'f', patch: 'f', 'auto-advance': 'f', edit: 'f',
  force: 'f', update: 'f', renormalize: 'f', 'intent-to-add': 'f', all: 'f',
  'ignore-removal': 'f', refresh: 'f', 'ignore-errors': 'f', 'ignore-missing': 'f', sparse: 'f',
  'warn-embedded-repo': 'f', 'pathspec-file-nul': 'f', chmod: 'v', 'pathspec-from-file': 'v',
  unified: 'v', 'inter-hunk-context': 'v',
};
const ADD_LONG_NAMES = Object.keys(ADD_LONG).concat(Object.keys(ADD_LONG)
  .filter((name) => !['unified', 'inter-hunk-context'].includes(name)).map((name) => 'no-' + name));

/** Parse add/stage option arity and expose literal paths while rejecting expanded or Git-glob pathspecs. */
function parseAddArgs(words) {
  const result = { terminal: false, unsafePathspec: false, reason: null, pathspecs: [], runtimeBlanket: false, actualBlanket: false };
  const unsafe = (reason) => { result.unsafePathspec = true; if (!result.reason) result.reason = reason; };
  const value = (word) => {
    if (!word) unsafe('option の値が無い');
    else if (word.dynamicMaySplit || word.ansiCUnknown) unsafe('option の値が複数の語や不明な ANSI-C 引用になりうる');
  };
  let afterDD = false;
  for (let k = 0; k < words.length; k++) {
    const original = words[k];
    const word = typeof original.literalValue === 'string'
      ? { ...original, text: original.literalValue, dynamic: false, dynamicMaySplit: false } : original;
    const text = word.text;
    if (!afterDD && text === '--' && !word.dynamic) { afterDD = true; continue; }
    if (!afterDD && !word.dynamic && ['-h', '--help'].includes(text)) {
      if (!result.unsafePathspec) { result.terminal = true; result.helpKind = text === '-h' ? 'stdout' : 'manual'; }
      return result;
    }
    if (!afterDD && text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      const names = ADD_LONG_NAMES.includes(name) ? [name] : ADD_LONG_NAMES.filter((candidate) => candidate.startsWith(name));
      if (names.length !== 1 || name.includes(DYN)) { unsafe('不明・曖昧な add option'); continue; }
      const full = names[0];
      const negative = full.startsWith('no-');
      const base = negative ? full.slice(3) : full;
      if (!word.dynamic && eq < 0 && !negative && base === 'all') result.actualBlanket = true;
      if (typeof original.literalValue === 'string' && !negative && base === 'all') result.runtimeBlanket = true;
      if (!negative && ['pathspec-from-file', 'pathspec-file-nul'].includes(base)) unsafe('file からの pathspec を検査できない');
      if (!negative && ADD_LONG[base] === 'v') {
        value(eq >= 0 ? { ...word, text: text.slice(eq + 1) } : words[++k]);
      } else if (word.dynamic || eq >= 0) unsafe('値を取らない add option の引数を検査できない');
      continue;
    }
    if (!afterDD && text.startsWith('-') && text.length > 1) {
      for (let p = 1; p < text.length; p++) {
        const ch = text[p];
        if (ch === 'h') { if (!result.unsafePathspec) { result.terminal = true; result.helpKind = 'stdout'; } return result; }
        if (ch === 'U') {
          value(p + 1 < text.length ? { ...word, text: text.slice(p + 1) } : words[++k]);
          // A fully dynamic attached suffix can be empty, consuming the following word instead.
          if (word.dynamic && !text.slice(p + 1).replaceAll(DYN, '') && k + 1 < words.length) unsafe('空になりうる attached option の値');
          break;
        }
        if (ch === 'A' && !word.dynamic) result.actualBlanket = true;
        if (ch === 'A' && typeof original.literalValue === 'string') result.runtimeBlanket = true;
        if (word.dynamic || !ADD_SHORT_FLAGS.has(ch)) { unsafe('不明・動的な add option'); break; }
      }
      continue;
    }
    let literalPath = '';
    let wildcard = false;
    for (let p = 0; p < text.length; p++) {
      if (text[p] === '\\' && p + 1 < text.length) literalPath += text[++p];
      else { if ('*?['.includes(text[p])) wildcard = true; literalPath += text[p]; }
    }
    result.pathspecs.push({ ...word, literalPath });
    if (word.dynamic || word.ansiCUnknown || word.tildeExpanded || wildcard || text.startsWith(':')) unsafe('動的・glob・magic の pathspec を検査できない');
  }
  return result;
}

/**
 * Inspect Git grep's file-opening pager selection without executing a search or helper.
 * Values consumed by -e/-f/context options remain DATA; -O's optional value is attached only.
 * Git stops parsing options at the first bare operand. Unknown expansion cannot prove that
 * a later reset/help flag remains an option. A global no-pager disables only the default
 * file-opening pager, not a pager selected by an explicit -Ovalue/--open-files-in-pager=value.
 */
function grepPagerEffect(g) {
  const result = { opensFiles: false, unknown: false, terminal: false };
  if (!g || g.sub !== 'grep') return result;
  if (g.terminal) { result.terminal = true; return result; }
  if (!Array.isArray(g.args)) { result.unknown = true; return result; }
  const required = new Set(['context', 'before-context', 'after-context', 'threads', 'max-depth', 'max-count', 'parent-basename']);
  const flags = [
    'cached', 'index', 'no-index', 'untracked', 'exclude-standard', 'recurse-submodules',
    'invert-match', 'ignore-case', 'word-regexp', 'text', 'textconv', 'recursive',
    'extended-regexp', 'basic-regexp', 'fixed-strings', 'perl-regexp', 'line-number',
    'column', 'full-name', 'files-with-matches', 'name-only', 'files-without-match',
    'null', 'only-matching', 'count', 'break', 'heading', 'show-function',
    'function-context', 'and', 'or', 'not', 'quiet', 'all-match', 'ext-grep', 'debug',
  ];
  const names = [...new Set([...flags, ...required, 'color', 'open-files-in-pager',
    ...[...flags, 'context', 'threads', 'max-count', 'color', 'open-files-in-pager'].map((name) => 'no-' + name)])];
  const shortFlags = new Set('viaIriwE G F PnhHlLzo cpWq'.replace(/ /g, ''));
  let selection = null;
  result.unknown = Boolean(g.incomplete);
  const value = (word) => {
    if (!word || word.ansiCUnknown || word.globExpanded || (word.dynamic && word.dynamicMaySplit !== false)) result.unknown = true;
  };
  for (let k = 0; k < g.args.length; k++) {
    const original = g.args[k];
    const word = typeof original.literalValue === 'string'
      ? { ...original, text: original.literalValue, dynamic: false, dynamicMaySplit: false } : original;
    const text = word.text;
    if (text === '--' && !word.dynamic) break;
    if (!word.dynamic && ['(', ')'].includes(text)) continue; // Git's nondash expression operators
    if (word.ansiCUnknown || word.globExpanded) result.unknown = true;
    if (!word.dynamic && ['--help', '--help-all'].includes(text)) {
      if (!result.unknown) return { opensFiles: false, unknown: false, terminal: true };
      break;
    }
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      const matches = names.includes(name) ? [name] : names.filter((candidate) => candidate.startsWith(name));
      if (!name || matches.length !== 1) { result.unknown = true; continue; }
      const full = matches[0];
      if (word.dynamic && word.dynamicMaySplit !== false) result.unknown = true;
      if (full === 'open-files-in-pager') {
        selection = eq < 0 ? 'default' : 'explicit';
      } else if (full === 'no-open-files-in-pager') {
        if (word.dynamic || eq >= 0) result.unknown = true;
        else selection = null;
      } else if (required.has(full)) {
        value(eq < 0 ? g.args[++k] : word);
      } else if (full === 'color') {
        if (eq >= 0) value(word); // optional attached value; the next word remains an operand
      } else if (word.dynamic || eq >= 0) result.unknown = true;
      continue;
    }
    if (/^-[^-]/.test(text)) {
      if (/^-\d+$/.test(text) && !word.dynamic) continue;
      for (let j = 1; j < text.length; j++) {
        const flag = text[j];
        if (/\d/.test(flag)) continue; // numeric context shorthand can share a short bundle
        if ('efABCm'.includes(flag)) {
          if (j + 1 < text.length) {
            value(word);
            if (word.dynamic && !text.slice(j + 1).replaceAll(DYN, '') && k + 1 < g.args.length) result.unknown = true;
          } else value(g.args[++k]);
          break;
        }
        if (flag === 'O') {
          selection = j + 1 < text.length ? 'explicit' : 'default';
          if (word.dynamic && word.dynamicMaySplit !== false) result.unknown = true;
          break;
        }
        if (word.dynamic || !shortFlags.has(flag)) { result.unknown = true; break; }
      }
      continue;
    }
    if (word.dynamic && (word.dynamicMaySplit !== false || !text || text.startsWith(DYN))) {
      result.unknown = true;
      continue;
    }
    break; // first proven bare pattern/ref closes Git's option parser
  }
  result.opensFiles = selection === 'explicit' || (selection === 'default' && g.pagerDisabled !== true);
  return result;
}

/** Recognize config/branch/remote read actions using their option arity, including terminal help. */
function readOnlyGitMode(g, allowHelp = true, scalarConfigOnly = false) {
  // unquoted expansion や "$@" は追加の action / option を作れる。古い metadata も安全と決めつけない。
  if (g.incomplete || g.args.some((w) => w.dynamic && w.dynamicMaySplit !== false)) return false;
  let args = g.args;
  let reader = false;
  let mayPage = false;
  const values = new Set();
  let flags;
  if (g.sub === 'config') {
    flags = new Set([
      '--get', '--get-all', '--get-regexp', '--get-urlmatch', '--list', '-l',
      '--get-color', '--get-colorbool', '--global', '--system', '--local', '--worktree',
      '--includes', '--no-includes', '--show-origin', '--show-scope', '--name-only',
      '--null', '-z', '--bool', '--int', '--bool-or-int', '--bool-or-str', '--path',
      '--expiry-date', '--no-type', '--fixed-value', '--all', '--regexp',
    ]);
    for (const v of ['--file', '-f', '--blob', '-b', '--type', '-t', '--default', '--value']) values.add(v);
  } else if (g.sub === 'branch') {
    flags = new Set([
      '--list', '-l', '--show-current', '--all', '-a', '--remotes', '-r',
      '--verbose', '-v', '-vv', '--quiet', '-q', '--no-color', '--column', '--no-column',
      '--color', '--abbrev', '--no-abbrev', '--ignore-case', '-i', '--omit-empty',
    ]);
    for (const v of ['--format', '--sort', '--contains', '--no-contains', '--merged', '--no-merged', '--points-at']) values.add(v);
  } else if (g.sub === 'remote') {
    // remote の action は option でなく最初の位置引数。get-url と show は設定を変えない。
    const rest = args.slice();
    while (rest.length && ['-v', '--verbose'].includes(rest[0].text) && !rest[0].dynamic) rest.shift();
    if (!rest.length) return true;
    if (rest[0].dynamic || !['get-url', 'show'].includes(rest[0].text)) return false;
    const action = rest.shift().text;
    args = rest;
    flags = new Set(action === 'get-url' ? ['--push', '--all'] : ['-n']);
    reader = true;
  } else return false;

  let positional = 0;
  let configOperand = false;
  let endOptions = false;
  for (let k = 0; k < args.length; k++) {
    const w = args[k];
    const t = w.text;
    if (g.sub === 'config' && configOperand) { positional++; continue; }
    if (endOptions) { positional++; continue; }
    if (w.dynamic) return false;
    if (t === '--') { endOptions = true; continue; }
    if (!t.startsWith('-')) {
      if (g.sub === 'config' && !reader && positional === 0 && ['get', 'list'].includes(t)) {
        reader = true; if (t === 'list') mayPage = true;
      }
      else { positional++; if (g.sub === 'config') configOperand = true; }
      continue;
    }
    if (['-h', '--help'].includes(t)) return allowHelp;
    const eq = t.indexOf('=');
    const option = eq < 0 ? t : t.slice(0, eq);
    if (values.has(option)) {
      if (eq < 0) {
        const optional = g.sub === 'branch' && ['--contains', '--no-contains', '--merged', '--no-merged'].includes(option);
        const value = args[k + 1];
        // branch の filter は値なしなら HEAD。次の action option を値として飛ばさない。
        if (!optional || (value && !value.text.startsWith('-'))) {
          if (!value || (optional && value.dynamic) || (g.sub === 'branch' && value.text.startsWith('-'))) return false;
          k++;
        }
      }
      if (g.sub === 'branch' && ['--contains', '--no-contains', '--merged', '--no-merged', '--points-at'].includes(option)) reader = true;
      continue;
    }
    if (g.sub === 'branch' && eq >= 0 && ['--abbrev', '--color', '--column'].includes(option)) continue;
    if (!flags.has(t)) return false;
    if (g.sub === 'config' && ['--list', '-l', '--get-all', '--get-regexp', '--get-urlmatch', '--all', '--regexp'].includes(t)) mayPage = true;
    if (g.sub === 'config' && /^(?:--get(?:-all|-regexp|-urlmatch|-color|-colorbool)?|--list|-l)$/.test(t)) reader = true;
    if (g.sub === 'branch' && ['--list', '-l', '--show-current'].includes(t)) reader = true;
  }
  // branch の引数なし / 表示 option だけの形は一覧。裸の名前は branch 作成。
  return (reader || (g.sub === 'branch' && positional === 0)) && !(scalarConfigOnly && g.sub === 'config' && mayPage);
}

/** Select supported notes/tag/stash queries and the file operands of object writers. */
function parseGitObjectRoute(g, parseMessages = parseCommitArgs) {
  if (g.sub === 'stash') return parseStashRoute(g);
  if (!['notes', 'tag'].includes(g.sub)) return null;
  const words = g.args;
  const files = [];
  const kinds = [];
  let unknown = false;
  let terminal = false;
  let afterDD = false;
  let query = false;
  let mutation = false;
  let action = null;
  let positional = 0;
  let queryModifier = false;
  let sourceOverride = false;
  const required = new Set(g.sub === 'notes'
    ? ['ref', 'file', 'message', 'reuse-message', 'reedit-message', 'separator', 'strategy']
    : ['file', 'message', 'local-user', 'format', 'sort', 'points-at']);
  const optional = new Set(g.sub === 'tag'
    ? ['contains', 'no-contains', 'merged', 'no-merged', 'column', 'no-column', 'color', 'no-color'] : []);
  const flags = new Set(g.sub === 'notes'
    ? ['force', 'allow-empty', 'edit', 'stripspace', 'no-stripspace', 'no-separator', 'stdin', 'ignore-missing', 'dry-run', 'verbose', 'quiet', 'commit', 'abort']
    : ['annotate', 'sign', 'no-sign', 'force', 'delete', 'verify', 'list', 'ignore-case', 'omit-empty', 'create-reflog']);
  const noteQueries = new Set(['list', 'show', 'get-ref']);
  const noteWrites = new Set(['add', 'append', 'copy', 'edit', 'merge', 'remove', 'prune']);

  const value = (word, option, attached) => {
    if (['file', 'message', 'reuse-message', 'reedit-message'].includes(option)) kinds.push(option);
    if (option !== 'file') { if (word.dynamic) unknown = true; return; }
    let selected = word;
    if (attached !== undefined) {
      selected = { ...word, text: attached };
      delete selected.literalValue;
      if (!word.dynamic) selected.literalValue = attached;
    }
    files.push(selected);
  };

  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    const t = w.text;
    if (w.dynamic || w.dynamicMaySplit || w.ansiCUnknown || w.braceExpanded || w.globExpanded || w.tildeExpanded) unknown = true;
    if (afterDD) { positional++; continue; }
    if (t === '--') { afterDD = true; continue; }
    if (t === '--help' || t === '-h') { terminal = true; break; }
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const name = t.slice(2, eq < 0 ? undefined : eq);
      const supported = [...required, ...optional, ...flags, 'no-file', 'no-message', 'no-local-user'];
      const matches = supported.filter(x => x.startsWith(name));
      const option = supported.includes(name) ? name : matches.length === 1 ? matches[0] : null;
      if (!option) { unknown = true; continue; }
      if (['list'].includes(option)) query = true;
      if (g.sub === 'notes' && option !== 'ref') queryModifier = true;
      if (g.sub === 'notes' && option === 'ref' && action !== null) unknown = true;
      if (['no-file', 'no-message', 'no-local-user'].includes(option)) sourceOverride = true;
      if (['annotate', 'sign', 'force', 'delete', 'verify', 'create-reflog'].includes(option)) mutation = true;
      if (required.has(option)) {
        if (eq >= 0) value(w, option, t.slice(eq + 1));
        else if (words[i + 1]) value(words[++i], option);
        else unknown = true;
      } else if (optional.has(option)) {
        if (words[i + 1]?.dynamic) unknown = true;
        if (eq < 0 && !['column', 'no-column', 'color', 'no-color'].includes(option) && words[i + 1] && !words[i + 1].text.startsWith('-')) i++;
      } else if (eq >= 0) unknown = true;
      continue;
    }
    if (t.startsWith('-') && t !== '-') {
      for (let j = 1; j < t.length; j++) {
        const ch = t[j];
        if (g.sub === 'notes') queryModifier = true;
        const requiredShort = g.sub === 'notes'
          ? { F: 'file', m: 'message', c: 'reedit-message', C: 'reuse-message', s: 'strategy' }
          : { F: 'file', m: 'message', u: 'local-user' };
        if (requiredShort[ch]) {
          if (j + 1 < t.length) value(w, requiredShort[ch], t.slice(j + 1));
          else if (words[i + 1]) value(words[++i], requiredShort[ch]);
          else unknown = true;
          break;
        }
        if (g.sub === 'tag' && ch === 'l') query = true;
        else if (g.sub === 'tag' && ['a', 's', 'f', 'd', 'v'].includes(ch)) mutation = true;
        else if (g.sub === 'tag' && ch === 'n') {
          if (j + 1 < t.length && !/^\d+$/.test(t.slice(j + 1))) unknown = true;
          break;
        } else if (!(g.sub === 'notes' ? ['f', 'e', 'n', 'v', 'q'] : ['i']).includes(ch)) unknown = true;
      }
      continue;
    }
    if (g.sub === 'notes' && action === null) {
      action = t;
      if (!noteQueries.has(action) && !noteWrites.has(action)) unknown = true;
    } else positional++;
  }

  let mode;
  if (terminal && !unknown) mode = 'terminal';
  else if (unknown) mode = 'unknown';
  else if (g.sub === 'notes') {
    const selected = action || 'list';
    const limit = selected === 'get-ref' ? 0 : 1;
    mode = noteQueries.has(selected) && !kinds.length && !queryModifier && positional <= limit ? 'query' : 'write';
    if (noteQueries.has(selected) && (kinds.length || queryModifier || positional > limit)) mode = 'unknown';
  } else {
    mode = !mutation && !kinds.length && (query || positional === 0) ? 'query' : 'write';
    if (query && (mutation || kinds.length)) mode = 'unknown';
  }
  const synthetic = files.flatMap(word => [{ text: '-F', dynamic: false }, word]);
  const metadata = synthetic.length ? parseMessages(synthetic) : { messageFiles: [], messageFileUnknown: false, messageFileSelectionUnknown: false };
  return { mode, action, messageFiles: metadata.messageFiles,
    messageFileUnknown: unknown || metadata.messageFileUnknown || !Array.isArray(metadata.messageFiles),
    messageFileSelectionUnknown: unknown || metadata.messageFileSelectionUnknown || kinds.length > 1 || files.length > 0 && sourceOverride,
    reason: mode === 'unknown' ? 'notes/tag の action・option 境界・source 選択を確認できない' : null };
}


/** Refuse known secret message files, or unsupported source/object/ref routes. */
function gitObjectInputDecision(g) {
  const objectRoute = parseGitObjectRoute(g);
  const parsed = objectRoute || (g.sub === 'commit' ? parseCommitArgs(g.args)
    : g.sub === 'merge' ? parseMergeMessageArgs(g.args) : null);
  if (!parsed || parsed.terminal || ['query', 'terminal'].includes(parsed.mode)) return null;
  const files = parsed.messageFiles;
  if (!objectRoute && Array.isArray(files) && files.length === 0 && !parsed.messageFileUnknown) return null;
  if (objectRoute && g.sub === 'stash') return { category: 'UNKNOWN', reason: 'git stash の snapshot・更新・未対応 action は staged 検査の対象外で、入力 tree/object/ref・内容・実行条件を確認できません。対応する static list/show/help 以外の操作が必要なら owner に対象・操作・cwd/env/config/source と不明点を確認してください。同目的の writer 代替は未対応で、個別操作の了承は hook 無効化の了承ではありません。' };
  if (!Array.isArray(files) || parsed.mode === 'unknown' || parsed.messageFileUnknown || parsed.messageFileSelectionUnknown ||
      g.incomplete || g.cdLikeBefore || g.unknownContextBefore || g.dynamicOpt) {
    return { category: 'UNKNOWN', reason: 'Git message の file/stdin/source 選択や argv・対象条件を確認できません。対応済みの非秘密 inline message で同目的を保てなければ、owner に対象・操作・cwd/env/config/source と不明点を確認してください。' };
  }
  const secret = files.filter(source => !source.unknown && typeof source.word?.text === 'string' && isSecretPath(source.word.text));
  if (secret.length) return { category: 'FORBIDDEN', reason: 'Git message の対応済み file operand が禁止された secret filename に当たります: ' + secret.map(source => source.word.text).join(', ') + '。内容や実行成立を確認したものではありません。非秘密の同目的 message に変更し、必要なら owner に確認してください。' };
  if (objectRoute) return { category: 'UNKNOWN', reason: 'git notes/tag/stash の object/ref 更新・未対応形式は staged 検査の対象外で、source/内容・実行条件を確認できません。通常の読取/list/show/help は対応形式を使い、更新自体が必要なら owner に対象・操作・cwd/env/config/source を確認してください。個別操作の了承は hook 無効化の了承ではありません。' };
  return null;
}

module.exports = {
  DYN,
  deny,
  readInput,
  parseShell,
  inspect,
  inspectMediatedSource,
  problemMessage,
  aliasProblem,
  resolveDir,
  parseCommitArgs,
  parseMergeMessageArgs,
  parseGitObjectRoute,
  gitObjectInputDecision,
  messageFileSource,
  grepPagerEffect,
  parseAddArgs,
  isSecretPath,
  readOnlyGitMode,
  READ_ONLY_SUBS,
};
