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
function parseSeq(src, start, out, depth, stopAtParen, scope, parentEffects = [], functionBoundary = null) {
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
  let redirectionOrder = 0;
  let redirs = [];
  let piped = false;
  const heredocs = [];
  let definitionName = null;
  let functionBody = null;
  let functionClosed = false;

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
    // coproc is reserved syntax only in the original, unquoted command position.
    // Its asynchronous body and optional name are outside the supported source/scope proof.
    if (!redirNext && !scope.arrayInitializer && !cur.quoted && !cur.dynamic &&
        cur.text === 'coproc' && atCmdPos(words)) {
      (out.unsupportedSources ||= []).push({ kind: 'coproc', start: cur.start });
    }
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
        if (functionBoundary === cur.text && compoundEffects.length === 0) functionClosed = true;
      }
    }
    if (redirNext) {
      redirs.push({ ...redirNext, word: cur });
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
      const keywordDefinition = functionKeywordHeader(words);
      const c = { words, redirs, piped, heredocBodies: [], scope,
        definitionName: definitionName || (keywordDefinition ? words[words.length - 1].text : null),
        functionBody, functionBodyUnknown: !!keywordDefinition && !functionBody,
        effects: currentEffects(), arrayInitializer: scope.arrayInitializer };
      out.cmds.push(c);
      for (const h of heredocs) if (!h.cmd) h.cmd = c;
    }
    words = [];
    redirs = [];
    redirectionOrder = 0;
    piped = false;
    definitionName = null;
    functionBody = null;
    closedGroup = null;
  };
  // A function stores its body and redirection expansions; neither runs at definition time.
  // Keeping a separate parse result also prevents an unused body's errors/effects leaking out.
  const retainFunction = (header, bodyStart, boundary) => {
    endWord();
    definitionName = header[header.length - 1].text;
    const bodyScope = { parent: null, functionBody: true };
    const body = { cmds: [], errors: [], unsupportedSources: [], scope: bodyScope,
      async: false, evaluationUnknown: false };
    const close = parseSeq(src, bodyStart, body, depth + 1, boundary === ')', bodyScope, [], boundary);
    functionBody = { ...body, subshell: boundary === ')', unknown: close >= n || body.errors.length > 0 };
    i = boundary === '}' || boundary === ')' ? Math.min(close + 1, n) : close;
  };
  const functionKeywordHeader = (header) => header.length >= 2 &&
    atCmdPos(header.slice(0, -2)) && header.at(-2).text === 'function' &&
    !header.at(-2).quoted && !header.at(-2).dynamic &&
    !header.at(-1).quoted && !header.at(-1).dynamic && /^[A-Za-z_][A-Za-z0-9_]*$/.test(header.at(-1).text);
  const functionBodyStart = (k) => {
    for (;;) {
      k = skipLC(src, k);
      if (/[ \t\n]/.test(src[k] || '')) { k++; continue; }
      if (src[k] === '#') { const e = src.indexOf('\n', k); k = e < 0 ? n : e + 1; continue; }
      return k;
    }
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
    if (!cur && !functionBody && functionKeywordHeader(words)) {
      const compound = /^(if|while|until|for|select|case)(?=[ \t\n;(])/.exec(src.slice(i));
      if (compound) {
        const close = { if: 'fi', while: 'done', until: 'done', for: 'done', select: 'done', case: 'esac' }[compound[1]];
        retainFunction(words, i, close);
        continue;
      }
    }
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
          const r = scanExpansion(src, i, functionBody || out, depth, functionBody ? functionBody.scope : scope, currentEffects(), true);
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
      const r = scanExpansion(src, i, functionBody || out, depth, functionBody ? functionBody.scope : scope, currentEffects());
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
      endWord();
      if (!functionBody && functionKeywordHeader(words)) {
        const bodyStart = functionBodyStart(i);
        if (src[bodyStart] === '{' || src[bodyStart] === '(') {
          retainFunction(words, bodyStart + 1, src[bodyStart] === '{' ? '}' : ')');
          continue;
        }
      }
      endCmd();
      if (functionClosed) return i;
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
          const stored = h.cmd && h.cmd.functionBody;
          scanSubsts(body, stored || out, depth + 1, stored ? stored.scope : scope,
            h.cmd ? h.cmd.effects : currentEffects(), evaluations);
          if (h.cmd) h.cmd.evaluations = (h.cmd.evaluations || []).concat(evaluations);
        }
        if (h.cmd) h.cmd.heredocBodies.push({ body, quoted: h.quoted,
          fd: h.fd, fdKnown: h.fdKnown, redirectionOrder: h.redirectionOrder });
      }
      continue;
    }
    // CR（\r）は bash / zsh と同じく語の文字として扱う（区切りにしない・v3）。
    if (c === ' ' || c === '\t') {
      endWord();
      if (functionClosed) { endCmd(); return i; }
      i++;
      continue;
    }
    if (c === ';' || c === '|' || (c === '&' && src[i + 1] !== '>')) {
      if (c === '&' && src[i + 1] !== '&') out.async = true;
      const isPipe = c === '|' && src[i + 1] !== '|';
      endWord(); // fi/done/esac closes its outer segment before a trailing pipe.
      if (functionClosed) { endCmd(); return i; }
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
    if (c === '{' && !cur && !functionBody && functionKeywordHeader(words) && /[ \t\n;]/.test(src[i + 1] || '')) {
      retainFunction(words, i + 1, '}');
      continue;
    }
    if (c === '}' && !cur && !braceEffects.length && functionBoundary === '}' && /[ \t\n;&|)]|^$/.test(src[i + 1] || '')) {
      endCmd();
      return i;
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
          (atCmdPos(header.slice(0, -1)) || functionKeywordHeader(header))) {
        const signature = /^\([ \t\n]*\)/.exec(src.slice(i))[0];
        const bodyStart = functionBodyStart(i + signature.length);
        if (src[bodyStart] === '{' || src[bodyStart] === '(') {
          retainFunction(header, bodyStart + 1, src[bodyStart] === '{' ? '}' : ')');
          continue;
        }
        const compound = /^(if|while|until|for|select|case)(?=[ \t\n;(])/.exec(src.slice(bodyStart));
        if (compound) {
          const close = { if: 'fi', while: 'done', until: 'done', for: 'done', select: 'done', case: 'esac' }[compound[1]];
          retainFunction(header, bodyStart, close);
          continue;
        }
        // The selected function will fail closed if its compound source boundary is unsupported.
        definitionName = fn.text;
        endWord();
        i += signature.length;
        continue;
      }
      if (!functionBody && functionKeywordHeader(header)) {
        retainFunction(header, i + 1, ')');
        continue;
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
        const close = parseSeq(src, i + 2, functionBody || out, depth + 1, true,
          { parent: functionBody ? functionBody.scope : scope }, currentEffects());
        if (close >= n) { out.errors.push('閉じていない <( … )'); return n; }
        cur.dynamic = true;
        cur.braceSource += DYN;
        cur.text += DYN;
        i = close + 1;
        continue;
      }
      // fd の番号（2> など）は語にしない。
      let fd = null;
      let fdKnown = true;
      if (cur && !cur.quoted && !cur.dynamic && /^\d+$/.test(cur.text)) { fd = cur.text; cur = null; }
      else if (cur && !cur.quoted && !cur.dynamic && /^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(cur.text)) {
        fdKnown = false; cur = null; // Bash allocates a descriptor; its runtime value is not fd 0 proof.
      } else endWord();
      const descriptor = { fd, fdKnown, redirectionOrder: redirectionOrder++ };
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
          // An unquoted backslash + LF disappears before delimiter tokenization.
          // It does not quote the delimiter, so its body still expands unless another byte did.
          if (d === '\\' && src[i + 1] === '\n') { i += 2; continue; }
          if (d === '\\') { delim += src[i + 1] || ''; quoted = true; i += 2; continue; }
          delim += d;
          i++;
        }
        if (!delim) { out.errors.push('ヒアドキュメントの区切りが無い'); return n; }
        heredocs.push({ delim, strip, quoted, cmd: null, ...descriptor });
        // サブシェルと決められない括弧の中のヒアドキュメント（v3.5.2）。
        if (parenKinds.some((k) => k !== 'sub')) out.errors.push('サブシェルと決められない括弧の中のヒアドキュメント');
        continue;
      }
      // ほかのリダイレクト（> >> < <> >| >& <& &> &>> <<<）: 次の語は対象。
      let j = i;
      while (j < n && '<>&|'.includes(src[j]) && j - i < 3) j++;
      redirNext = { op: src.slice(i, j), ...descriptor };
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
  const out = { cmds: [], errors: [], unsupportedSources: [], scope: { parent: null }, async: false, evaluationUnknown: false };
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

/** Retain only names for Bash's positive imported-function environment protocols. */
function functionEnvironmentAssignment(word, name, value) {
  const modern = /^BASH_FUNC_([A-Za-z_][A-Za-z0-9_]*)%%$/.exec(name);
  const protocol = /^BASH_FUNC_.*%%$/.test(name);
  const header = /^\(\)[ \t\n]*\{/.test(value);
  if (!protocol && !header) return null;
  const callee = modern ? modern[1] : !protocol && /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? name : null;
  return { environment: name, callee: header ? callee : null,
    unknown: !header || !callee || !!word.dynamic || !!word.dynamicMaySplit };
}

/** GNU timeout options precede duration; value-taking options consume argv before child lookup. */
function timeoutArgs(rest, info) {
  info.launcherArgs.push(...rest);
  const values = new Set(['signal', 'kill-after']);
  const flags = new Set(['foreground', 'preserve-status', 'verbose']);
  const duration = word => word && !word.dynamic && !word.dynamicMaySplit &&
    /^\+?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?[smhd]?$/.test(word.text);
  let k = 0;
  let terminal = false;
  while (k < rest.length && rest[k].text.startsWith('-')) {
    const word = rest[k];
    if (word.dynamic || word.dynamicMaySplit) info.launcherUnknown = true;
    if (word.text === '--') { k++; break; }
    if (word.text.startsWith('--')) {
      const eq = word.text.indexOf('=');
      const option = word.text.slice(2, eq < 0 ? undefined : eq);
      if (['help', 'version'].includes(option) && eq < 0) {
        if (!info.launcherUnknown) return -1;
        terminal = true;
      }
      else if (values.has(option)) {
        const value = eq < 0 ? rest[++k] : { ...word, text: word.text.slice(eq + 1) };
        if (!value || value.dynamic || value.dynamicMaySplit || !value.text ||
            (option === 'kill-after' ? !duration(value) : value.text.startsWith('-'))) info.launcherUnknown = true;
      } else if (!flags.has(option) || eq >= 0) info.launcherUnknown = true;
    } else {
      if (word.text === '-') info.launcherUnknown = true;
      for (let p = 1; p < word.text.length; p++) {
        const ch = word.text[p];
        if ('fpv'.includes(ch)) continue;
        if (!'sk'.includes(ch)) { info.launcherUnknown = true; break; }
        const value = p + 1 < word.text.length ? { ...word, text: word.text.slice(p + 1) } : rest[++k];
        if (!value || value.dynamic || value.dynamicMaySplit || !value.text ||
            (ch === 'k' ? !duration(value) : value.text.startsWith('-'))) info.launcherUnknown = true;
        break;
      }
    }
    k++;
  }
  if (terminal && !info.launcherUnknown) return -1;
  if (!duration(rest[k]) || !rest[k + 1]) info.launcherUnknown = true;
  return info.launcherUnknown ? rest.length : k + 1;
}

/** GNU nice/stdbuf value options consume argv before resolving the actual child. */
function coreutilsValueLauncher(rest, info, name) {
  const options = name === 'nice' ? { adjustment: 'n' } : { input: 'i', output: 'o', error: 'e' };
  const shorts = Object.values(options);
  const validValue = (ch, word) => word && !word.dynamic && !word.dynamicMaySplit &&
    (name === 'nice' ? /^[+-]?\d+$/.test(word.text) :
      (word.text === 'L' ? ch !== 'i' : /^\d+(?:[KMGTPEZYRQ](?:i?B)?)?$/.test(word.text)));
  let k = 0;
  info.launcherArgs.push(...rest);
  while (k < rest.length && rest[k].text.startsWith('-')) {
    const word = rest[k];
    if (word.dynamic || word.dynamicMaySplit) info.launcherUnknown = true;
    if (word.text === '--') { k++; break; }
    if (name === 'nice' && /^--?\d+$/.test(word.text)) { k++; continue; }
    if (word.text.startsWith('--')) {
      const eq = word.text.indexOf('=');
      const option = word.text.slice(2, eq < 0 ? undefined : eq);
      if (['help', 'version'].includes(option) && eq < 0 && !info.launcherUnknown) return -1;
      const ch = options[option];
      if (!ch) info.launcherUnknown = true;
      else {
        const value = eq < 0 ? rest[++k] : { ...word, text: word.text.slice(eq + 1) };
        if (!validValue(ch, value)) info.launcherUnknown = true;
      }
    } else {
      const ch = word.text[1];
      if (!shorts.includes(ch)) info.launcherUnknown = true;
      else {
        const value = word.text.length > 2 ? { ...word, text: word.text.slice(2) } : rest[++k];
        if (!validValue(ch, value)) info.launcherUnknown = true;
      }
    }
    k++;
  }
  if (info.launcherUnknown) return rest.length;
  return k >= rest.length ? -1 : k; // nice query / invalid stdbuf usage has no child.
}

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

/** Keep required wrapper operands as DATA before resolving the executable. */
function wrapperValueKnown(word) {
  return !!word && !word.dynamicMaySplit && !word.globExpanded && !word.braceExpanded && !word.tildeExpanded;
}

/** sudo 1.9.17p2: exact child boundary, optional preserve-env and dual -h. */
function sudoArgs(rest, info) {
  const longs = {
    background: ['b', 'none'], 'preserve-env': ['E', 'optional'], edit: ['e', 'none'],
    'set-home': ['H', 'none'], login: ['i', 'none'], 'remove-timestamp': ['K', 'none'],
    list: ['l', 'none'], 'preserve-groups': ['P', 'none'], shell: ['s', 'none'],
    'other-user': ['U', 'required'], validate: ['v', 'none'], askpass: ['A', 'none'],
    'auth-type': ['a', 'required'], bell: ['B', 'none'], 'close-from': ['C', 'required'],
    'login-class': ['c', 'required'], chdir: ['D', 'required'], group: ['g', 'required'],
    help: ['?', 'none'], host: ['h', 'required'], 'reset-timestamp': ['k', 'none'],
    'no-update': ['N', 'none'], 'non-interactive': ['n', 'none'], prompt: ['p', 'required'],
    chroot: ['R', 'required'], role: ['r', 'required'], stdin: ['S', 'none'],
    'command-timeout': ['T', 'required'], type: ['t', 'required'], user: ['u', 'required'],
    version: ['V', 'none'],
  };
  info.launcherArgs.push(...rest);
  info.launcherChildNoAssignments = true;
  let k = 0, nonChild = false;
  const apply = (ch, value, arity) => {
    if (arity === 'required' && !wrapperValueKnown(value)) info.launcherUnknown = true;
    // These sudo parser cases reject an empty operand; prompt explicitly permits it.
    if (arity === 'required' && value && !value.dynamic && value.text === '' &&
        'aCcDghRrtUu'.includes(ch)) info.launcherUnknown = true;
    if ('AaeisDRhcr t'.replaceAll(' ', '').includes(ch)) info.launcherUnknown = true;
    if ('DR'.includes(ch)) info.cdLike = true;
    if ('Klv'.includes(ch)) nonChild = true;
    if ('?V'.includes(ch)) nonChild = true;
  };
  while (k < rest.length) {
    const w = rest[k], t = w.text;
    if (t === '--' && !w.dynamic) { k++; break; }
    // Unlike shell assignments, sudo accepts a quoted supported NAME=value carrier.
    if (!t.startsWith('-') && !t.startsWith('/') && !t.startsWith('=') && t.includes('=')) {
      // sudo's native carrier grammar is broader than our supported metadata names.
      if (!/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) { info.launcherUnknown = true; k++; continue; }
      const name = t.split('=')[0];
      info.assigns.push(name); info.assignRaws.push(w.raw); info.envOps.push({ set: name });
      if (w.dynamicMaySplit) info.launcherUnknown = true;
      k++; continue;
    }
    if (!t.startsWith('-') || t === '-') break;
    if (w.dynamicMaySplit || w.globExpanded || w.braceExpanded || w.tildeExpanded) info.launcherUnknown = true;
    if (t.startsWith('--')) {
      const eq = t.indexOf('='), name = t.slice(2, eq < 0 ? undefined : eq);
      const matches = Object.keys(longs).filter(n => n === name || n.startsWith(name));
      const exact = Object.hasOwn(longs, name);
      if (!exact && matches.length !== 1) info.launcherUnknown = true;
      else {
        const [ch, arity] = longs[exact ? name : matches[0]];
        let value;
        if (arity === 'required') value = eq < 0 ? rest[++k] : { ...w, text: t.slice(eq + 1) };
        else if (arity === 'optional' && eq >= 0) value = { ...w, text: t.slice(eq + 1) };
        else if (eq >= 0) info.launcherUnknown = true;
        if ('?V'.includes(ch) && k === 0 && !w.dynamic && eq < 0) return -1;
        apply(ch, value, arity);
      }
    } else {
      for (let p = 1; p < t.length; p++) {
        const ch = t[p];
        if (!'AaBbCcDEegHhiKklNnPpRrSsTtUuVv'.includes(ch)) { info.launcherUnknown = true; break; }
        let value, arity = 'none';
        if ('aCcDgpRrTtUu'.includes(ch)) {
          arity = 'required'; value = p + 1 < t.length ? { ...w, text: t.slice(p + 1) } : rest[++k];
        } else if (ch === 'h') {
          if (p + 1 < t.length) { arity = 'required'; value = { ...w, text: t.slice(p + 1) }; }
          else if (rest[k + 1] && !rest[k + 1].text.startsWith('-') && !rest[k + 1].text.includes('=')) {
            arity = 'required'; value = rest[++k];
          } else {
            nonChild = true;
            if (rest.length === 1 && !w.dynamic && t === '-h') return -1;
            continue;
          }
        }
        if (ch === 'V' && k === 0 && !w.dynamic && t === '-V') return -1;
        apply(ch, value, arity);
        if (arity === 'required') break;
      }
    }
    k++;
  }
  if (nonChild && !info.launcherUnknown) return -1;
  if (k >= rest.length) info.launcherUnknown = true; // implied target shell is uninspected
  return k;
}

/** util-linux 2.41.2: plain known child is inspectable; selected namespace context is not. */
function unshareArgs(rest, info) {
  const optional = new Set(['mount', 'uts', 'ipc', 'net', 'pid', 'user', 'cgroup', 'time',
    'kill-child', 'mount-proc', 'mount-binfmt']);
  const required = new Set(['map-user', 'map-users', 'map-group', 'map-groups', 'propagation',
    'setgroups', 'setuid', 'setgid', 'root', 'wd', 'monotonic', 'boottime', 'load-interp']);
  const flags = new Set(['help', 'version', 'fork', 'map-root-user', 'map-current-user',
    'map-auto', 'map-subids', 'keep-caps']);
  const names = [...optional, ...required, ...flags];
  info.launcherArgs.push(...rest);
  info.launcherChildNoAssignments = true;
  let k = 0;
  while (k < rest.length && rest[k].text.startsWith('-') && rest[k].text !== '-') {
    const w = rest[k], t = w.text;
    if (t === '--' && !w.dynamic) { k++; break; }
    if (w.dynamicMaySplit || w.globExpanded || w.braceExpanded || w.tildeExpanded) info.launcherUnknown = true;
    if (t.startsWith('--')) {
      const eq = t.indexOf('='), name = t.slice(2, eq < 0 ? undefined : eq);
      const matches = names.includes(name) ? [name] : names.filter(n => n.startsWith(name));
      if (matches.length !== 1) info.launcherUnknown = true;
      else {
        const option = matches[0];
        if (['help', 'version'].includes(option) && k === 0 && !w.dynamic && eq < 0) return -1;
        if (required.has(option)) {
          const value = eq < 0 ? rest[++k] : { ...w, text: t.slice(eq + 1) };
          if (!wrapperValueKnown(value)) info.launcherUnknown = true;
        } else if (!optional.has(option) && eq >= 0) info.launcherUnknown = true;
        if (option !== 'fork') info.launcherUnknown = true;
      }
    } else {
      for (let p = 1; p < t.length; p++) {
        const ch = t[p];
        if (['-h', '-V'].includes(t) && k === 0 && !w.dynamic) return -1;
        if (!'fhVmuinpCTUrR:w:S:G:cl:'.replaceAll(':', '').includes(ch)) { info.launcherUnknown = true; break; }
        if ('RwSGl'.includes(ch)) {
          const value = p + 1 < t.length ? { ...w, text: t.slice(p + 1) } : rest[++k];
          if (!wrapperValueKnown(value)) info.launcherUnknown = true;
          info.launcherUnknown = true; break;
        }
        if (ch !== 'f') info.launcherUnknown = true;
      }
    }
    k++;
  }
  if (k >= rest.length) info.launcherUnknown = true; // exec_shell(), not a terminal no-child query
  return k;
}

const WRAPPERS = {
  chroot: (rest, info) => {
    info.launcherArgs.push(...rest);
    if (rest[0] && !rest[0].dynamic && ['--help', '--version'].includes(rest[0].text)) return -1;
    info.launcherUnknown = true;
    return 0;
  },
  setsid: (rest, info) => launcherArgs(rest, info, 'setsid'),
  taskset: (rest, info) => launcherArgs(rest, info, 'taskset'),
  ionice: (rest, info) => launcherArgs(rest, info, 'ionice'),
  command: (rest) => {
    let k = 0;
    while (k < rest.length && /^-[pvV]+$/.test(rest[k].text)) {
      if (/[vV]/.test(rest[k].text)) return -1; // command -v は実行しない
      k++;
    }
    if (rest[k]?.text === '--' && !rest[k].dynamic) k++;
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
  nice: (rest, info) => coreutilsValueLauncher(rest, info, 'nice'),
  stdbuf: (rest, info) => coreutilsValueLauncher(rest, info, 'stdbuf'),
  timeout: timeoutArgs,
  caffeinate: (rest) => {
    let k = 0;
    while (k < rest.length && rest[k].text.startsWith('-')) {
      if (/^-[tw]$/.test(rest[k].text)) k++;
      k++;
    }
    return k;
  },
  sudo: sudoArgs,
  unshare: unshareArgs,
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
    while (k < rest.length && /^(?:[A-Za-z_][A-Za-z0-9_]*|BASH_FUNC_[^=]*%%)=/.test(rest[k].text)) {
      if (rest[k].dynamicMaySplit) info.envUnknown = true;
      const name = rest[k].text.split('=')[0];
      info.assigns.push(name);
      info.assignRaws.push(rest[k].raw);
      info.envOps.push({ set: name });
      const imported = functionEnvironmentAssignment(rest[k], name, rest[k].text.slice(name.length + 1));
      if (imported) info.envOps.push({ functionEnvironment: imported });
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
function resolveCommand(words, localFunctions = null) {
  const info = {
    name: null, nameWord: null, args: [], assigns: [], assignRaws: [],
    cdLike: false, incomplete: false, nonExec: false, dynamicName: false, executableExpansionUnknown: false, splitString: false,
    envOps: [], wrapped: false, wrapperNames: [], persistsEnv: false, envUnknown: false, splitWords: [],
    launcherUnknown: false, launcherArgs: [],
  };
  let k = 0;
  for (;;) {
    while (k < words.length && !words[k].quoted && !words[k].dynamic && RESERVED.has(words[k].text)) k++;
    while (k < words.length && !info.launcherChildNoAssignments && isAssignWord(words[k])) {
      info.assigns.push(assignName(words[k]));
      info.assignRaws.push(words[k].raw);
      info.envOps.push({ set: assignName(words[k]) });
      const assignment = scalarAssignment(words[k]);
      const imported = assignment && functionEnvironmentAssignment(words[k], assignment.name, assignment.value);
      if (imported) info.envOps.push({ functionEnvironment: imported });
      k++;
    }
    if (k >= words.length) return info;
    const w = words[k];
    // Unquoted [[ is Bash syntax only at an original command position, not a pathname glob.
    const conditionalKeyword = !info.wrapped && !w.quoted && !w.dynamic && w.text === '[[';
    const executableGlob = w.globExpanded && !conditionalKeyword;
    if (w.dynamic || executableGlob || w.braceExpanded || w.tildeExpanded) {
      info.dynamicName = true;
      info.executableExpansionUnknown = !!(executableGlob || w.braceExpanded || w.tildeExpanded);
      info.nameWord = w;
      info.args = words.slice(k + 1);
      return info;
    }
    const base = path.posix.basename(w.text);
    const rest = words.slice(k + 1);
    // Shell function lookup precedes builtin/external wrapper handling for a direct literal call.
    if (!info.wrapped && localFunctions && localFunctions.has(w.text)) {
      info.name = w.text; info.nameWord = w; info.args = rest;
      return info;
    }
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

// Fixed upstream Git 2.54 help-a inventory plus the documented protocol servers.
// Registration identifies an operation; it does not approve its argv or helper body.
const OFFICIAL_GIT_OPERATIONS = new Set('add am archive backfill bisect branch bundle checkout cherry-pick citool clean clone commit describe diff fetch format-patch gc grep gui history init log maintenance merge mv notes pull push range-diff rebase reset restore revert rm scalar shortlog show sparse-checkout stash status submodule switch tag worktree config fast-export fast-import filter-branch mergetool pack-refs prune reflog refs remote repack replace annotate blame bugreport count-objects diagnose difftool fsck gitweb help instaweb merge-tree rerere show-branch verify-commit verify-tag version whatchanged archimport cvsexportcommit cvsimport cvsserver imap-send p4 quiltimport request-pull send-email svn apply checkout-index commit-graph commit-tree hash-object index-pack merge-file merge-index mktag mktree multi-pack-index pack-objects prune-packed read-tree replay symbolic-ref unpack-objects update-index update-ref write-tree cat-file cherry diff-files diff-index diff-pairs diff-tree for-each-ref for-each-repo get-tar-commit-id last-modified ls-files ls-remote ls-tree merge-base name-rev pack-redundant repo rev-list rev-parse show-index show-ref unpack-file var verify-pack daemon fetch-pack http-backend send-pack update-server-info check-attr check-ignore check-mailmap check-ref-format column credential credential-cache credential-store fmt-merge-msg hook interpret-trailers mailinfo mailsplit merge-one-file patch-id sh-i18n sh-setup stripspace upload-pack upload-archive receive-pack'.split(' '));
// Documented protocol helpers are omitted by the fixed help-a catalog. Known
// builtins include compatibility names which must not become unknown aliases.
const REGISTERED_GIT_OPERATIONS = new Set([...OFFICIAL_GIT_OPERATIONS, ...BUILTIN_SUBS, 'gitk', 'http-push', 'http-fetch']);
// A direct git-* name identifies the namespace, not an inspected helper body.
const directGitOperation = name => name === 'gitk' ? 'gitk' : /^git-.+/.test(name) ? name.slice(4) : null;

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'fish']);
const CD_LIKE = new Set(['cd', 'pushd', 'popd']);
const EXPORT_LIKE = new Set(['export', 'declare', 'typeset', 'local', 'readonly']);
const CONFIG_ROOT_ENV = new Set(['HOME', 'XDG_CONFIG_HOME']);
// Track explicit external-helper selectors separately from Git target/config variables.
const HELPER_SOURCE_ENV = new Set(['VISUAL', 'EDITOR', 'RSYNC_RSH', 'BASH_ENV', 'GIT_ASKPASS', 'SSH_ASKPASS', 'WGET_ASKPASS', 'ENV', 'GIT_EXTERNAL_DIFF', 'SHELLOPTS', 'POSIXLY_CORRECT', 'GIT_PAGER', 'PAGER', 'GH_EDITOR', 'GH_BROWSER', 'GH_PAGER', 'GH_CONFIG_DIR', 'BROWSER']);
/** Include Git's configuration-root variables in per-invocation environment effects. */
const affectsGitEnvironment = (name) => /^GIT_/.test(name) || CONFIG_ROOT_ENV.has(name);
const GIT_IDENTITY_ENV = new Set(['GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_AUTHOR_DATE',
  'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL', 'GIT_COMMITTER_DATE', 'EMAIL']);
const GIT_PAGER_ENV = new Set(['GIT_PAGER', 'PAGER']);
const GH_METADATA_ENV = new Set(['GH_REPO', 'GH_HOST']);
const GH_HELPER_ENV = new Set(['GH_EDITOR', 'GH_BROWSER', 'GH_PAGER', 'GH_CONFIG_DIR', 'BROWSER', 'HOME', 'XDG_CONFIG_HOME', 'AppData']);
const SHELL_STARTUP_ENV = new Set(['BASH_ENV', 'ENV']);
const GIT_CONFIG_SOURCE_ENV = new Set(['GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG']);
const GIT_HTTP_METADATA_ENV = new Set(['GIT_HTTP_USER_AGENT']);
const GIT_TRANSPORT_SOURCE_ENV = new Set(['GIT_PROXY_COMMAND', 'GIT_SSH_COMMAND', 'GIT_SSH']);
const TRACKED_VALUE_ENV = new Set([...GIT_TRANSPORT_SOURCE_ENV, ...GIT_HTTP_METADATA_ENV, ...GIT_IDENTITY_ENV, ...GIT_PAGER_ENV, ...GH_METADATA_ENV, ...GH_HELPER_ENV, ...SHELL_STARTUP_ENV, ...GIT_CONFIG_SOURCE_ENV, 'PS4']);
const trackedValueEnvironment = name => TRACKED_VALUE_ENV.has(name) || /^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(name);
const gitConfigurationEnvironment = name => GIT_CONFIG_SOURCE_ENV.has(name) || /^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(name);
/** A stored shell value enters a child environment only with a selected export attribute. */
function identityEnvironmentSources(state) {
  return new Map([...state.identitySources].flatMap(([name, word]) => {
    const exported = state.identityExports.get(name);
    return exported === false ? [] : [[name, exported === true ? word : null]];
  }));
}
/** A child receives the invocation's selected environment, not unexported shell values. */
function childIdentityState(sources) {
  const childSources = new Map([...sources].map(([name, word]) => [name,
    word && (!word.dynamic || typeof word.literalValue === 'string') ? word : null]));
  const childExports = new Map([...sources.keys()].map(name => [name, true]));
  if (!childSources.has('PS4')) {
    childSources.set('PS4', { text: '+ ', dynamic: false }); childExports.set('PS4', false);
  }
  return {
    identitySources: childSources, identityExports: childExports, promptRefNames: new Set(),
  };
}
/** Shell declaration options stop at the first operand; later strings are variable names or values. */
function declarationOptions(args) {
  const options = [];
  for (const word of args) {
    if (word.dynamic || word.text === '--' || !/^[-+][A-Za-z]+$/.test(word.text)) break;
    options.push(word.text);
  }
  return options;
}
/** Separate positive function-export attributes from variable exports, listing and removal. */
function functionExportSelection(name, args) {
  if (!['export', 'declare', 'typeset'].includes(name)) return null;
  const opts = declarationOptions(args);
  const has = (sign, flag) => opts.some(option => option[0] === sign && option.slice(1).includes(flag));
  const functionMode = has('-', 'f') || has('-', 'F');
  const removal = has('-', 'n') || has('+', 'x') || has('+', 'f') || has('+', 'F');
  const query = name !== 'export' && has('-', 'p');
  let k = opts.length;
  if (args[k]?.text === '--' && !args[k].dynamic) k++;
  const operands = args.slice(k);
  const uncertainOption = !functionMode && !query && !removal && args[k]?.dynamic &&
    !/^[A-Za-z_][A-Za-z0-9_]*=/.test(args[k].text);
  if (uncertainOption) return { names: [], unknown: true };
  if (!functionMode || removal || query || !operands.length || (name !== 'export' && !has('-', 'x'))) return null;
  const names = [];
  let unknown = false;
  for (const word of operands) {
    if (word.dynamic || word.dynamicMaySplit || word.globExpanded || word.braceExpanded || word.tildeExpanded ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/.test(word.text)) unknown = true;
    else names.push(word.text);
  }
  return { names, unknown };
}
// POSIX モードでは prefix の代入が、通常のコマンドと違い special builtin の後にも残る。
const SPECIAL_BUILTINS = new Set([':', '.', 'break', 'continue', 'eval', 'exit', 'export', 'readonly', 'return', 'set', 'shift', 'times', 'trap', 'unset']);
const COMMAND_SEARCH_MUTATORS = new Set(['alias', 'unalias', 'hash', 'rehash', 'enable', 'autoload', 'functions']);

// commit や add と同じコマンドの git に付けてよい `-c` / `--config-env` の鍵（短い allowlist）。
// 設定の中には、git に別のプログラムを走らせるものがある。そのため、ここに無い鍵は
// commit や add と同じコマンドでは検査できないとして拒む。足すときは、表示や名前だけを
// 変える鍵に限る。
const CONFIG_KEY_ALLOW = [/^core\.quotepath$/, /^color\./, /^advice\./,
  /^(?:user|author|committer)\.(?:name|email)$/];
/** Extract the case-insensitive Git configuration key from a key=value argument. */
const configKey = (v) => v.split('=')[0].toLowerCase();
/** Only display and identity settings are safe beside staging or commit commands. */
const configKeyAllowed = (v) => CONFIG_KEY_ALLOW.some((re) => re.test(configKey(v)));
const STAGING_OR_COMMIT = new Set(['commit', 'add', 'stage']);

/** Report unsupported per-invocation configuration keys; consumers select pre-commit order. */
function preCommitConfigKey(g) {
  if (g.terminal && g.helpKind === 'stdout') return null;
  for (const entry of [...(g.configs || []), ...(g.configEnvs || [])]) {
    if (typeof entry !== 'string') return '不明な config key';
    const key = entry.split('=', 1)[0].toLowerCase();
    if (!key || key.includes(DYN) || /[\r\n]/.test(key)) return '不明な config key';
    if (!configKeyAllowed(key)) return key;
  }
  return null;
}

/** Match Git as a word rather than as a substring of names such as digit. */
const hasGitText = (s) => /(^|[^a-z])git([^a-z]|$)/i.test(s);
/** Detect Git in source, outer-shell text, and the quoting removed by a mediated shell. */
const wordHasGit = (w) => hasGitText(w.raw) || hasGitText(w.text) || hasGitText(w.text.replace(/['"\\]/g, ''));

/** Separate Git global options, the subcommand, and its arguments without evaluating values. */
function parseGit(args) {
  const g = {
    sub: null, args: [], cdirs: [], configs: [], configEnvs: [], gitDir: false, workTree: false,
    dynamicOpt: false, dynamicGlobalWords: [], terminal: false, problems: [], pathspecFlags: [], pagerForced: false, pagerDisabled: false, configWords: [], configSelections: [],
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
      if (v.dynamic) { g.dynamicOpt = true; g.dynamicGlobalWords.push({ option: t, word: v }); }
      if (t === '-C') g.cdirs.push(v.text); else { g.configs.push(v.text); g.configWords.push(v);
        g.configSelections.push({ mode: 'value', text: v.text, word: v }); }
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
        if (v.dynamic) { g.dynamicOpt = true; g.dynamicGlobalWords.push({ option: name, word: v }); }
        value = v.text;
        k += 2;
      }
      if (name === '--git-dir') g.gitDir = true;
      if (name === '--work-tree') g.workTree = true;
      if (name === '--config-env') { g.configEnvs.push(value); g.configSelections.push({ mode: 'env', text: value }); }
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
  // Bash processes these first literal options as terminal queries before reading a program.
  // Redirection expansions were parsed independently and retain their executable effects.
  if (name === 'bash' && args[0] && !args[0].dynamic && ['--help', '--version'].includes(args[0].text)) {
    return { scripts: [], commandMode: false, readsStdin: false, unknown: false, positionals: [], terminal: true,
      interactive: false, privileged: false, posix: false, posixExplicit: false,
      login: false, noProfile: false, noRc: false, rcfileWords: [], debugger: false, fishNoConfig: false };
  }
  const scripts = [];
  let commandMode = false;
  let stdin = false;
  let unknown = false;
  let interactive = null;
  let privileged = false;
  let xtrace = false;
  let posix = name === 'sh';
  let posixExplicit = false;
  let login = false, noProfile = false, noRc = false, debuggerMode = false, fishNoConfig = false;
  const rcfileWords = [];
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
        if (ch === 'l') login = true;
        if (ch === 'N') fishNoConfig = true;
        if ('cCdofpD'.includes(ch)) fishValue(ch, eq < 0 ? args[++k] : { ...w, text: t.slice(eq + 1) });
        else if (eq >= 0) unknown = true;
      } else if (['rcfile', 'init-file', 'emulate'].includes(option)) {
        const value = eq < 0 ? args[++k] : { ...w, text: t.slice(eq + 1) };
        if (!value || value.dynamicMaySplit) unknown = true;
        if (option !== 'emulate' && value) rcfileWords.push(value);
      } else if (option === 'posix' && eq < 0) { posix = true; posixExplicit = true; }
      else if (option === 'login' && eq < 0) login = true;
      else if (option === 'noprofile' && eq < 0) noProfile = true;
      else if (option === 'norc' && eq < 0) noRc = true;
      else if (option === 'debugger' && eq < 0) debuggerMode = true;
      else if (!['debugger', 'dump-po-strings', 'dump-strings', 'help', 'login', 'noediting',
        'noprofile', 'norc', 'posix', 'restricted', 'verbose', 'version'].includes(option) || eq >= 0) unknown = true;
      continue;
    }
    for (let p = 1; p < t.length; p++) {
      const ch = t[p];
      if (!/[A-Za-z]/.test(ch)) { unknown = true; break; }
      if (name === 'fish') {
        if (ch === 'l') login = true;
        if (ch === 'N') fishNoConfig = true;
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
        const option = p + 1 < t.length ? { ...w, text: t.slice(p + 1) }
          : args[k + 1] && !/^[+-]/.test(args[k + 1].text) ? args[++k] : null;
        if (option?.dynamic) unknown = true;
        if (ch === 'o' && option?.text === 'posix' && !option.dynamic) {
          posix = t[0] === '-'; posixExplicit = true;
        }
        if (ch === 'o' && option?.text === 'xtrace' && !option.dynamic) xtrace = t[0] === '-';
        break;
      } else {
        if (ch === 'i') interactive = t[0] === '-';
        if (ch === 'l') login = t[0] === '-';
        if (ch === 'p') privileged = t[0] === '-';
        if (ch === 'x') xtrace = t[0] === '-';
        if (t[0] === '-' && ch === 'c') commandMode = true;
        if (t[0] === '-' && ch === 's') stdin = true;
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
  return { scripts, commandMode, readsStdin, unknown, positionals,
    interactive: unknown ? null : interactive === null && (commandMode || !readsStdin) ? false : interactive,
    privileged: unknown ? null : privileged, posix: unknown ? null : posix, posixExplicit,
    xtrace: unknown ? null : xtrace, login: unknown ? null : login,
    noProfile: unknown ? null : noProfile, noRc: unknown ? null : noRc, rcfileWords,
    debugger: unknown ? null : debuggerMode, fishNoConfig: unknown ? null : fishNoConfig };
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

/** A registered callback can change later prompt execution without returning through linear state. */
function sourceTraceEffects(inner) {
  const effects = { prompt: false, trace: false, promptvars: false };
  for (const entry of inner.invocations) {
    const builtin = entry.wrapperNames.every(name => ['command', 'builtin'].includes(name));
    if (!builtin || entry.nonExec || entry.definitionName) continue;
    const prompt = entry.tracePromptWord;
    const literal = prompt && !prompt.ansiCUnknown ? (typeof prompt.literalValue === 'string' ? prompt.literalValue :
      !prompt.dynamic ? prompt.text : null) : null;
    if (literal === null || /[$`]/.test(literal)) effects.prompt = true;
    if (entry.assignments.includes('PS4') && (!entry.name || SPECIAL_BUILTINS.has(entry.name))) effects.prompt = true;
    if (EXPORT_LIKE.has(entry.name) && !declarationOptions(entry.args).some(option => /^-[A-Za-z]*p[A-Za-z]*$/.test(option)) &&
        entry.args.some(word => scalarAssignment(word)?.name === 'PS4')) effects.prompt = true;
    if (entry.name === 'printf' && printfValueEffect(entry.args).targetWord?.text === 'PS4') effects.prompt = true;
    if (entry.name === 'read' && readEnvironmentTargets(entry.args).targets.some(word => word.text === 'PS4')) effects.prompt = true;
    if (entry.name === 'getopts' && entry.args[1]?.text === 'PS4') effects.prompt = true;
    if (entry.name === 'set' && xtraceSet(entry.args, false) !== false) effects.trace = true;
    if (entry.name === 'shopt' && promptvarsSet(entry.args, false) !== false) effects.promptvars = true;
  }
  return effects;
}

/** Reuse an exact quoted scalar proof without rewriting the shell word or evaluating its contents. */
function literalScalarWord(word, state) {
  const variable = /^([A-Za-z0-9_./=:-]*)"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})"$/.exec(word.raw);
  const name = variable && (variable[2] || variable[3]);
  const known = name && state.pathProofs.has(name) && !state.valuesTainted && state.values.get(name);
  return typeof known === 'string' ? { ...word, literalValue: variable[1] + known } : word;
}

/** Track allexport only in set's option region; positional operands and queries are data. */
function functionAutoExportSet(args, before) {
  let mode = before;
  for (let k = 0; k < args.length; k++) {
    const word = args[k];
    const text = word.text;
    if (word.dynamic) return null;
    if (text === '--' || text === '-' || !/^[+-]/.test(text)) break;
    if (!/^[+-][A-Za-z]+$/.test(text)) return null;
    for (let p = 1; p < text.length; p++) {
      if (text[p] === 'a') mode = text[0] === '-';
      if (text[p] === 'o') {
        if (p + 1 < text.length) return null;
        const option = args[k + 1];
        if (option?.dynamic) return null;
        if (option && !/^[+-]/.test(option.text)) {
          if (option.text === 'allexport') mode = text[0] === '-';
          k++;
        }
        break;
      }
    }
  }
  return mode;
}

/** set's option region changes tracing; queries and positional DATA do not. */
function xtraceSet(args, before) {
  let mode = before;
  for (let k = 0; k < args.length; k++) {
    const word = args[k], text = word.text;
    if (text === '--' || text === '-' || !/^[+-]/.test(text) && !word.dynamic) break;
    if (word.dynamic || !/^[+-][A-Za-z]+$/.test(text)) return null;
    for (let p = 1; p < text.length; p++) {
      if (text[p] === 'x') mode = text[0] === '-';
      if (text[p] === 'o') {
        if (p + 1 < text.length) return null;
        const option = args[k + 1];
        if (option?.dynamic) return null;
        if (option && !/^[+-]/.test(option.text)) {
          if (option.text === 'xtrace') mode = text[0] === '-';
          k++;
        }
        break;
      }
    }
  }
  return mode;
}

/** Only an actual shopt setter changes prompt expansion; print/query names stay DATA. */
function promptvarsSet(args, before) {
  let mode = before, setter = null, query = false, k = 0;
  for (; k < args.length; k++) {
    const word = args[k];
    if (word.text === '--' && !word.dynamic) { k++; break; }
    if (!word.dynamic && !word.text.startsWith('-')) break;
    if (word.dynamic || !/^-[supq]+$/.test(word.text)) return null;
    for (const flag of word.text.slice(1)) {
      if (flag === 's') setter = true;
      if (flag === 'u') setter = false;
      if ('pq'.includes(flag)) query = true;
    }
  }
  if (query || setter === null) return mode;
  for (const word of args.slice(k)) {
    if (word.dynamic) return null;
    if (word.text === 'promptvars') mode = setter;
  }
  return mode;
}

/** These Git operations have argv-selected sources or repository egress outside inspection. */
/** Preserve Git option consumption and source words without evaluating their contents. */
function gitTypedArguments(g, spec = {}) {
  const result = { values: [], operands: [], flags: [], unknown: Boolean(g.incomplete || g.dynamicOpt) };
  let afterDD = false;
  const required = new Set(spec.values || []), flags = new Set(spec.flags || []), optional = new Set(spec.optionalValues || []);
  const selectedText = word => typeof word?.literalValue === 'string' && word.dynamicMaySplit === false ? word.literalValue : word?.text;
  const boundary = word => word && !word.ansiCUnknown && !word.globExpanded && !word.braceExpanded && !word.tildeExpanded && word.dynamicMaySplit === false;
  const take = (option, word) => { result.values.push({ option, word }); if (!boundary(word)) result.unknown = true; };
  for (let k = 0; k < g.args.length; k++) {
    const word = g.args[k], text = selectedText(word);
    if (!afterDD && text === '--' && (!word.dynamic || typeof word.literalValue === 'string')) { afterDD = true; continue; }
    if (afterDD || !text.startsWith('-') || text === '-') {
      result.operands.push(word);
      if (!boundary(word) || !afterDD && word.dynamic && typeof word.literalValue !== 'string') result.unknown = true;
      continue;
    }
    if (!boundary(word)) result.unknown = true;
    if (text.startsWith('--')) {
      const eq = text.indexOf('='), option = text.slice(2, eq < 0 ? undefined : eq);
      if (required.has(option)) take(option, eq < 0 ? g.args[++k] : commitInlineValue(word, word, text.slice(eq + 1), eq + 1));
      else if (optional.has(option) && (!word.dynamic || typeof word.literalValue === 'string')) {
        result.flags.push(option);
        if (eq >= 0) take(option, commitInlineValue(word, word, text.slice(eq + 1), eq + 1));
      }
      else if (flags.has(option) && eq < 0 && (!word.dynamic || typeof word.literalValue === 'string')) result.flags.push(option);
      else result.unknown = true;
    } else {
      for (let p = 1; p < text.length; p++) {
        const option = spec.shortValues?.[text[p]];
        if (option) { take(option, p + 1 < text.length ? commitInlineValue(word, word, text.slice(p + 1), p + 1) : g.args[++k]); break; }
        if (spec.shortOptional?.[text[p]]) { take(spec.shortOptional[text[p]], p + 1 < text.length ? commitInlineValue(word, word, text.slice(p + 1), p + 1) : { text: '', dynamic: false, dynamicMaySplit: false }); break; }
        if ((spec.shortFlags || '').includes(text[p])) result.flags.push(spec.shortNames?.[text[p]] || text[p]);
        else result.unknown = true;
      }
    }
  }
  return result;
}

/** Official executable operations which need a source/context decision distinct from name parsing. */
function gitOperationRole(g) {
  if (['clone', 'fetch', 'pull', 'push', 'ls-remote', 'http-push', 'http-fetch', 'remote', 'submodule'].includes(g.sub) && gitHttpMetadataGlobalBoundary(g)) g = { ...g, dynamicOpt: false };
  const role = { operation: g.sub, mode: 'active', kind: null, sourceWords: [], values: [], operands: [],
    unknown: Boolean(g.incomplete || g.dynamicOpt), terminal: g.terminal && g.helpKind === 'stdout' };
  if (role.terminal) return role;
  if (['upload-pack', 'upload-archive', 'receive-pack', 'http-backend', 'cvsserver', 'gitweb', 'instaweb'].includes(g.sub)) role.kind = 'server';
  else if (g.sub === 'http-fetch') role.kind = 'protocol-input';
  else if (['p4', 'svn', 'cvsexportcommit', 'archimport', 'cvsimport', 'quiltimport'].includes(g.sub)) role.kind = 'external-scm';
  else if (['mergetool', 'history', 'verify-commit', 'verify-tag', 'gui', 'citool', 'gitk', 'scalar', 'sh-i18n', 'sh-setup'].includes(g.sub)) {
    role.kind = 'selected-program';
    if (g.sub === 'mergetool') {
      const parsed = gitTypedArguments(g, { values: ['tool'], shortValues: { t: 'tool' }, flags: ['tool-help', 'no-prompt', 'prompt', 'gui', 'no-gui'] });
      Object.assign(role, parsed);
      if (!parsed.unknown && parsed.flags.includes('tool-help') && !parsed.operands.length && !parsed.values.length) role.mode = 'query';
    }
  } else if (g.sub === 'help' || g.helpKind === 'manual') {
    role.kind = 'manual-viewer';
    if (!g.helpKind && g.args.every(word => !word.dynamic && ['-a', '--all', '-g', '--guides', '--user-interfaces', '--developer-interfaces', '--config', '--no-external-commands', '--no-aliases', '--verbose'].includes(word.text))) role.mode = 'query';
  } else if (g.sub === 'bisect' && g.args[0]?.text === 'run') {
    role.kind = 'argv-program'; role.sourceWords = g.args.slice(1);
  } else if (g.sub === 'merge-index' || g.sub === 'for-each-repo') {
    role.kind = 'argv-program';
    const parsed = gitTypedArguments(g, g.sub === 'for-each-repo' ? { values: ['config'], flags: ['keep-going'] } : { shortFlags: 'oq', flags: [] });
    Object.assign(role, parsed); role.sourceWords = parsed.operands;
  } else if (g.sub === 'submodule') {
    const parsed = gitTypedArguments(g, { values: ['branch', 'name', 'depth', 'jobs', 'reference'], shortValues: { b: 'branch', j: 'jobs' },
      flags: ['quiet', 'recursive', 'cached', 'init', 'remote', 'force', 'checkout', 'merge', 'rebase', 'none', 'recommend-shallow', 'no-recommend-shallow'], shortFlags: 'qf' });
    const action = parsed.operands[0], text = typeof action?.literalValue === 'string' ? action.literalValue : action?.text;
    if (text === 'foreach') {
      Object.assign(role, parsed); role.kind = 'shell-source';
      role.sourceWords = g.args.slice(g.args.indexOf(action) + 1).filter((word, k) => k > 0 || word.text !== '--recursive');
    } else if (parsed.unknown) { Object.assign(role, parsed); role.kind = 'argv-boundary'; }
  } else if (g.sub === 'rebase') {
    const parsed = gitTypedArguments(g, { values: ['exec', 'onto', 'strategy', 'strategy-option', 'empty'], shortValues: { x: 'exec', s: 'strategy', X: 'strategy-option' },
      flags: ['no-edit', 'root', 'interactive', 'no-interactive', 'continue', 'abort', 'quit', 'skip', 'quiet', 'verbose', 'show-current-patch', 'force-rebase', 'no-ff', 'fork-point', 'no-fork-point', 'keep-base', 'reapply-cherry-picks', 'no-reapply-cherry-picks', 'autosquash', 'no-autosquash', 'autostash', 'no-autostash', 'keep-empty', 'no-keep-empty', 'rebase-merges', 'no-rebase-merges', 'apply', 'merge', 'stat', 'no-stat', 'committer-date-is-author-date', 'ignore-date', 'reset-author-date'], shortFlags: 'iqvf' });
    if (parsed.values.some(value => value.option === 'exec')) { role.kind = 'shell-source'; Object.assign(role, parsed); role.sourceWords = parsed.values.filter(value => value.option === 'exec').map(value => value.word); }
    else if (parsed.unknown) { role.kind = 'argv-boundary'; Object.assign(role, parsed); }
  } else if (['clone', 'fetch', 'fetch-pack', 'archive', 'ls-remote'].includes(g.sub)) {
    const parsed = gitTypedArguments(g, { values: ['upload-pack', 'exec', 'remote', 'branch', 'origin', 'filter', 'depth', 'output', 'format'], shortValues: { u: 'upload-pack', b: 'branch', o: 'origin' },
      flags: ['quiet', 'verbose', 'bare', 'no-checkout', 'mirror', 'list', 'all', 'tags', 'no-tags', 'prune', 'no-prune', 'force', 'atomic', 'dry-run', 'progress', 'no-progress', 'single-branch', 'no-single-branch', 'local', 'no-local', 'shared', 'no-hardlinks', ...(g.sub === 'ls-remote' ? ['get-url'] : [])], shortFlags: 'qvnft' });
    if (g.sub === 'ls-remote' && !parsed.unknown && parsed.flags.includes('get-url')) return { ...role, ...parsed, kind: 'http-query', mode: 'query' };
    if (parsed.values.some(value => ['upload-pack', 'exec'].includes(value.option))) { role.kind = 'selected-program'; Object.assign(role, parsed); role.sourceWords = parsed.values.filter(value => ['upload-pack', 'exec'].includes(value.option)).map(value => value.word); }
    else if (parsed.unknown) { role.kind = 'argv-boundary'; Object.assign(role, parsed); }
  } else if (g.sub === 'hook') {
    role.kind = 'hook-source';
    if (g.args[0] && !g.args[0].dynamic && g.args[0].text === 'list') {
      const parsed = gitTypedArguments({ ...g, args: g.args.slice(1) }, { flags: ['show-scope'], shortFlags: 'z' });
      Object.assign(role, parsed); if (!parsed.unknown && parsed.operands.every(word => !word.dynamic)) role.mode = 'query';
    }
  } else if (g.sub === 'interpret-trailers') {
    const parsed = gitTypedArguments(g, { values: ['trailer', 'where', 'if-exists', 'if-missing'],
      flags: ['parse', 'only-input', 'no-only-input', 'only-trailers', 'no-only-trailers', 'unfold', 'no-unfold', 'trim-empty', 'in-place', 'no-in-place'] });
    Object.assign(role, parsed); role.kind = 'trailer-source';
    const input = parsed.flags.filter(flag => ['parse', 'only-input', 'no-only-input'].includes(flag)).at(-1);
    if (!parsed.unknown && ['parse', 'only-input'].includes(input)) role.mode = 'query';
  } else if (g.sub === 'am') {
    const parsed = gitTypedArguments(g, { values: ['patch-format', 'quoted-cr', 'empty', 'whitespace', 'directory', 'exclude', 'include', 'resolvemsg'],
      optionalValues: ['show-current-patch', 'gpg-sign'], shortValues: { C: 'context', p: 'strip' }, shortOptional: { S: 'sign' },
      flags: ['abort', 'quit', 'continue', 'resolved', 'skip', 'retry', 'allow-empty', 'reject', 'quiet', 'signoff', 'keep', 'keep-non-patch', 'keep-cr', 'no-keep-cr', 'utf8', 'no-utf8', 'verify', 'no-verify', '3way', 'no-3way', 'interactive', 'committer-date-is-author-date', 'ignore-date', 'ignore-space-change', 'ignore-whitespace', 'scissors', 'no-scissors', 'message-id', 'no-message-id', 'no-gpg-sign', 'rerere-autoupdate', 'no-rerere-autoupdate'],
      shortFlags: 'skbu3iqmrn', shortNames: { q: 'quiet', r: 'resolved' } });
    Object.assign(role, parsed); role.kind = 'mail-object-input';
    role.messageFiles = parsed.operands; role.stdinInput = parsed.operands.length === 0;
    const modes = parsed.flags.filter(flag => ['abort', 'quit', 'show-current-patch', 'continue', 'resolved', 'skip', 'retry', 'allow-empty'].includes(flag));
    const onlyControl = !parsed.unknown && modes.length === 1 && !parsed.operands.length &&
      parsed.flags.every(flag => ['quiet', 'abort', 'quit', 'show-current-patch'].includes(flag)) &&
      parsed.values.every(value => value.option === 'show-current-patch' && ['raw', 'diff'].includes(value.word.text));
    if (onlyControl) { role.mode = modes[0] === 'show-current-patch' ? 'query' : 'cleanup'; role.stdinInput = false; }
    else if (modes.length) role.mode = 'resume';
  } else if (g.sub === 'commit-tree') {
    const parsed = gitTypedArguments(g, { shortValues: { m: 'message', F: 'file', p: 'parent' }, shortOptional: { S: 'sign' }, flags: ['no-gpg-sign'] });
    Object.assign(role, parsed); role.kind = 'generated-object';
    role.inlineObjectWords = parsed.values.filter(value => value.option === 'message').map(value => ({ kind: 'message', word: value.word }));
    role.messageFiles = parsed.values.filter(value => value.option === 'file').map(value => value.word);
  } else if (['mktree', 'index-pack', 'unpack-objects', 'update-ref', 'write-tree', 'read-tree', 'replay'].includes(g.sub)) role.kind = 'object-ref-input';
  else if (g.sub === 'update-index') {
    const parsed = gitTypedArguments(g, { values: ['cacheinfo', 'index-version', 'chmod'], flags: ['add', 'remove', 'force-remove', 'replace', 'refresh', 'really-refresh', 'unmerged', 'ignore-missing', 'info-only', 'index-info', 'stdin', 'show-index-version', 'verbose'], shortFlags: 'qz' });
    Object.assign(role, parsed); role.kind = 'index-file-input';
    if (!parsed.unknown && parsed.flags.includes('show-index-version') && !parsed.operands.length && parsed.flags.length === 1) role.mode = 'query';
  } else if (g.sub === 'commit' && parseCommitArgs(g.args).signingSelected) {
    role.kind = 'signature-program';
  } else if (['merge', 'pull'].includes(g.sub) &&
      (parseMergeMessageArgs(g.args).signingSelected || parseMergeMessageArgs(g.args).verificationSelected)) {
    role.kind = 'signature-program';
  }
  return role.kind || role.terminal ? role : null;
}

/** Numbered command-scope config retains actual exported keys and values, not local DATA. */
function gitConfigurationEntries(sources) {
  const scalar = word => word && !word.dynamicMaySplit && !word.ansiCUnknown && !word.globExpanded && !word.braceExpanded && !word.tildeExpanded ?
    !word.dynamic ? word.text : typeof word.literalValue === 'string' ? word.literalValue : undefined : undefined;
  const selected = new Map(sources.map(source => [source.name, source.word]));
  let unknown = sources.some(source => !source.word?.implicitGitConfigRoot &&
    ['GIT_CONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM'].includes(source.name));
  if (selected.has('GIT_CONFIG_PARAMETERS') && scalar(selected.get('GIT_CONFIG_PARAMETERS')) !== '') unknown = true;
  const entries = [];
  if (selected.has('GIT_CONFIG_COUNT')) {
    const count = scalar(selected.get('GIT_CONFIG_COUNT'));
    if (count === '') return { entries, unknown };
    if (count === undefined || !/^\d+$/.test(count) || Number(count) > 32) return { entries, unknown: true };
    for (let index = 0; index < Number(count); index++) {
      const key = scalar(selected.get('GIT_CONFIG_KEY_' + index));
      if (key === undefined || !key || key.includes('\0')) { unknown = true; continue; }
      entries.push({ key, index, word: selected.get('GIT_CONFIG_VALUE_' + index) || null });
    }
  }
  return { entries, unknown };
}

/** Dynamic metadata bytes do not erase an already proven quoted -c argv/key boundary. */
function gitHttpMetadataGlobalBoundary(g) {
  return Boolean(g.dynamicOpt && g.dynamicGlobalWords?.length && g.dynamicGlobalWords.every(({ option, word }) => {
    if (option !== '-c' || word.dynamicMaySplit || word.ansiCUnknown || word.globExpanded || word.braceExpanded || word.tildeExpanded) return false;
    const eq = word.text.indexOf('='), key = word.text.slice(0, eq < 0 ? undefined : eq);
    return eq >= 0 && !key.includes(DYN) && /^http(?:\..+)?\.(?:extraheader|useragent)$/i.test(key);
  }));
}

/** Preserve actual HTTP operation/query selection independently of configured input families. */
function gitHttpClientRole(g) {
  if (gitHttpMetadataGlobalBoundary(g)) g = { ...g, dynamicOpt: false };
  if (g.gitNamespaceInferred || g.terminal || g.helpKind === 'manual') return null;
  if (!['clone', 'fetch', 'pull', 'push', 'ls-remote', 'http-push', 'http-fetch', 'remote', 'submodule'].includes(g.sub)) return null;
  const parsed = gitTypedArguments(g, { values: ['upload-pack', 'exec', 'repo', 'branch', 'origin', 'depth', 'filter', 'server-option', 'push-option', 'receive-pack', 'recurse-submodules', 'refmap', 'jobs', 'shallow-since', 'shallow-exclude', 'negotiation-tip', 'separate-git-dir', 'config'],
    shortValues: { u: 'upload-pack', b: 'branch', o: g.sub === 'push' ? 'push-option' : 'origin', j: 'jobs' },
    flags: ['get-url', 'heads', 'branches', 'tags', 'refs', 'symref', 'exit-code', 'quiet', 'verbose', 'bare', 'no-checkout', 'mirror', 'all', 'no-tags', 'prune', 'no-prune', 'force', 'atomic', 'dry-run', 'progress', 'no-progress', 'single-branch', 'no-single-branch', 'local', 'no-local', 'shared', 'no-hardlinks', 'recursive', 'init', 'remote', 'cached', 'no-recurse-submodules', 'update-head-ok', 'append', 'no-write-fetch-head', 'write-fetch-head'], shortFlags: 'qvnft46' });
  if (g.sub === 'ls-remote' && !parsed.unknown && parsed.flags.includes('get-url')) return null;
  const action = parsed.operands[0]?.text;
  if (g.sub === 'remote' && !parsed.unknown && (action === 'get-url' || action === 'show' && parsed.flags.includes('n'))) return null;
  if (g.sub === 'submodule' && !parsed.unknown && ['status', 'sync', 'summary'].includes(action)) return null;
  const repositoryWord = g.sub === 'http-fetch' ? parsed.operands[1] : g.sub === 'remote' ? parsed.operands[1] :
    g.sub === 'submodule' ? action === 'add' ? parsed.operands[1] : null :
      parsed.operands[0] || parsed.values.findLast(value => value.option === 'repo')?.word;
  return { repositoryWord, argvUnknown: parsed.unknown, mode: 'potential-http-client', values: parsed.values, operands: parsed.operands };
}

/** Explicit transport selectors are executable sources, selected only by an active client role. */
function gitTransportSourceRole(g) {
  if (!['clone', 'fetch', 'fetch-pack', 'pull', 'push', 'ls-remote'].includes(g.sub)) return null;
  let client;
  if (g.sub === 'fetch-pack') {
    if (g.gitNamespaceInferred || g.terminal || g.helpKind === 'manual') return null;
    const valueNames = ['upload-pack', 'exec', 'depth', 'shallow-since', 'shallow-exclude', 'filter'];
    const argumentText = word => typeof word.literalValue === 'string' && word.dynamicMaySplit === false ? word.literalValue : word.text;
    const firstOperand = g.args.findIndex(word => !argumentText(word).startsWith('-'));
    const prefixLength = firstOperand < 0 ? g.args.length : firstOperand;
    const prefix = g.args.slice(0, prefixLength);
    const parsed = gitTypedArguments({ ...g, args: prefix }, { values: valueNames,
      flags: ['all', 'stdin', 'quiet', 'keep', 'thin', 'include-tag', 'no-progress', 'diag-url', 'stateless-rpc',
        'lock-pack', 'check-self-contained-and-connected', 'cloning', 'update-shallow', 'from-promisor',
        'refetch', 'no-filter', 'deepen-relative'], shortFlags: 'qkv' });
    // Native stops option parsing at its first destination. Later dash-prefixed
    // reference names are DATA and cannot select diag/stateless query modes.
    parsed.operands = g.args.slice(prefixLength);
    if (parsed.operands.some(word => word.dynamicMaySplit !== false || word.ansiCUnknown ||
        word.globExpanded || word.braceExpanded || word.tildeExpanded) ||
        parsed.operands[0]?.dynamic && typeof parsed.operands[0].literalValue !== 'string') parsed.unknown = true;
    // This builtin accepts value options only with '=' and its short flags are
    // single-letter forms. An unknown native arity is never a query proof.
    if (prefix.some(word => valueNames.some(name => argumentText(word) === '--' + name) ||
        /^-[^-]/.test(argumentText(word)) && !['-q', '-k', '-v'].includes(argumentText(word)))) parsed.unknown = true;
    if (!parsed.unknown && parsed.flags.some(flag => ['stateless-rpc', 'diag-url'].includes(flag))) return null;
    client = { repositoryWord: parsed.operands[0], argvUnknown: parsed.unknown || !parsed.operands.length,
      mode: 'potential-transport-client', values: parsed.values, operands: parsed.operands };
  } else client = gitHttpClientRole(g);
  if (!client) return null;
  const settings = (g.configSelections || []).flatMap((selection, order) => {
    const eq = selection.text.indexOf('='), key = selection.text.slice(0, eq < 0 ? undefined : eq).toLowerCase();
    if (!['core.gitproxy', 'core.sshcommand'].includes(key)) return [];
    const word = selection.mode === 'configuration-env' ? selection.word : selection.mode === 'env' ?
      selection.prefixSourceKnown ? selection.word : null : selection.word && eq >= 0 ?
        commitInlineValue(selection.word, selection.word, selection.text.slice(eq + 1), eq + 1) : null;
    return [{ key, kind: key === 'core.gitproxy' ? 'proxy' : 'ssh', word, order, mode: selection.mode }];
  });
  const environmentSources = g.gitTransportSources || [];
  if (!settings.length && !environmentSources.length) return null;
  const configEnvironmentUnknown = gitConfigurationEntries(g.gitConfigurationSources || []).unknown;
  return { ...client, kind: 'selected-transport-source', settings, environmentSources, configEnvironmentUnknown };
}

/** Keep ordered command-scope selectors and their original value words. */
function gitHttpSettings(g, family) {
  const selections = (g.configSelections || []).slice();
  const seen = new Set(selections.map(value => (value.mode === 'configuration-env' ? 'env' : value.mode) + ':' + value.text));
  for (const [mode, entries] of [['value', g.configs || []], ['env', g.configEnvs || []]]) for (const text of entries) {
    if (!seen.has(mode + ':' + text)) selections.push({ mode, text, word: null });
  }
  return selections.flatMap((selection, order) => {
    const eq = selection.text.indexOf('='), key = selection.text.slice(0, eq < 0 ? undefined : eq);
    const match = /^http(?:\.(.+))?\.(cookiefile|extraheader|useragent)$/i.exec(key);
    if (!match || !family.includes(match[2].toLowerCase())) return [];
    const word = selection.mode === 'configuration-env' ? selection.word : selection.mode === 'env' ? selection.prefixSourceKnown ? selection.word : null :
      selection.word && eq >= 0 ? commitInlineValue(selection.word, selection.word, selection.text.slice(eq + 1), eq + 1) : null;
    return [{ key, field: match[2].toLowerCase(), scope: match[1] || null, mode: selection.mode, word, order }];
  });
}

/** Explicit cookie-file selectors are client file input, not ordinary header DATA. */
function gitHttpCookieRole(g) {
  const client = gitHttpClientRole(g);
  if (!client) return null;
  const settings = gitHttpSettings(g, ['cookiefile']);
  const configurationSources = (g.gitConfigurationSources || []).filter(source => !source.word?.implicitGitConfigRoot);
  const configEnvironmentUnknown = gitConfigurationEntries(configurationSources).unknown;
  if (!settings.length && !configEnvironmentUnknown) return null;
  return { ...client, kind: 'http-cookie-file-input', settings, configEnvironmentUnknown, configurationSources };
}

/** HTTP headers and User-Agent are generated outbound DATA, retaining export/word provenance. */
function gitHttpMetadataRole(g) {
  const client = gitHttpClientRole(g);
  if (!client) return null;
  const settings = gitHttpSettings(g, ['extraheader', 'useragent']);
  const environmentSources = g.gitHttpMetadataSources || [];
  const configurationSources = (g.gitConfigurationSources || []).filter(source => !source.word?.implicitGitConfigRoot);
  const configEnvironmentUnknown = gitConfigurationEntries(configurationSources).unknown;
  if (!settings.length && !environmentSources.length && !configEnvironmentUnknown) return null;
  return { ...client, kind: 'http-generated-metadata', settings, environmentSources, configEnvironmentUnknown };
}

function gitOutboundRole(g) {
  if (!['send-email', 'filter-branch', 'daemon'].includes(g.sub)) return null;
  const role = { operation: g.sub, terminal: false, files: [], values: [], noSend: false,
    unknown: Boolean(g.incomplete || g.dynamicOpt), afterDD: false };
  // A sole -h is a terminal usage operation. --help can invoke an external manual viewer.
  if (g.args.length === 1 && !g.args[0].dynamic && g.args[0].text === '-h' && !role.unknown) {
    role.terminal = true; return role;
  }
  const required = g.sub === 'send-email' ? ['to', 'cc', 'bcc', 'from', 'subject', 'in-reply-to',
    'reply-to', 'smtp-server', 'smtp-server-port', 'smtp-user', 'smtp-pass', 'smtp-domain',
    'smtp-encryption', 'smtp-ssl-cert-path', 'smtp-debug', 'smtp-auth', 'smtp-batch-size',
    'smtp-relog-delay', 'sendmail-cmd', 'to-cmd', 'cc-cmd', 'header-cmd', 'confirm', 'suppress-cc',
    'transfer-encoding', 'compose-encoding', '8bit-encoding', 'identity'] :
    g.sub === 'filter-branch' ? ['setup', 'env-filter', 'tree-filter', 'index-filter', 'parent-filter',
      'msg-filter', 'commit-filter', 'tag-name-filter', 'subdirectory-filter', 'original', 'state-branch'] :
      ['listen', 'port', 'user', 'group', 'base-path', 'interpolated-path', 'pid-file', 'init-timeout',
        'timeout', 'max-connections', 'access-hook', 'enable', 'disable', 'allow-override', 'forbid-override'];
  const flags = g.sub === 'send-email' ? ['dry-run', 'quiet', 'chain-reply-to', 'thread', 'no-thread',
    'signed-off-by-cc', 'no-signed-off-by-cc', 'suppress-from', 'no-suppress-from', 'compose',
    'annotate', 'no-annotate', 'validate', 'no-validate', 'no-xmailer', 'xmailer', 'force'] :
    g.sub === 'filter-branch' ? ['force', 'prune-empty', 'remap-to-ancestor'] :
      ['verbose', 'syslog', 'inetd', 'detach', 'reuseaddr', 'strict-paths', 'base-path-relaxed',
        'export-all', 'informative-errors', 'no-informative-errors'];
  for (let k = 0; k < g.args.length; k++) {
    const word = g.args[k], text = typeof word.literalValue === 'string' ? word.literalValue : word.text;
    if (word.dynamic && typeof word.literalValue !== 'string' || word.dynamicMaySplit || word.globExpanded || word.braceExpanded || word.tildeExpanded) role.unknown = true;
    if (!role.afterDD && text === '--') { role.afterDD = true; continue; }
    if (!role.afterDD && text.startsWith('-')) {
      const eq = text.indexOf('='), option = text.slice(2, eq < 0 ? undefined : eq);
      if (text.startsWith('--') && required.includes(option)) {
        const value = eq < 0 ? g.args[++k] : commitInlineValue(word, word, text.slice(eq + 1), eq + 1);
        role.values.push({ option, word: value });
        if (['sendmail-cmd', 'to-cmd', 'cc-cmd', 'header-cmd'].includes(option)) role.unknown = true;
        if (!value || value.dynamic && typeof value.literalValue !== 'string' || value.dynamicMaySplit) role.unknown = true;
      } else if (text.startsWith('--') && flags.includes(option) && eq < 0 || g.sub === 'filter-branch' && text === '-f') {
        if (option === 'dry-run') role.noSend = true;
      } else role.unknown = true;
    } else if (g.sub === 'send-email') role.files.push(word);
    else role.values.push({ option: 'operand', word });
  }
  return role;
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
  const options = depth && typeof depth === 'object' ? depth : {};
  if (depth && typeof depth === 'object') depth = options.sourceDepth || 0;
  const word = typeof source === 'string' ? { text: source, dynamic: false } : source;
  if (!word || word.dynamic) return { gits: [], invocations: [], problems: ['実行する source 文字列が動的で、中身を検査できない'] };
  const inner = inspect(word.text, { ...options, sourceDepth: depth + 1 });
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
  // Opt in only for egress: an explicit SendEnv can select any exported scalar.
  const trackedEnv = name => trackedValueEnvironment(name) ||
    options.trackOutboundEnvironment === true && typeof name === 'string' && name.length > 0 && !/[=\0]/.test(name);
  const outboundScalarWord = (word, state) => {
    const selected = literalScalarWord(word, state);
    if (options.trackOutboundEnvironment !== true || typeof selected.literalValue === 'string') return selected;
    // A single quoted scalar with static prefix/suffix has no splitting or
    // re-evaluation. Keep this DATA proof separate from executable identity.
    const match = /^([^'"$`\\]*)"([^"$`\\]*)\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})([^"$`\\]*)"$/.exec(word.raw || '');
    const name = match && (match[3] || match[4]);
    const value = name && state.pathProofs.has(name) && !state.valuesTainted && state.values.get(name);
    return typeof value === 'string' && word.dynamicMaySplit === false && !state.integers.has(name) && !state.associatives.has(name)
      ? { ...selected, outboundLiteralValue: match[1] + match[2] + value + match[5] } : selected;
  };
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
  if (parsed.unsupportedSources.some(source => source.kind === 'coproc')) {
    res.problems.push('Bash coproc の非同期 source・実行条件は対応範囲外で、実行先と副作用を確認できません。同目的を保てる対応済みの同期形式がなければ、owner に対象・操作・cwd/env/config/source と不明点を確認してください。個別操作の了承は hook 無効化の了承ではありません。');
  }
  res.async = parsed.async;
  if (parsed.errors.length && gitContext) {
    res.problems.push(`コマンドの引用符や括弧が閉じていない（${parsed.errors[0]}）`);
  }
  const queue = parsed.cmds.map((c) => ({ c, origin: 'top' }));
  const resolved = [];
  for (let qi = 0; qi < queue.length; qi++) {
    const { c } = queue[qi];
    const info = resolveCommand(c.words);
    resolved.push({ c, info });
  }

  // スコープの状態は最初のコマンドを訪れた時に親から写す。置換とサブシェルの変更は親へ戻さない。
  const scopeStates = new Map();
  const emptyState = () => ({ env: new Set(), helperEnv: new Set(), functions: new Map(), functionAutoExport: false, exportedFunctions: new Set(), exportedFunctionUnknown: false, environmentFunctions: new Map(), environmentFunctionUnknown: new Set(), localNames: new Set(), cd: false, pathChanged: false, searchChanged: false, unknownContext: false, gitShadowed: false, positionals: null, positionalsTainted: false, values: new Map(), integers: new Set(), associatives: new Set(), valuesTainted: false, loopBindings: new Map(), pathProofs: new Set(), outboundEnvironmentUnknown: !!options.initialOutboundEnvironmentUnknown, identitySources: new Map([['PS4', { text: '+ ', dynamic: false }]]), identityExports: new Map([['PS4', false]]), promptRefNames: new Set(), xtrace: false, promptvars: true, localShellOptions: false });
  const copyState = (s) => ({ ...s, env: new Set(s.env), helperEnv: new Set(s.helperEnv), functions: new Map(s.functions), exportedFunctions: new Set(s.exportedFunctions), environmentFunctions: new Map(s.environmentFunctions), environmentFunctionUnknown: new Set(s.environmentFunctionUnknown), localNames: new Set(s.localNames), values: new Map(s.values), integers: new Set(s.integers), associatives: new Set(s.associatives), loopBindings: new Map(s.loopBindings), pathProofs: new Set(s.pathProofs), identitySources: new Map(s.identitySources), identityExports: new Map(s.identityExports), promptRefNames: new Set(s.promptRefNames) });
  const stateFor = (scope) => {
    if (!scopeStates.has(scope)) {
      scopeStates.set(scope, scope && scope.parent ? copyState(stateFor(scope.parent)) : emptyState());
    }
    return scopeStates.get(scope);
  };
  const seedScope = (scope, env, cd, inherited) => scopeStates.set(scope, copyState({ ...emptyState(), ...inherited, env: new Set(env), cd }));
  if (options.trackOutboundEnvironment === true) {
    const initial = stateFor(parsed.scope);
    for (const name of options.initialOutboundEnvironmentNames || []) if (trackedEnv(name)) {
      initial.identitySources.set(name, null); initial.identityExports.set(name, true);
    }
    const selected = childIdentityState(new Map((options.initialOutboundEnvironmentSources || [])
      .filter(source => trackedEnv(source.name)).map(source => [source.name, source.word])));
    for (const [name, word] of selected.identitySources) initial.identitySources.set(name, word);
    for (const [name, exported] of selected.identityExports) initial.identityExports.set(name, exported);
  }
  if (Array.isArray(options.initialHelperEnvNames)) {
    for (const name of options.initialHelperEnvNames) if (HELPER_SOURCE_ENV.has(name)) stateFor(parsed.scope).helperEnv.add(name);
  }
  if (Array.isArray(options.initialGitIdentityEnvNames) || Array.isArray(options.initialPagerEnvNames) || Array.isArray(options.initialGhEnvNames) || Array.isArray(options.initialShellStartupEnvNames) || Array.isArray(options.initialGitConfigEnvNames) || Array.isArray(options.initialGitHttpEnvNames) || Array.isArray(options.initialGitTransportEnvNames)) {
    const initial = stateFor(parsed.scope);
    for (const name of [...(options.initialGitIdentityEnvNames || []), ...(options.initialPagerEnvNames || []), ...(options.initialGhEnvNames || []), ...(options.initialShellStartupEnvNames || []), ...(options.initialGitConfigEnvNames || []), ...(options.initialGitHttpEnvNames || []), ...(options.initialGitTransportEnvNames || [])]) if (trackedEnv(name)) {
      initial.identitySources.set(name, null); initial.identityExports.set(name, true);
    }
  }
  if (Array.isArray(options.initialGitIdentitySources) || Array.isArray(options.initialPagerSources) || Array.isArray(options.initialGhSources) || Array.isArray(options.initialShellStartupSources) || Array.isArray(options.initialGitConfigSources) || Array.isArray(options.initialGitHttpSources) || Array.isArray(options.initialGitTransportSources)) {
    const initial = stateFor(parsed.scope);
    const selected = childIdentityState(new Map([...(options.initialGitIdentitySources || []), ...(options.initialPagerSources || []), ...(options.initialGhSources || []), ...(options.initialShellStartupSources || []), ...(options.initialGitConfigSources || []), ...(options.initialGitHttpSources || []), ...(options.initialGitTransportSources || [])]
      .filter(source => trackedEnv(source.name)).map(source => [source.name, source.word])));
    // Presence names may include unknown inherited values while source arrays only
    // supply partial known values. Preserve every presence seed across families.
    // Child inspections pass selected sources without presence names, so [] still
    // leaves that child's environment empty (including an actual env -u removal).
    for (const [name, word] of selected.identitySources) initial.identitySources.set(name, word);
    for (const [name, exported] of selected.identityExports) initial.identityExports.set(name, exported);
  }
  const sourcePlaceholder = (name) => ({ definitionName: name, redirs: [], heredocBodies: [], functionBody: null });
  const initial = stateFor(parsed.scope);
  if (Object.prototype.hasOwnProperty.call(options, 'initialTraceMode')) initial.xtrace = options.initialTraceMode;
  if (Object.prototype.hasOwnProperty.call(options, 'initialPromptVars')) initial.promptvars = options.initialPromptVars;
  if (options.initialPromptEnvPresent) { initial.identitySources.set('PS4', null); initial.identityExports.set('PS4', true); }
  for (const source of options.initialPromptSources || []) if (source.name === 'PS4') {
    initial.identitySources.set('PS4', source.word); initial.identityExports.set('PS4', true);
  }
  const seedFunctionNames = (names, add) => {
    if (!Array.isArray(names)) return;
    for (const name of names) {
      if (typeof name === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) add(name);
      else stateFor(parsed.scope).exportedFunctionUnknown = true;
    }
  };
  seedFunctionNames(options.initialFunctionSourceNames, name => stateFor(parsed.scope).functions.set(name, sourcePlaceholder(name)));
  seedFunctionNames(options.initialExportedFunctionNames, name => stateFor(parsed.scope).exportedFunctions.add(name));
  if (options.initialExportedFunctionUnknown) stateFor(parsed.scope).exportedFunctionUnknown = true;
  if (Array.isArray(options.initialPositionals)) stateFor(parsed.scope).positionals = knownPositionals(options.initialPositionals);
  const updatePositionals = (state, c, next) => {
    const conditional = (c.effects || []).some((effect) => effect.conditional || effect.pipeline);
    const same = state.positionals && next && state.positionals.length === next.length &&
      state.positionals.every((word, index) => word.text === next[index].text);
    state.positionals = conditional && !same ? null : next;
  };

  const visit = (c, info, depth) => {
    if (depth > MAX_DEPTH) { res.problems.push('入れ子が深すぎる'); return; }
    const state = stateFor(c.scope);
    if (!c.definitionName && !info.incomplete) info = resolveCommand(c.words, state.functions);
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
    for (const evaluation of c.definitionName ? [] : c.evaluations || []) checkEvaluation(evaluation, state);
    // Assignment-only commands expand assignments in order. Prefix assignments to other commands
    // are not proofs for those commands' argument expansions.
    const expansionState = copyState(state);
    // Flattened current-environment bodies may have changed a value before an earlier outer-word
    // expansion is inspected. Do not certify a saved value from that reordered visit.
    if (c.words.some((word) => (word.evaluations || []).some((evaluation) => evaluation.kind === 'source'))) {
      expansionState.valuesTainted = true;
      state.pathProofs.clear();
    }
    for (const word of c.definitionName ? [] : c.words.concat(c.redirs.map((redir) => redir.word))) {
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
        info = resolveCommand(c.words.slice(0, index).concat(replacement.map(expandedLiteral), c.words.slice(index + 1)), state.functions);
      }
    }
    const env = new Set(state.env);
    const promptWord = state.identitySources.has('PS4') ? state.identitySources.get('PS4') : { text: '+ ', dynamic: false };
    const promptLiteral = promptWord && !promptWord.ansiCUnknown ? (typeof promptWord.literalValue === 'string' ? promptWord.literalValue :
      !promptWord.dynamic ? promptWord.text : null) : null;
    if (!c.definitionName && state.xtrace !== false && state.promptvars !== false &&
        (promptLiteral === null || /[$`]/.test(promptLiteral))) {
      res.problems.push('active xtrace が展開する PS4 prompt の保存 source・置換・実行条件を検査できない');
    }
    const identitySources = identityEnvironmentSources(state);
    let outboundEnvironmentUnknown = state.outboundEnvironmentUnknown || !!info.envUnknown;
    const helperEnv = new Set(state.helperEnv);
    const exportedFunctions = new Set(state.exportedFunctions);
    let exportedFunctionUnknown = state.exportedFunctionUnknown;
    const environmentFunctions = new Map(state.environmentFunctions);
    const environmentFunctionUnknown = new Set(state.environmentFunctionUnknown);
    let pathChanged = state.pathChanged;
    for (const op of info.envOps) {
      if (op.clear) { outboundEnvironmentUnknown = false; identitySources.clear(); env.clear(); helperEnv.clear(); exportedFunctions.clear(); exportedFunctionUnknown = false;
        environmentFunctions.clear(); environmentFunctionUnknown.clear(); for (const root of CONFIG_ROOT_ENV) env.add(root); pathChanged = false; }
      if (op.unset) {
        identitySources.delete(op.unset);
        if (CONFIG_ROOT_ENV.has(op.unset)) env.add(op.unset); else env.delete(op.unset);
        helperEnv.delete(op.unset);
        environmentFunctions.delete(op.unset); environmentFunctionUnknown.delete(op.unset);
        if (op.unset === 'PATH') pathChanged = false;
      }
      if (op.set && affectsGitEnvironment(op.set)) env.add(op.set);
      if (op.set && trackedEnv(op.set)) {
        const carrier = c.words.find(word => info.assignRaws.includes(word.raw) && word.text.startsWith(op.set + '='));
        const value = carrier && literalScalarWord(carrier, expansionState);
        identitySources.set(op.set, value ? commitInlineValue(value, value, value.text.slice(op.set.length + 1), op.set.length + 1) : null);
      }
      if (op.set && HELPER_SOURCE_ENV.has(op.set)) helperEnv.add(op.set);
      if (op.set === 'PATH' || op.set === 'FPATH') pathChanged = true;
      if (op.functionEnvironment) {
        const imported = op.functionEnvironment;
        if (imported.callee) environmentFunctions.set(imported.environment, imported.callee);
        if (imported.unknown) environmentFunctionUnknown.add(imported.environment);
      }
    }
    const cdBefore = state.cd || info.cdLike;
    const shell = SHELLS.has(info.name) ? shellInvocation(info.args, info.name) : null;
    const shellXtrace = shell && helperEnv.has('SHELLOPTS') && shell.privileged !== true && ['bash', 'sh'].includes(info.name)
      ? shell.xtrace === true ? true : null : shell?.xtrace;
    if (shell && !shell.posixExplicit && (helperEnv.has('SHELLOPTS') || helperEnv.has('POSIXLY_CORRECT'))) shell.posix = null;
    const importedFunctionNames = [...new Set([...exportedFunctions, ...environmentFunctions.values()])];
    const builtin = info.wrapperNames.every((name) => name === 'command' || name === 'builtin');
    const trap = info.name === 'trap' && builtin ? trapInvocation(info.args) : null;
    const alias = info.name === 'alias' && builtin ? aliasInvocation(info.args) : null;
    const invocation = {
      order: res.invocations.length, name: info.name, nameWord: info.nameWord,
      args: info.args.map(word => outboundScalarWord(word, expansionState)),
      words: c.words, redirs: c.redirs, heredocBodies: c.heredocBodies, scope: c.scope, incomplete: info.incomplete,
      wrapped: info.wrapped, nonExec: info.nonExec, dynamicName: info.dynamicName,
      executableExpansionUnknown: info.executableExpansionUnknown,
      wrapperNames: info.wrapperNames,
      launcherUnknown: info.launcherUnknown, launcherArgs: info.launcherArgs,
      positionalExec: !!positionalExec, positionalUnknown, positionalsBefore,
      splitString: info.splitString, splitWords: info.splitWords, envUnknown: info.envUnknown,
      definitionName: c.definitionName,
      functionBodyUnknown: !!c.functionBodyUnknown || !!c.functionBody?.unknown,
      assignments: info.assigns, gitEnvNames: [...env], cdLikeBefore: cdBefore,
      helperEnvNames: [...helperEnv],
      outboundEnvironmentSources: options.trackOutboundEnvironment === true ? [...identitySources].map(([name, word]) => ({ name,
        // Context markers identify an inherited config root, not its transmitted
        // bytes. Keep family DTOs unchanged; only the outbound DATA proof is opaque.
        word: word?.implicitGitConfigRoot ? word.actualOutboundEmpty === true ?
          { text: '', raw: "''", quoted: true, dynamic: false, dynamicMaySplit: false } : null :
          word?.defaultGhConfigRoot && word.text !== '' ? null : word })) : [],
      outboundEnvironmentUnknown: options.trackOutboundEnvironment === true && outboundEnvironmentUnknown,
      gitIdentitySources: [...identitySources].filter(([name]) => GIT_IDENTITY_ENV.has(name)).map(([name, word]) => ({ name, word })),
      gitPagerEnvSources: [...identitySources].filter(([name]) => GIT_PAGER_ENV.has(name)).map(([name, word]) => ({ name, word })),
      gitTransportSources: [...identitySources].filter(([name]) => GIT_TRANSPORT_SOURCE_ENV.has(name)).map(([name, word]) => ({ name, word })),
      gitHttpMetadataSources: [...identitySources].filter(([name]) => GIT_HTTP_METADATA_ENV.has(name)).map(([name, word]) => ({ name, word })),
      gitConfigurationSources: [...identitySources].filter(([name]) => gitConfigurationEnvironment(name)).map(([name, word]) => ({ name, word })),
      ghEnvironmentSources: [...identitySources].filter(([name]) => GH_METADATA_ENV.has(name)).map(([name, word]) => ({ name, word })),
      ghHelperEnvironmentSources: [...identitySources].filter(([name]) => GH_HELPER_ENV.has(name)).map(([name, word]) => ({ name, word })),
      shellStartupEnvironmentSources: [...identitySources].filter(([name]) => SHELL_STARTUP_ENV.has(name)).map(([name, word]) => ({ name, word })),
      traceModeBefore: state.xtrace, tracePromptWord: promptWord,
      promptVarsBefore: state.promptvars,
      tracePromptEnvSources: [...identitySources].filter(([name]) => name === 'PS4').map(([name, word]) => ({ name, word })),
      shellXtrace,
      exportedFunctionNames: importedFunctionNames, exportedFunctionUnknown: exportedFunctionUnknown || environmentFunctionUnknown.size > 0,
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
      shellInteractive: shell ? shell.interactive : null, shellPrivileged: shell ? shell.privileged : null,
      shellPosix: shell ? shell.posix : null, shellTerminal: !!shell?.terminal,
      shellLogin: shell ? shell.login : null, shellNoProfile: shell ? shell.noProfile : null,
      shellNoRc: shell ? shell.noRc : null, shellRcfileWords: shell ? shell.rcfileWords : [],
      shellDebugger: shell ? shell.debugger : null, shellFishNoConfig: shell ? shell.fishNoConfig : null,
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
    if (invocation.definitionName) {
      state.functions.set(invocation.definitionName, { ...c, functionConditional: conditional });
      if (state.functionAutoExport === true) state.exportedFunctions.add(invocation.definitionName);
      else if (state.functionAutoExport === null) state.exportedFunctionUnknown = true;
      // Keep the existing conservative Git/positional gates after a definition, without running it.
      state.unknownContext = true;
      state.positionalsTainted = true;
      state.valuesTainted = true;
      if (invocation.definitionName === 'git') state.gitShadowed = true;
      return;
    }
    const reservedTime = info.wrapperNames.length > 0 && info.wrapperNames.every((name) => name === 'time') &&
      c.words.some((word, index) => word.text === 'time' && !word.quoted && !word.dynamic && atCmdPos(c.words.slice(0, index)));
    const selectedFunction = (!info.wrapped || reservedTime) && !info.nonExec && !info.dynamicName && !info.incomplete &&
      info.nameWord?.text === info.name && state.functions.get(info.name);
    if (selectedFunction) {
      invocation.functionCallName = info.name;
      invocation.redirs = selectedFunction.redirs.concat(c.redirs);
      invocation.heredocBodies = selectedFunction.heredocBodies.concat(c.heredocBodies);
      if (info.name === 'git') res.problems.push('git の関数定義で実行先が置き換わり、Git と同じ実行条件を保証できない');
      const body = selectedFunction.functionBody;
      if (!body || body.unknown || selectedFunction.functionConditional || state.searchChanged) {
        res.problems.push('選択された関数の body / source 境界を読みきれず、実行するコマンド・環境・引数を検査できない');
        return;
      }
      if (body.evaluationUnknown || body.unsupportedSources.length) {
        res.problems.push('選択された関数の未対応の実行 source・副作用を検査できない');
      }
      res.async = res.async || body.async;
      // Each call inherits its current caller. Cached descendant scopes from an
      // earlier call must not retain that call's environment or positional proof.
      for (const cachedScope of scopeStates.keys()) {
        for (let ancestor = cachedScope; ancestor; ancestor = ancestor.parent) {
          if (ancestor === body.scope) { scopeStates.delete(cachedScope); break; }
        }
      }
      // A prefix assignment to a shell function is visible/exported during that
      // call, including to children, but must not replace unexported caller locals.
      const functionIdentitySources = new Map(state.identitySources);
      const functionIdentityExports = new Map(state.identityExports);
      for (const name of info.assigns) if (trackedEnv(name)) {
        functionIdentitySources.set(name, identitySources.get(name) ?? null);
        functionIdentityExports.set(name, true);
      }
      seedScope(body.scope, env, cdBefore, { ...state, helperEnv, pathChanged,
        identitySources: functionIdentitySources, identityExports: functionIdentityExports,
        exportedFunctions, exportedFunctionUnknown, environmentFunctions, environmentFunctionUnknown,
        localNames: new Set(), localShellOptions: false, positionals: knownPositionals(info.args), positionalsTainted: !!info.incomplete });
      for (const evaluation of selectedFunction.evaluations || []) checkEvaluation(evaluation, stateFor(body.scope));
      for (const redir of selectedFunction.redirs) {
        for (const evaluation of redir.word.evaluations || []) checkEvaluation(evaluation, stateFor(body.scope));
      }
      for (const ic of body.cmds) {
        visit({ ...ic, effects: (ic.effects || []).concat(c.effects || []) }, resolveCommand(ic.words), depth + 1);
      }
      if (!body.subshell) {
        const after = stateFor(body.scope);
        // Function calls share ordinary shell variables and registered functions. Arguments remain local.
        const local = (name) => info.assigns.includes(name) || after.localNames.has(name);
        for (const name of after.env) if (!local(name)) state.env.add(name);
        for (const name of after.helperEnv) if (!local(name)) state.helperEnv.add(name);
        for (const [name, definition] of after.functions) state.functions.set(name, definition);
        for (const name of after.exportedFunctions) state.exportedFunctions.add(name);
        state.exportedFunctionUnknown ||= after.exportedFunctionUnknown;
        state.functionAutoExport = after.functionAutoExport;
        state.xtrace = after.localShellOptions && state.xtrace !== after.xtrace ? null : after.xtrace;
        state.promptvars = after.promptvars;
        for (const name of after.promptRefNames) if (!local(name)) state.promptRefNames.add(name);
        for (const [environment, name] of after.environmentFunctions) if (!local(environment)) state.environmentFunctions.set(environment, name);
        for (const environment of after.environmentFunctionUnknown) if (!local(environment)) state.environmentFunctionUnknown.add(environment);
        state.cd ||= after.cd;
        if (!local('PATH') && !local('FPATH')) state.pathChanged ||= after.pathChanged;
        state.searchChanged ||= after.searchChanged;
        state.gitShadowed ||= after.gitShadowed;
        state.unknownContext ||= after.unknownContext;
        for (const name of new Set([...state.identitySources.keys(), ...after.identitySources.keys()])) {
          if (local(name)) continue;
          if (after.identitySources.has(name)) state.identitySources.set(name, after.identitySources.get(name));
          else state.identitySources.delete(name);
          if (after.identityExports.has(name)) state.identityExports.set(name, after.identityExports.get(name));
          else state.identityExports.delete(name);
        }
        state.outboundEnvironmentUnknown ||= after.outboundEnvironmentUnknown;
        state.valuesTainted = true;
        state.pathProofs.clear();
      }
      return;
    }
    const persistentValues = (!info.name && !info.dynamicName && !info.wrapped) ||
      info.persistsEnv || (builtin && (SPECIAL_BUILTINS.has(info.name) || EXPORT_LIKE.has(info.name)));
    const declaration = builtin && EXPORT_LIKE.has(info.name);
    const declOptions = declaration ? declarationOptions(info.args) : [];
    const declarationQuery = ['declare', 'typeset', 'local'].includes(info.name) &&
      declOptions.some((option) => /^-[A-Za-z]*p[A-Za-z]*$/.test(option));
    if (builtin && c.scope.functionBody && info.name === 'local' && info.args.some(word => !word.dynamic && word.text === '-')) {
      state.localShellOptions = true; // Bash versions differ; an altered trace mode is not a restoration proof.
    }
    const exported = builtin && declaration ? functionExportSelection(info.name, info.args) : null;
    if (exported) {
      for (const name of exported.names) state.exportedFunctions.add(name);
      state.exportedFunctionUnknown ||= exported.unknown;
    }
    if (c.scope.functionBody && !declarationQuery && ['local', 'declare', 'typeset'].includes(info.name) &&
        !declOptions.some((option) => /^-[A-Za-z]*g[A-Za-z]*$/.test(option))) {
      for (const word of info.args.slice(declOptions.length)) {
        const declared = /^([A-Za-z_][A-Za-z0-9_]*)(?:=|$)/.exec(word.text);
        if (declared) state.localNames.add(declared[1]);
      }
    }
    const integerDeclaration = !declarationQuery && declOptions.some((option) => /^-[A-Za-z]*i[A-Za-z]*$/.test(option));
    const associativeDeclaration = !declarationQuery && declOptions.some((option) => /^-[A-Za-z]*A[A-Za-z]*$/.test(option));
    if (builtin && !declarationQuery && ['declare', 'typeset', 'local'].includes(info.name) &&
        declOptions.some((option) => /^-[A-Za-z]*n[A-Za-z]*$/.test(option))) {
      state.valuesTainted = true;
      for (const name of state.identitySources.keys()) state.identitySources.set(name, null);
      for (const word of info.args.slice(declOptions.length)) {
        const name = /^([A-Za-z_][A-Za-z0-9_]*)(?:=|$)/.exec(word.text)?.[1];
        if (name) state.promptRefNames.add(name);
      }
    }
    const valueWords = c.words.filter((word) => info.assignRaws.includes(word.raw))
      .concat(declaration && !declarationQuery ? info.args : []);
    for (const word of valueWords) {
      const assignment = scalarAssignment(word);
      const prefix = info.assignRaws.includes(word.raw) && !info.args.includes(word);
      const valueConditional = conditional || (!!info.name && prefix);
      const canRemember = prefix ? ((!info.name && !info.dynamicName && !info.wrapped) || info.persistsEnv ||
        (builtin && SPECIAL_BUILTINS.has(info.name))) : persistentValues;
      if (assignment && canRemember && state.promptRefNames.has(assignment.name)) state.identitySources.set('PS4', null);
      if (assignment && canRemember && trackedEnv(assignment.name)) {
        const prior = state.identityExports.get(assignment.name) ?? false;
        const selected = state.functionAutoExport === true ? true : state.functionAutoExport === false ? prior : prior === true ? true : null;
        state.identityExports.set(assignment.name, conditional && prior !== selected ? null : selected);
        const value = literalScalarWord(word, expansionState);
        const prefixLength = assignment.name.length + (assignment.name === 'PS4' && assignment.append ? 2 : 1);
        let selectedWord = commitInlineValue(value, value, value.text.slice(prefixLength), prefixLength);
        if (assignment.name !== 'PS4' && assignment.append) {
          const previous = state.identitySources.get(assignment.name);
          const literal = w => w && (typeof w.literalValue === 'string' ? w.literalValue : !w.dynamic ? w.text : null);
          const added = commitInlineValue(value, value, value.text.slice(assignment.name.length + 2), assignment.name.length + 2);
          const priorValue = literal(previous), addedValue = literal(added);
          // Appending cannot turn an unproved inherited/generated source into
          // ordinary bytes. Unsupported composed producer spans stay unknown.
          selectedWord = typeof priorValue === 'string' && typeof addedValue === 'string' ?
            { ...added, text: priorValue + addedValue, literalValue: priorValue + addedValue, dynamic: false } : null;
        }
        if (assignment.name === 'PS4' && assignment.append) {
          const previous = state.identitySources.get('PS4');
          const literal = w => w && (typeof w.literalValue === 'string' ? w.literalValue : !w.dynamic ? w.text : null);
          const priorValue = literal(previous), addedValue = literal(selectedWord);
          selectedWord = typeof priorValue === 'string' && typeof addedValue === 'string' ?
            { ...selectedWord, text: priorValue + addedValue, literalValue: priorValue + addedValue, dynamic: false } : null;
        }
        state.identitySources.set(assignment.name, conditional ? null : selectedWord);
      }
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
    if (declaration && !declarationQuery) {
      const attributeArgs = info.name === 'export' ? info.args.map(word => {
        const value = literalScalarWord(word, expansionState);
        return typeof value.literalValue === 'string' && value.dynamicMaySplit === false
          ? { ...value, text: value.literalValue, dynamic: false } : value;
      }) : info.args;
      const attributeOptions = declarationOptions(attributeArgs);
      const has = (sign, flag) => attributeOptions.some(option => option[0] === sign && option.slice(1).includes(flag));
      const functionMode = has('-', 'f') || has('-', 'F');
      const query = has('-', 'p') || info.name === 'export' && info.args.length === 0;
      const exportOptionUnknown = info.name === 'export' &&
        (attributeOptions.some(option => option[0] !== '-' || /[^fnp]/.test(option.slice(1))) ||
          (attributeArgs[attributeOptions.length]?.dynamic &&
            !/^[A-Za-z_][A-Za-z0-9_]*(?:=|$)/.test(attributeArgs[attributeOptions.length].text)));
      const selection = info.name === 'export' ? exportOptionUnknown ? null : !has('-', 'n') : has('-', 'x') ? true : has('+', 'x') ? false : undefined;
      if (!functionMode && !query && selection !== undefined) {
        let start = attributeOptions.length;
        if (attributeArgs[start]?.text === '--') start++;
        for (const word of attributeArgs.slice(start)) {
          if (info.name === 'export' && word.dynamic && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(word.text)) {
            for (const name of state.identitySources.keys()) state.identityExports.set(name, null);
            state.outboundEnvironmentUnknown = true;
            continue;
          }
          const name = /^([A-Za-z_][A-Za-z0-9_]*)(?:=|$)/.exec(word.text)?.[1];
          if (!trackedEnv(name)) continue;
          const prior = state.identityExports.get(name) ?? false;
          state.identityExports.set(name, conditional && prior !== selection ? null : selection);
          if (!state.identitySources.has(name)) state.identitySources.set(name, null);
        }
      }
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
          state.identitySources.set('PS4', null);
          // An unresolved target can replace config roots or command lookup, even for a later Git read.
          for (const root of CONFIG_ROOT_ENV) state.env.add(root);
          for (const name of HELPER_SOURCE_ENV) state.helperEnv.add(name);
          state.pathChanged = true;
        }
        for (const word of read.targets) {
          const target = /^([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?$/.exec(word.text);
          if (!target) continue;
          if (affectsGitEnvironment(target[1])) state.env.add(target[1]);
          if (HELPER_SOURCE_ENV.has(target[1])) state.helperEnv.add(target[1]);
          if (target[1] === 'PATH' || target[1] === 'FPATH') state.pathChanged = true;
        }
      }
      if (info.args.some((word) => word.dynamic)) { state.valuesTainted = true; state.associatives.clear(); }
      if (info.name === 'unset' && info.args.some(word => word.dynamic)) state.identitySources.set('PS4', null);
      if (!info.args.length && info.name === 'read') state.values.set('REPLY', null);
      for (const word of info.args) {
        const target = /^([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?$/.exec(word.text);
        if (!target) continue;
        if (target[2] !== undefined && !numericArithmetic(target[2], state)) res.problems.push('builtin が評価する配列の添字を検査できない');
        const identityTarget = info.name !== 'read' || readEnvironmentTargets(info.args).targets.includes(word);
        if (info.name === 'read' && identityTarget && state.promptRefNames.has(target[1])) state.identitySources.set('PS4', null);
        if (identityTarget && trackedEnv(target[1])) {
          if (info.name === 'unset' && !conditional) { state.identitySources.delete(target[1]); state.identityExports.delete(target[1]); }
          else state.identitySources.set(target[1], null);
        }
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
        if (state.promptRefNames.has(target[1])) state.identitySources.set('PS4', null);
        if (target[2] !== undefined && !numericArithmetic(target[2], state)) res.problems.push('printf -v が評価する配列の添字を検査できない');
        if (trackedEnv(target[1])) state.identitySources.set(target[1], null);
        if (target[1] === 'PS4') {
          const offset = info.args[0].text === '-v' ? 2 : 1;
          const format = invocation.args[offset], value = invocation.args[offset + 1];
          state.identitySources.set('PS4', !conditional && format && !format.dynamic && format.text === '%s' &&
            invocation.args.length === offset + 2 ? value : null);
        }
        state.values.set(target[1], null);
        state.pathProofs.delete(target[1]);
        if (affectsGitEnvironment(target[1])) state.env.add(target[1]);
        if (HELPER_SOURCE_ENV.has(target[1])) state.helperEnv.add(target[1]);
        if (target[1] === 'PATH' || target[1] === 'FPATH') state.pathChanged = true;
        for (const key of state.values.keys()) if (key.startsWith(target[1] + '[')) state.values.set(key, null);
      }
    }
    if (builtin && info.name === 'getopts') {
      const targetWord = info.args[1];
      const target = targetWord && /^([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?$/.exec(targetWord.text);
      for (const name of ['OPTARG', 'OPTIND', ...(target ? [target[1]] : [])]) {
        if (state.promptRefNames.has(name)) state.identitySources.set('PS4', null);
        if (trackedEnv(name)) state.identitySources.set(name, null);
        if (name === 'PS4') state.identitySources.set(name, null);
        state.values.set(name, null); state.pathProofs.delete(name);
        if (affectsGitEnvironment(name)) state.env.add(name);
        if (HELPER_SOURCE_ENV.has(name)) state.helperEnv.add(name);
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
    if (!info.name && !info.dynamicName && !info.wrapped) {
      state.env = env; state.helperEnv = helperEnv; state.pathChanged = pathChanged;
      state.environmentFunctions = environmentFunctions; state.environmentFunctionUnknown = environmentFunctionUnknown;
    }
    if (info.persistsEnv || (!info.wrapped && SPECIAL_BUILTINS.has(info.name))) {
      for (const a of env) state.env.add(a);
      for (const a of helperEnv) state.helperEnv.add(a);
      state.pathChanged = state.pathChanged || pathChanged;
      for (const [environment, name] of environmentFunctions) state.environmentFunctions.set(environment, name);
      for (const environment of environmentFunctionUnknown) state.environmentFunctionUnknown.add(environment);
    }
    if (info.envUnknown && (gitContext || c.words.some(wordHasGit))) {
      res.problems.push('env の option が不明・曖昧、または値が複数の語になりうるため、git の実行を検査できない');
      return;
    }
    if (info.launcherUnknown && (gitContext || c.words.some(wordHasGit) || info.wrapperNames.some(name => ['timeout', 'nice', 'stdbuf', 'chroot', 'sudo', 'unshare'].includes(name)))) {
      res.problems.push('launcher の option や引数の個数を読みきれず、git の実行先を確かめられない');
      return;
    }
    if (positionalUnknown || (positionalExec && info.name === 'git')) {
      res.problems.push('位置引数から実行する git や不明なコマンドは、引数と実行先を検査できない');
      return;
    }
    if (info.dynamicName) {
      if (info.executableExpansionUnknown) {
        res.problems.push('実行ファイル名に pathname・brace・tilde の展開があり、展開後の実行先と引数を確認できません。目的を保てる literal の実行ファイル名を使い、必要なら owner に対象・操作・cwd/env/config/source と不明点を確認してください。個別操作の了承は hook 無効化の了承ではありません。');
      } else {
        res.problems.push('実行ファイル名が変数・置換・named array などの未確定の展開で作られていて、実行先と argv を確認できません。同目的を保てる literal の実行ファイル名と対応済み引数を使い、必要なら owner に対象・操作・cwd/env/config/source と不明点を確認してください。個別操作の了承は hook 無効化の了承ではありません。');
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
    const selectsLocalFunction = (script) => !script.dynamic && parseShell(script.text).cmds.some((entry) => {
      const selected = resolveCommand(entry.words, state.functions);
      const timed = selected.wrapperNames.length > 0 && selected.wrapperNames.every((name) => name === 'time') &&
        entry.words.some((word, index) => word.text === 'time' && !word.quoted && !word.dynamic && atCmdPos(entry.words.slice(0, index)));
      return (!selected.wrapped || timed) && !selected.nonExec && !selected.dynamicName &&
        selected.nameWord?.text === selected.name && state.functions.has(selected.name);
    });
    const evalWords = name === 'eval' && info.args[0]?.text === '--' && !info.args[0].dynamic ? info.args.slice(1) : info.args;
    const mediatedFunction = (trap && trap.scripts.some(selectsLocalFunction)) ||
      (alias && alias.scripts.some(selectsLocalFunction)) ||
      (name === 'eval' && evalWords.every((word) => !word.dynamic) &&
        selectsLocalFunction({ text: evalWords.map((word) => word.text).join(' '), dynamic: false }));
    if (mediatedFunction) res.problems.push('文字列の実行 source が選ぶ既存の関数の状態・body・呼出し条件を引き継いで検査できない');
    if (builtin && name === 'set') {
      const trace = xtraceSet(invocation.args.map(word => typeof word.literalValue === 'string' ?
        { ...word, text: word.literalValue, dynamic: false, dynamicMaySplit: false } : word), state.xtrace);
      state.xtrace = conditional && trace !== state.xtrace ? null : trace;
      const mode = functionAutoExportSet(info.args, state.functionAutoExport);
      state.functionAutoExport = conditional && mode !== state.functionAutoExport ? null : mode;
      const change = positionalSet(info.args);
      if (change) {
        const words = change.words.flatMap((word) => state.positionals && exactQuotedAt(word) ? state.positionals : [word]);
        updatePositionals(state, c, change.unknown ? null : knownPositionals(words));
      }
      return; // Stored positional operands are data until an executable expansion uses them.
    }
    if (builtin && name === 'shopt') {
      const mode = promptvarsSet(invocation.args, state.promptvars);
      state.promptvars = conditional && mode !== state.promptvars ? null : mode;
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
        const trace = sourceTraceEffects(inner);
        if (trace.prompt) state.identitySources.set('PS4', null);
        if (trace.trace) state.xtrace = null;
        if (trace.promptvars) state.promptvars = null;
        if ((trace.prompt || trace.trace || trace.promptvars) && state.xtrace !== false && state.promptvars !== false &&
            (!state.identitySources.get('PS4') || /[$`]/.test(state.identitySources.get('PS4').text))) {
          res.problems.push('registered trap が変更する PS4/xtrace/promptvars の callback state と後続の prompt source を検査できない');
        }
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
        if (HELPER_SOURCE_ENV.has(nm) && (w.text.includes('=') || !print)) state.helperEnv.add(nm);
        const assignment = scalarAssignment(w);
        const imported = assignment && functionEnvironmentAssignment(w, assignment.name, assignment.value);
        if (imported) {
          if (imported.callee) state.environmentFunctions.set(imported.environment, imported.callee);
          if (imported.unknown) state.environmentFunctionUnknown.add(imported.environment);
        }
        if (nm === 'PATH' || nm === 'FPATH') state.pathChanged = true;
      }
    }
    if (name === 'unset') for (const word of info.args) {
      if (CONFIG_ROOT_ENV.has(word.text)) { state.env.add(word.text); res.gitEnvNames.push(word.text); }
    }
    // unset は && / || の分岐で実行されないことがあるので、永続状態からは消さない。
    if (SHELLS.has(name)) {
      if (shell.terminal) return;
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
            seedScope(inner.scope, env, cdBefore, { ...state, ...childIdentityState(identitySources), outboundEnvironmentUnknown, xtrace: shellXtrace, promptvars: true, helperEnv, pathChanged, functionAutoExport: false, exportedFunctions, exportedFunctionUnknown,
              environmentFunctions, environmentFunctionUnknown,
              functions: new Map((shell.privileged === true && ['bash', 'sh'].includes(name) ? [] : importedFunctionNames)
                .map(name => [name, sourcePlaceholder(name)])), positionals: shell.unknown ? null : knownPositionals(shell.positionals) });
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
                seedScope(inner.scope, env, cdBefore, { ...state, ...childIdentityState(identitySources), outboundEnvironmentUnknown, xtrace: shellXtrace, promptvars: true, helperEnv, pathChanged, functionAutoExport: false, exportedFunctions, exportedFunctionUnknown,
                  environmentFunctions, environmentFunctionUnknown,
                  functions: new Map((shell.privileged === true && ['bash', 'sh'].includes(name) ? [] : importedFunctionNames)
                    .map(name => [name, sourcePlaceholder(name)])), positionals: shell.unknown ? null : knownPositionals(shell.positionals) });
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
          seedScope(scope, env, cdBefore, { ...state, helperEnv, pathChanged, exportedFunctions, exportedFunctionUnknown,
            environmentFunctions, environmentFunctionUnknown });
          visit({ words: info.args.slice(k + 1, e), redirs: [], piped: false, heredocBodies: [], scope, effects: c.effects }, sub, depth + 1);
          k = e;
        }
      }
      return;
    }
    const directOperation = directGitOperation(name);
    if (name !== 'git' && !directOperation) {
      // Literal printf/echo argv is data, including in a tuple or inspected source string.
      if (['echo', 'printf'].includes(name) &&
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
          seedScope(scope, env, cdBefore, { ...state, helperEnv, pathChanged, exportedFunctions, exportedFunctionUnknown,
            environmentFunctions, environmentFunctionUnknown });
          const sub = resolveCommand(tail);
          sub.incomplete = info.incomplete || sub.incomplete;
          visit({ words: tail, redirs: [], piped: false, heredocBodies: [], scope, effects: c.effects,
            gitNamespaceInferred: true }, sub, depth + 1);
        }
      }
      return;
    }
    const gitWords = info.args.map((word, index) => {
      const proven = literalScalarWord(word, state);
      return info.args[index - 1]?.text === '-c' && typeof proven.literalValue === 'string' &&
        /^(?:user|author|committer)\.(?:name|email)=/i.test(proven.literalValue)
        ? { ...proven, text: proven.literalValue, dynamic: false, dynamicMaySplit: false } : word;
    });
    const g = directOperation ? { ...parseGit([]), sub: directOperation, args: gitWords, directHelper: true } : parseGit(gitWords);
    // The legacy token fallback protects risky Git-looking wrappers; it does not
    // prove that a reader's argv token is an actual executable Git identity.
    g.gitNamespaceInferred = Boolean(c.gitNamespaceInferred);
    g.gitNamespaceUnknown = Boolean(!g.gitNamespaceInferred && g.sub && !REGISTERED_GIT_OPERATIONS.has(g.sub));
    if (g.problems.length) { res.problems.push(...g.problems); return; }
    g.args = g.args.map(word => literalScalarWord(word, state));
    g.gitConfigurationSources = invocation.gitConfigurationSources;
    const environmentConfig = gitConfigurationEntries(g.gitConfigurationSources || []);
    const environmentSelections = environmentConfig.entries.map(entry => ({ mode: 'configuration-env', text: entry.key + '=GIT_CONFIG_VALUE_' + entry.index, word: entry.word }));
    g.configSelections.unshift(...environmentSelections);
    g.configEnvs.unshift(...environmentSelections.map(entry => entry.text));

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
    g.outboundRole = gitOutboundRole(g);
    g.operationRole = gitOperationRole(g);
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
    if ((!directOperation && !trustedGitExecutable(info.nameWord)) || pathChanged || state.searchChanged || state.gitShadowed) {
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
    if (g.dynamicOpt && !(g.sub && READ_ONLY_SUBS.has(g.sub)) &&
        !(gitHttpMetadataGlobalBoundary(g) && (['clone', 'fetch', 'pull', 'push', 'ls-remote', 'http-push', 'http-fetch', 'remote', 'submodule'].includes(g.sub) || g.sub === 'config' && readOnlyGitMode(g, false, true)))) {
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
    g.helperEnvNames = [...helperEnv];
    g.gitIdentitySources = invocation.gitIdentitySources;
    g.gitPagerEnvSources = invocation.gitPagerEnvSources;
    g.gitConfigurationSources = invocation.gitConfigurationSources;
    g.gitHttpMetadataSources = invocation.gitHttpMetadataSources;
    g.gitTransportSources = invocation.gitTransportSources;
    for (const config of g.configSelections) if (config.mode === 'env') {
      const variable = config.text.slice(config.text.indexOf('=') + 1);
      const carrier = c.words.find(word => info.assignRaws.includes(word.raw) && word.text.startsWith(variable + '='));
      if (carrier) {
        const value = literalScalarWord(carrier, expansionState);
        config.word = commitInlineValue(value, value, value.text.slice(variable.length + 1), variable.length + 1);
        config.prefixSourceKnown = true;
      } else {
        const value = !state.valuesTainted && state.values.get(variable);
        config.word = typeof value === 'string' ? { text: value, dynamic: false, dynamicMaySplit: false, literalValue: value } : null;
      }
    }
    g.cdLikeBefore = cdBefore;
    g.httpCookieRole = gitHttpCookieRole(g);
    g.httpMetadataRole = gitHttpMetadataRole(g);
    g.transportSourceRole = gitTransportSourceRole(g);
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
      // Actual stdout usage does not execute the subcommand; other independent gates still apply.
      if (g.terminal && g.helpKind === 'stdout') continue;
      const cfgs = g.configs.concat(g.configEnvs);
      if (cfgs.some((v) => v.includes(DYN))) {
        res.problems.push('commit や add と同じコマンドの git の -c / --config-env の値が変数や置換で作られていて、読みきれない');
        break;
      }
      const bad = cfgs.find((v) => !configKeyAllowed(v));
      if (bad) {
        res.problems.push(
          `commit や add と同じコマンドの git の -c / --config-env の鍵（${configKey(bad)}）は、allowlist の外なので検査できない` +
          '（使える鍵: core.quotepath・color.*・advice.*・user/author/committer の name/email）',
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
  if (!g.sub || g.directHelper || BUILTIN_SUBS.has(g.sub)) return null;
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

/** Preserve a message value's exact source span and strip only its known option carrier. */
function commitInlineValue(carrier, value, attached, prefixLength) {
  if (!value || attached === null) return value || null;
  const selected = { ...value, text: attached };
  if (typeof value.literalValue === 'string') selected.literalValue = value.literalValue.slice(prefixLength);
  // raw/start still cover the original word so substitution producers remain associated.
  return selected;
}

/** Identify commit-time staging and pathspecs while accepting single-word dynamic option values. */
function parseCommitArgs(words) {
  const r = { all: false, patch: false, fromFile: false, noVerify: false, terminal: false, dynamic: false, unknown: [], pathspecs: [],
    messageFiles: [], inlineMessageWords: [], inlineObjectWords: [], messageFileUnknown: false, messageFileSelectionUnknown: false, editorMayRun: true, signingSelected: false };
  const identityWords = new Map();
  const trailerWords = [];
  let inlineMessage = false;
  let reusedMessage = false;
  let sourceOverride = false;
  let editorDefault = true;
  let editorSelection = null;
  let editorSourceUnknown = false;
  let dryRun = false;
  const finish = () => {
    r.inlineObjectWords = [...r.inlineMessageWords.map(word => ({ kind: 'message', word })),
      ...[...identityWords].map(([kind, word]) => ({ kind, word })), ...trailerWords];
    r.messageFileUnknown = r.dynamic || r.unknown.length > 0 || r.messageFiles.some((source) => source.unknown);
    r.messageFileSelectionUnknown = r.messageFiles.length > 1 ||
      (r.messageFiles.length > 0 && (inlineMessage || reusedMessage || sourceOverride));
    r.editorMayRun = !r.terminal && (r.dynamic || r.unknown.length > 0 || editorSourceUnknown ||
      (!dryRun && (editorSelection === null ? editorDefault : editorSelection)));
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
      if (full === 'message') {
        inlineMessage = true;
        r.inlineMessageWords.push(commitInlineValue(w, eq < 0 ? words[k + 1] : w, eq < 0 ? null : t.slice(eq + 1), eq < 0 ? 0 : eq + 1));
      }
      if (['author', 'date', 'trailer'].includes(full)) {
        const value = commitInlineValue(w, eq < 0 ? words[k + 1] : w, eq < 0 ? null : t.slice(eq + 1), eq < 0 ? 0 : eq + 1);
        if (full === 'trailer') trailerWords.push({ kind: 'trailer', word: value });
        else identityWords.set(full, value);
      }
      if (['reedit-message', 'reuse-message'].includes(full)) reusedMessage = true;
      if (['no-file', 'no-template', 'no-message', 'no-reedit-message', 'no-reuse-message'].includes(full)) sourceOverride = true;
      if (full === 'all') r.all = true;
      if (full === 'patch' || full === 'interactive') r.patch = true;
      if (full === 'pathspec-from-file') r.fromFile = true;
      if (full === 'no-verify') r.noVerify = true;
      if (full === 'gpg-sign' || full === 'no-gpg-sign') r.signingSelected = full === 'gpg-sign';
      const takesValue = !full.startsWith('no-') && (kind.startsWith('v') || kind.startsWith('o'));
      if (w.dynamic && !takesValue) r.dynamic = true;
      if (['message', 'file', 'reuse-message', 'reedit-message'].includes(full)) {
        const value = eq < 0 ? words[k + 1] : { ...w, text: t.slice(eq + 1) };
        if (!value || value.dynamicMaySplit || value.ansiCUnknown || value.globExpanded || value.braceExpanded || value.tildeExpanded) editorSourceUnknown = true;
        editorDefault = full === 'reedit-message';
      }
      if (['template', 'fixup', 'squash'].includes(full) || full.startsWith('no-') &&
          ['message', 'file', 'template', 'reedit-message', 'reuse-message'].includes(base)) editorDefault = true;
      if (full === 'edit' || full === 'no-edit') editorSelection = full === 'edit';
      if (full === 'dry-run' || full === 'no-dry-run') dryRun = full === 'dry-run';
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
          if (ch === 'm') {
            inlineMessage = true;
            r.inlineMessageWords.push(commitInlineValue(w, p + 1 < t.length ? w : words[k + 1], p + 1 < t.length ? t.slice(p + 1) : null, p + 1 < t.length ? p + 1 : 0));
          }
          if (ch === 'c' || ch === 'C') reusedMessage = true;
          if (['m', 'F', 'C', 'c'].includes(ch)) {
            const value = p + 1 < t.length ? { ...w, text: t.slice(p + 1) } : words[k + 1];
            if (!value || value.dynamicMaySplit || value.ansiCUnknown || value.globExpanded || value.braceExpanded || value.tildeExpanded) editorSourceUnknown = true;
            editorDefault = ch === 'c';
          }
          if (ch === 't') editorDefault = true;
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
        if (COMMIT_SHORT_ATTACHED.has(ch)) { if (ch === 'S') r.signingSelected = true; break; }
        if (ch === 'a') r.all = true;
        if (ch === 'p') r.patch = true;
        if (ch === 'n') r.noVerify = true;
        if (ch === 'e') editorSelection = true;
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
  const r = { terminal: false, messageFiles: [], messageFileUnknown: false, messageFileSelectionUnknown: false, editorMayRun: true,
    signingSelected: false, verificationSelected: false };
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
  let editorSelected = true;
  const finish = () => {
    r.messageFileUnknown = unknown || r.messageFiles.some((source) => source.unknown);
    r.messageFileSelectionUnknown = r.messageFiles.length > 1 ||
      (r.messageFiles.length > 0 && (inlineMessage || sourceOverride));
    r.editorMayRun = !r.terminal && (unknown || editorSelected);
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
      if (option === 'gpg-sign' || option === 'no-gpg-sign') r.signingSelected = option === 'gpg-sign';
      if (option === 'verify-signatures' || option === 'no-verify-signatures') r.verificationSelected = option === 'verify-signatures';
      if (option === 'edit' || option === 'no-edit') editorSelected = option === 'edit';
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
        if (ch === 'S') { r.signingSelected = true; break; } // Its key is optional and attached only.
        if (ch === 'e') editorSelected = true;
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

/** Classify hash-object option roles without executing input or configured filters. */
function parseHashObjectRoute(g) {
  let unknown = !!(g.incomplete || g.dynamicOpt);
  let write = false;
  let terminal = false;
  let afterDD = false;
  const flags = new Set(['stdin', 'no-stdin', 'stdin-paths', 'no-stdin-paths',
    'filters', 'no-filters', 'literally', 'no-literally', 'no-path']);
  const longNames = [...flags, 'path', 'help'];
  const uncertain = word => !word || word.dynamic || word.dynamicMaySplit || word.ansiCUnknown ||
    word.braceExpanded || word.globExpanded || word.tildeExpanded;
  for (let i = 0; i < g.args.length; i++) {
    const word = g.args[i];
    const text = word.text;
    if (uncertain(word)) unknown = true;
    if (afterDD) continue;
    if (text === '--') { afterDD = true; continue; }
    if (text === '-h' || text === '--help') { terminal = true; break; }
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      const name = text.slice(2, eq < 0 ? undefined : eq);
      const matches = longNames.filter(option => option.startsWith(name));
      const option = longNames.includes(name) ? name : matches.length === 1 ? matches[0] : null;
      if (!option) { unknown = true; continue; }
      if (option === 'help') { terminal = true; if (eq >= 0) unknown = true; break; }
      if (option === 'path') {
        if (eq < 0 && uncertain(g.args[++i])) unknown = true;
      } else if (eq >= 0) unknown = true;
      continue;
    }
    if (text.startsWith('-') && text !== '-') {
      for (let j = 1; j < text.length; j++) {
        const option = text[j];
        if (option === 'w') write = true;
        else if (option === 'h') { terminal = true; break; }
        else if (option === 't') {
          if (j + 1 === text.length && uncertain(g.args[++i])) unknown = true;
          break; // The rest of this bundle, or the next word, is the type value.
        } else unknown = true;
      }
      if (terminal) break;
    }
  }
  const mode = unknown ? 'unknown' : terminal ? 'terminal' : write ? 'write' : 'query';
  return { mode, action: 'hash-object', writesObject: write, messageFiles: [],
    messageFileUnknown: unknown, messageFileSelectionUnknown: unknown,
    reason: mode === 'unknown' ? 'hash-object の argv・option 境界や object 書込みの選択を確認できない' : null };
}

/** Select supported object-route queries and the file operands of object writers. */
function parseGitObjectRoute(g, parseMessages = parseCommitArgs) {
  if (g.sub === 'hash-object') return parseHashObjectRoute(g);
  if (g.sub === 'stash') return parseStashRoute(g);
  if (g.sub === 'mktag') return { mode: g.terminal && g.helpKind === 'stdout' ? 'terminal' : 'write',
    action: 'mktag', messageFiles: [], messageFileUnknown: false, messageFileSelectionUnknown: false };
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
  if (objectRoute && g.sub === 'mktag') return { category: 'UNKNOWN', reason: 'git mktag は stdin から未検査の tag object を object database に書き込みます。staged filename 検査では message・入力 object・実行条件を確認できません。必要なら owner に対象・操作・cwd/env/config/source と不明点を確認してください。個別操作の承認は hook 無効化の承認ではありません。' };
  if (objectRoute && g.sub === 'hash-object') return { category: 'UNKNOWN', reason: 'git hash-object の object database 書込み、または書込みを選べる未確定の argv は staged 検査の対象外で、blob/tree/commit/tag の入力内容・対象・実行条件を確認できません。hash-only 形式は書込みと同目的の代替ではありません。書込みが必要なら owner に対象・操作・cwd/env/config/source と不明点を確認してください。個別操作の了承は hook 無効化の了承ではありません。' };
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
  preCommitConfigKey,
  messageFileSource,
  grepPagerEffect,
  gitTypedArguments,
  gitOperationRole,
  gitHttpCookieRole,
  gitHttpMetadataRole,
  gitTransportSourceRole,
  parseAddArgs,
  isSecretPath,
  readOnlyGitMode,
  READ_ONLY_SUBS,
};
