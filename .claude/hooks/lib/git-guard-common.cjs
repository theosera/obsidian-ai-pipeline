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

/** Emit Claude Code's deny response and stop without allowing an uncaught hook error. */
function deny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
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

/** Scan one expansion and collect executable substitutions in child shell scopes. */
function scanExpansion(src, i, out, depth, scope) {
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
    parseSeq(inner, 0, out, depth + 1, false, { parent: scope });
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
      scanSubsts(src.slice(i + 3, j), out, depth + 1, scope);
      return { end: j + 2, dynamic: true };
    }
    const close = parseSeq(src, i + 2, out, depth + 1, true, { parent: scope });
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
    scanSubsts(src.slice(i + 2, j), out, depth + 1, scope);
    return { end: j + 1, dynamic: true };
  }
  if (c1 === '{') {
    let j = i + 2;
    let d = 0;
    let multiWord = false;
    while (j < n) {
      const ch = src[j];
      if (ch === '\\') { j += 2; continue; }
      if (ch === "'") {
        const q = src.indexOf("'", j + 1);
        if (q < 0) { j = n; break; }
        // 外側が二重引用の ${…} では、この単一引用内の置換も実行されうる。
        multiWord = scanSubsts(src.slice(j + 1, q), out, depth + 1, scope) || multiWord;
        j = q + 1;
        continue;
      }
      if (ch === '"') {
        j++;
        while (j < n && src[j] !== '"') {
          if (src[j] === '\\') { j += 2; continue; }
          if (src[j] === '$' || src[j] === '`') {
            const r = scanExpansion(src, j, out, depth + 1, scope);
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
        const r = scanExpansion(src, j, out, depth + 1, scope);
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
    // "$@"・"${a[@]}"・"${!prefix@}" は、二重引用されていても複数の語になりうる。
    multiWord = multiWord || /\[@\]/.test(body) || /^@(?::|$)/.test(body) || /^![A-Za-z_][A-Za-z0-9_]*@$/.test(body);
    return { end: j + 1, dynamic: true, multiWord };
  }
  if (c1 === "'") {
    // $'…'（escape を解く文字列）。中身は実行されないが、語の文字は決めない。
    let j = i + 2;
    while (j < n && src[j] !== "'") {
      if (src[j] === '\\') j++;
      j++;
    }
    if (j >= n) { out.errors.push("閉じていない $'…'"); return { end: n, dynamic: true }; }
    return { end: j + 1, dynamic: true, noSplit: true };
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
function scanSubsts(text, out, depth, scope) {
  let k = 0;
  let multiWord = false;
  while (k < text.length) {
    const ch = text[k];
    if (ch === '\\') { k += 2; continue; }
    if (ch === '$' || ch === '`') {
      const r = scanExpansion(text, k, out, depth, scope);
      multiWord = multiWord || !!r.multiWord;
      k = r.end;
      continue;
    }
    k++;
  }
  return multiWord;
}

/**
 * Tokenize a shell sequence into commands with scope metadata and redirections.
 * For substitutions, stop at the unmatched closing parenthesis; otherwise consume the source.
 */
function parseSeq(src, start, out, depth, stopAtParen, scope) {
  const n = src.length;
  if (depth > MAX_DEPTH) { out.errors.push('入れ子が深すぎる'); return n; }
  let i = start;
  let words = [];
  let cur = null;
  let parenDepth = 0;
  // 開いている括弧の種類（'sub' = コマンドの位置のサブシェル・'other' = それ以外・v3.5.2）。
  const parenKinds = [];
  const parenScopes = [];
  let redirNext = null;
  let redirs = [];
  let piped = false;
  const heredocs = [];

  const startWord = () => {
    if (!cur) cur = { text: '', dynamic: false, dynamicMaySplit: false, quoted: false, start: i };
  };
  const endWord = () => {
    if (!cur) return;
    cur.raw = src.slice(cur.start, i);
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
      const c = { words, redirs, piped, heredocBodies: [], scope };
      out.cmds.push(c);
      for (const h of heredocs) if (!h.cmd) h.cmd = c;
    }
    words = [];
    redirs = [];
    piped = false;
  };
  const appendExpansion = (r, quoted = false) => {
    if (r.dynamic) {
      cur.dynamic = true;
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
      if (i + 1 < n) { cur.text += src[i + 1]; i += 2; } else { i++; }
      continue;
    }
    if (c === "'") {
      startWord();
      cur.quoted = true;
      const j = src.indexOf("'", i + 1);
      if (j < 0) { out.errors.push("閉じていない '…'"); return n; }
      cur.text += src.slice(i + 1, j);
      i = j + 1;
      continue;
    }
    if (c === '"') {
      startWord();
      cur.quoted = true;
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
          const r = scanExpansion(src, i, out, depth, scope);
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
      const r = scanExpansion(src, i, out, depth, scope);
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
        if (!h.quoted) scanSubsts(body, out, depth + 1, scope);
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
      const isPipe = c === '|' && src[i + 1] !== '|';
      endCmd();
      piped = isPipe;
      if ((c === ';' || c === '|' || c === '&') && src[i + 1] === c) i += 2;
      else if (c === '|' && src[i + 1] === '&') i += 2;
      else i++;
      continue;
    }
    if (c === '(') {
      // `(` と `(` の間の行の継続: シェルは `((` と読む（v3.5.2）。
      if (joinedByLC(src, i + 1, '(')) out.errors.push('( と ( の間に行の継続がある');
      // コマンドの頭（予約語の後を含む・v3.5.2）か `for` の後の `((…))` は算術（v3.5）。シェルと同じく対の `))` まで
      // 生の文字として読み、中の置換だけを読む（`<<` はシフトでヒアドキュメントではない）。対にならなければ括弧として読む。
      const atCmd = !cur && atCmdPos(words);
      const arithAt = atCmd || (!cur && words.length === 1 && !words[0].quoted && words[0].text === 'for');
      if (src[i + 1] === '(' && arithAt) {
        const end = arithEnd(src, i + 2);
        if (end >= 0) {
          scanSubsts(src.slice(i + 2, end), out, depth + 1, scope);
          i = end + 2;
          continue;
        }
      }
      // サブシェルとみるのは、コマンドの位置の `(`（`((` でない）だけ（v3.5.2）。語の後の `(`（zsh の glob など）や
      // 算術にならなかった `((` の外側の中では、`<<` がヒアドキュメントかをシェルと同じに決められない。
      parenKinds.push(atCmd && src[i + 1] !== '(' ? 'sub' : 'other');
      endCmd();
      parenScopes.push(scope);
      scope = { parent: scope };
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
      if (parenDepth > 0) { parenDepth--; parenKinds.pop(); scope = parenScopes.pop(); }
      i++;
      continue;
    }
    if (c === '<' || c === '>' || c === '&') {
      // `<` と `<` の間の行の継続: シェルは `<<` と読む（v3.5.2）。
      if (c === '<' && joinedByLC(src, i + 1, '<')) out.errors.push('< と < の間に行の継続がある');
      if ((c === '<' || c === '>') && src[i + 1] === '(') {
        // プロセス置換 <( … ) / >( … )
        startWord();
        const close = parseSeq(src, i + 2, out, depth + 1, true, { parent: scope });
        if (close >= n) { out.errors.push('閉じていない <( … )'); return n; }
        cur.dynamic = true;
        cur.text += DYN;
        i = close + 1;
        continue;
      }
      // fd の番号（2> など）は語にしない。
      if (cur && !cur.quoted && !cur.dynamic && /^\d+$/.test(cur.text)) cur = null;
      else endWord();
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
    cur.text += c;
    i++;
  }
  endCmd();
  return n;
}

/** Parse shell source without executing it, retaining errors and isolated child scopes. */
function parseShell(src) {
  const out = { cmds: [], errors: [], scope: { parent: null } };
  parseSeq(src, 0, out, 0, false, out.scope);
  return out;
}

// ---------------------------------------------------------------------------
// コマンドの名前（ラッパーを外す）
// ---------------------------------------------------------------------------

const RESERVED = new Set(['!', '{', '}', 'then', 'else', 'elif', 'fi', 'do', 'done', 'if', 'while', 'until']);
/** Assignment syntax is recognized from source, where quoting can change its shell meaning. */
const isAssignWord = (w) => /^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(w.raw);
/** Extract the variable name from an assignment, including the shell's += form. */
const assignName = (w) => w.raw.split('=')[0].replace(/\+$/, '');

const WRAPPERS = {
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
    let k = 0;
    while (k < rest.length) {
      const t = rest[k].text;
      if (t === '--') { k++; break; }
      if (['-', '-i', '--ignore-environment'].includes(t)) { info.envOps.push({ clear: true }); k++; continue; }
      if (['-0', '--null', '-v', '--debug'].includes(t)) { k++; continue; }
      if (t === '-u' || t === '--unset') {
        if (rest[k + 1] && !rest[k + 1].dynamic) info.envOps.push({ unset: rest[k + 1].text });
        k += 2; continue;
      }
      if (t === '-P') { k += 2; continue; }
      if (/^--unset=/.test(t) || /^-u./.test(t)) {
        if (!rest[k].dynamic) info.envOps.push({ unset: t.startsWith('--') ? t.slice(8) : t.slice(2) });
        k++; continue;
      }
      if (t === '-C' || t === '--chdir') { info.cdLike = true; k += 2; continue; }
      if (/^--chdir=/.test(t) || /^-C./.test(t)) { info.cdLike = true; k++; continue; }
      if (t === '-S' || t === '--split-string') { info.splitString = true; k += 2; continue; }
      if (/^--split-string=/.test(t) || /^-S./.test(t)) { info.splitString = true; k++; continue; }
      if (t.startsWith('-')) { k++; continue; }
      break;
    }
    // env 自身が読む代入はシェルの代入語と違い、引用された NAME=value も有効。
    while (k < rest.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[k].text)) {
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
    let k = 0;
    while (k < rest.length && rest[k].text.startsWith('-')) {
      const t = rest[k].text;
      if (t === '--') { k++; break; }
      if (/^-[adEILnPs]$/.test(t)) k++;
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
    envOps: [], wrapped: false, persistsEnv: false,
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
  'am', 'push', 'remote', 'config',
]);

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'fish']);
const CD_LIKE = new Set(['cd', 'pushd', 'popd']);
const EXPORT_LIKE = new Set(['export', 'declare', 'typeset', 'local', 'readonly']);
// POSIX モードでは prefix の代入が、通常のコマンドと違い special builtin の後にも残る。
const SPECIAL_BUILTINS = new Set([':', '.', 'break', 'continue', 'eval', 'exit', 'export', 'readonly', 'return', 'set', 'shift', 'times', 'trap', 'unset']);

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
    dynamicOpt: false, terminal: false, problems: [], pathspecFlags: [],
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
      if (v.dynamic) g.dynamicOpt = true;
      if (t === '-C') g.cdirs.push(v.text); else g.configs.push(v.text);
      k += 2;
      continue;
    }
    if (GIT_FLAG_OPTS.has(t)) {
      if (PATHSPEC_FLAG_OPTS.has(t)) g.pathspecFlags.push(t);
      k++;
      continue;
    }
    if (GIT_TERMINAL_OPTS.has(t)) { g.terminal = true; return g; }
    const eq = t.indexOf('=');
    const name = eq < 0 ? t : t.slice(0, eq);
    if (GIT_VALUE_OPTS.has(name) || (name === '--exec-path' && eq >= 0) || (name === '--list-cmds' && eq >= 0)) {
      let value;
      if (eq >= 0) { value = t.slice(eq + 1); k++; } else {
        const v = args[k + 1];
        if (!v) { g.problems.push(`git の ${t} に値が無い`); return g; }
        if (v.dynamic) g.dynamicOpt = true;
        value = v.text;
        k += 2;
      }
      if (name === '--git-dir') g.gitDir = true;
      if (name === '--work-tree') g.workTree = true;
      if (name === '--config-env') g.configEnvs.push(value);
      if (name === '--list-cmds') { g.terminal = true; return g; }
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

/** Inspect executable Git invocations, associating preceding scope changes with each invocation. */
function inspect(cmd) {
  const res = {
    gits: [], problems: [], cdLike: false, gitEnvNames: [], cmdCount: 0,
  };
  const normalized = cmd.replace(/['"\\]/g, '');
  const gitContext = hasGitText(normalized);
  // CR（\r）を含むコマンドは、シェルと同じに語へ分けられる保証が無い（v3・fail-closed）。
  if (cmd.includes('\r') && gitContext) {
    res.problems.push('コマンドに CR（\\r）があり、シェルと同じに語へ分けられる保証が無い');
  }
  const parsed = parseShell(cmd);
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
  const gitInAssign = assignRawsAll.some((raw) => hasGitText(raw.slice(raw.indexOf('=') + 1)));

  // スコープの状態は最初のコマンドを訪れた時に親から写す。置換とサブシェルの変更は親へ戻さない。
  const scopeStates = new Map();
  const copyState = (s) => ({ env: new Set(s.env), cd: s.cd });
  const stateFor = (scope) => {
    if (!scopeStates.has(scope)) {
      scopeStates.set(scope, scope && scope.parent ? copyState(stateFor(scope.parent)) : { env: new Set(), cd: false });
    }
    return scopeStates.get(scope);
  };
  const seedScope = (scope, env, cd) => scopeStates.set(scope, { env: new Set(env), cd });

  const visit = (c, info, depth) => {
    if (depth > MAX_DEPTH) { res.problems.push('入れ子が深すぎる'); return; }
    const state = stateFor(c.scope);
    const env = new Set(state.env);
    for (const op of info.envOps) {
      if (op.clear) env.clear();
      if (op.unset) env.delete(op.unset);
      if (op.set && /^GIT_/.test(op.set)) env.add(op.set);
    }
    const cdBefore = state.cd || info.cdLike;
    if (info.cdLike) res.cdLike = true;
    for (const a of info.assigns) if (/^GIT_/.test(a) && !res.gitEnvNames.includes(a)) res.gitEnvNames.push(a);
    if (!info.name && !info.dynamicName && !info.wrapped) state.env = env;
    if (info.persistsEnv || (!info.wrapped && SPECIAL_BUILTINS.has(info.name))) {
      for (const a of env) state.env.add(a);
    }
    if (info.dynamicName) {
      const first = info.args[0];
      if (wordHasGit(info.nameWord) || gitInAssign ||
          info.args.some((w) => !w.dynamic && path.posix.basename(w.text) === 'git') ||
          (first && !first.dynamic && RISKY_SUBS.has(first.text))) {
        res.problems.push('コマンドの名前が変数や置換で作られていて、git かどうかを決められない');
      }
      return;
    }
    if (info.splitString && c.words.some(wordHasGit)) {
      res.problems.push('env -S の文字列に入れた git は、中身を検査できない');
    }
    if (!info.name || info.nonExec) return;
    const name = info.name;
    if (CD_LIKE.has(name)) { res.cdLike = true; state.cd = true; }
    if (EXPORT_LIKE.has(name)) {
      for (const w of info.args) {
        const nm = w.text.split('=')[0];
        if (/^GIT_/.test(nm)) { res.gitEnvNames.push(nm); state.env.add(nm); }
      }
    }
    // unset は && / || の分岐で実行されないことがあるので、永続状態からは消さない。
    if (SHELLS.has(name)) {
      const ci = info.args.findIndex((w) => /^-[A-Za-z]*c[A-Za-z]*$/.test(w.text) || w.text === '--command');
      if (ci >= 0) {
        const script = info.args[ci + 1];
        if (script && (wordHasGit(script) || (script.dynamic && gitContext))) {
          res.problems.push(`${name} -c の文字列に入れた git は、中身を検査できない`);
        }
      } else {
        // 標準入力（ヒアドキュメント・here-string・パイプ）から読むシェル。
        const reads = info.args.every((w) => w.text.startsWith('-'));
        if (reads) {
          for (const h of c.heredocBodies) {
            const inner = parseShell(h.body);
            seedScope(inner.scope, env, cdBefore);
            if (inner.errors.length && hasGitText(h.body)) {
              res.problems.push(`${name} に流すヒアドキュメントを読みきれない`);
            }
            for (const ic of inner.cmds) visit(ic, resolveCommand(ic.words), depth + 1);
          }
          for (const r of c.redirs) {
            if (r.op === '<<<' && wordHasGit(r.word)) {
              if (r.word.dynamic) res.problems.push(`${name} に流す文字列の git は、中身を検査できない`);
              else {
                const inner = parseShell(r.word.text);
                seedScope(inner.scope, env, cdBefore);
                if (inner.errors.length) res.problems.push(`${name} に流す文字列の git を読みきれない`);
                for (const ic of inner.cmds) visit(ic, resolveCommand(ic.words), depth + 1);
              }
            }
          }
          if (c.piped && gitContext) {
            res.problems.push(`パイプで ${name} に流したコマンドは、中身を検査できない`);
          }
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
          seedScope(scope, env, cdBefore);
          visit({ words: info.args.slice(k + 1, e), redirs: [], piped: false, heredocBodies: [], scope }, sub, depth + 1);
          k = e;
        }
      }
      return;
    }
    if (name !== 'git') {
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
          // 引数はコマンドの文字に全部出ているので、xargs と違い incomplete にはしない。
          const scope = { parent: null };
          seedScope(scope, env, cdBefore);
          visit({ words: tail, redirs: [], piped: false, heredocBodies: [], scope }, resolveCommand(tail), depth + 1);
        }
      }
      return;
    }
    const g = parseGit(info.args);
    if (g.problems.length) { res.problems.push(...g.problems); return; }
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
    g.gitEnvNames = [...env];
    g.cdLikeBefore = cdBefore;
    res.gits.push(g);
  };

  for (const { c, info } of resolved) visit(c, info, 0);
  res.cmdCount = resolved.length;

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

/** Identify commit-time staging and pathspecs while accepting single-word dynamic option values. */
function parseCommitArgs(words) {
  const r = { all: false, patch: false, fromFile: false, dynamic: false, unknown: [], pathspecs: [] };
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
    if (t.startsWith('--')) {
      const eq = t.indexOf('=');
      const nm = eq < 0 ? t.slice(2) : t.slice(2, eq);
      if (nm.includes(DYN)) { r.dynamic = true; k++; continue; }
      const full = resolveCommitLong(nm);
      if (!full) { r.unknown.push(t); k++; continue; }
      const base = full.startsWith('no-') && !COMMIT_LONG[full] ? full.slice(3) : full;
      const kind = COMMIT_LONG[base] || 'f';
      if (full === 'all') r.all = true;
      if (full === 'patch' || full === 'interactive') r.patch = true;
      if (full === 'pathspec-from-file') r.fromFile = true;
      const takesValue = !full.startsWith('no-') && (kind.startsWith('v') || kind.startsWith('o'));
      if (w.dynamic && !takesValue) r.dynamic = true;
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
        if (COMMIT_SHORT_VALUE.has(ch)) {
          if (p === t.length - 1) {
            if (words[k + 1] && words[k + 1].dynamicMaySplit) r.dynamic = true;
            k++; // 値は次の語
          }
          break;
        }
        if (COMMIT_SHORT_ATTACHED.has(ch)) break;
        if (ch === 'a') r.all = true;
        if (ch === 'p') r.patch = true;
        if (!COMMIT_SHORT_FLAGS.has(ch)) { r.unknown.push(t); break; }
      }
      k++;
      continue;
    }
    if (w.dynamic) r.dynamic = true; else r.pathspecs.push(t);
    k++;
  }
  return r;
}

module.exports = {
  DYN,
  deny,
  readInput,
  parseShell,
  inspect,
  problemMessage,
  aliasProblem,
  resolveDir,
  parseCommitArgs,
  READ_ONLY_SUBS,
};
