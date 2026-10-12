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

/** Flush a bounded deny response before exiting, so a pipe cannot truncate its JSON. */
function deny(reason) {
  const message = typeof reason === 'string' ? reason : 'hook が入力を検査できないため実行をブロックします (fail-closed)。';
  // 512 UTF-16 units stay below 4 KiB even when JSON escapes every unit as \uXXXX.
  const bounded = message.length > 512 ? message.slice(0, 511) + '…' : message;
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

/** Scan one expansion and collect executable substitutions in child shell scopes. */
function scanExpansion(src, i, out, depth, scope, effects) {
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
      scanSubsts(src.slice(i + 3, j), out, depth + 1, scope, effects);
      return { end: j + 2, dynamic: true };
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
    scanSubsts(src.slice(i + 2, j), out, depth + 1, scope, effects);
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
        multiWord = scanSubsts(src.slice(j + 1, q), out, depth + 1, scope, effects) || multiWord;
        j = q + 1;
        continue;
      }
      if (ch === '"') {
        j++;
        while (j < n && src[j] !== '"') {
          if (src[j] === '\\') { j += 2; continue; }
          if (src[j] === '$' || src[j] === '`') {
            const r = scanExpansion(src, j, out, depth + 1, scope, effects);
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
function scanSubsts(text, out, depth, scope, effects) {
  let k = 0;
  let multiWord = false;
  while (k < text.length) {
    const ch = text[k];
    if (ch === '\\') { k += 2; continue; }
    if (ch === '$' || ch === '`') {
      const r = scanExpansion(text, k, out, depth, scope, effects);
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
    if (!cur) cur = { text: '', braceSource: '', dynamic: false, dynamicMaySplit: false, quoted: false, start: i };
  };
  const endWord = () => {
    if (!cur) return;
    cur.raw = src.slice(cur.start, i);
    cur.braceExpanded = hasBraceExpansion(cur.braceSource);
    delete cur.braceSource;
    if (cur.braceExpanded) { cur.dynamic = true; cur.dynamicMaySplit = true; }
    if (!redirNext && !cur.quoted && !cur.dynamic && atCmdPos(words)) {
      const close = { if: 'fi', while: 'done', until: 'done', for: 'done', select: 'done', case: 'esac' }[cur.text];
      if (close) {
        const group = newEffect();
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
      const c = { words, redirs, piped, heredocBodies: [], scope, definitionName, effects: currentEffects() };
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
          const r = scanExpansion(src, i, out, depth, scope, currentEffects());
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
        if (!h.quoted) scanSubsts(body, out, depth + 1, scope, h.cmd ? h.cmd.effects : currentEffects());
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
      const arithAt = atCmd || (!cur && words.length === 1 && !words[0].quoted && words[0].text === 'for');
      if (src[i + 1] === '(' && arithAt) {
        const end = arithEnd(src, i + 2);
        if (end >= 0) {
          scanSubsts(src.slice(i + 2, end), out, depth + 1, scope, currentEffects());
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
  const out = { cmds: [], errors: [], scope: { parent: null }, async: false };
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
  'am', 'push', 'send-pack', 'http-push', 'remote', 'config',
]);

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'fish']);
const CD_LIKE = new Set(['cd', 'pushd', 'popd']);
const EXPORT_LIKE = new Set(['export', 'declare', 'typeset', 'local', 'readonly']);
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
      if (v.dynamicMaySplit) { g.problems.push(`git の ${t} の値が複数の語になりうるため、subcommand を決められない`); return g; }
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
        if (v.dynamicMaySplit) { g.problems.push(`git の ${t} の値が複数の語になりうるため、subcommand を決められない`); return g; }
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

/** Inspect executable Git invocations, associating preceding scope changes with each invocation. */
function inspect(cmd, options = {}) {
  const sourceDepth = options.sourceDepth || 0;
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
  const emptyState = () => ({ env: new Set(), cd: false, pathChanged: false, searchChanged: false, unknownContext: false, gitShadowed: false, positionals: null, positionalsTainted: false });
  const copyState = (s) => ({ ...s, env: new Set(s.env) });
  const stateFor = (scope) => {
    if (!scopeStates.has(scope)) {
      scopeStates.set(scope, scope && scope.parent ? copyState(stateFor(scope.parent)) : emptyState());
    }
    return scopeStates.get(scope);
  };
  const seedScope = (scope, env, cd, inherited) => scopeStates.set(scope, { ...emptyState(), ...inherited, env: new Set(env), cd });
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
      if (op.clear) { env.clear(); pathChanged = false; }
      if (op.unset) { env.delete(op.unset); if (op.unset === 'PATH') pathChanged = false; }
      if (op.set && /^GIT_/.test(op.set)) env.add(op.set);
      if (op.set === 'PATH' || op.set === 'FPATH') pathChanged = true;
    }
    const cdBefore = state.cd || info.cdLike;
    const shell = SHELLS.has(info.name) ? shellInvocation(info.args, info.name) : null;
    const builtin = info.wrapperNames.every((name) => name === 'command' || name === 'builtin');
    const trap = info.name === 'trap' && builtin ? trapInvocation(info.args) : null;
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
      unsafeGroupSetup: (c.effects || []).some((e) => e.unsafeSetup),
      shellScripts: shell ? shell.scripts : [], shellCommandMode: shell ? shell.commandMode : false,
      shellSourceUnknown: shell ? shell.unknown : false, shellReadsStdin: shell ? shell.readsStdin : false,
      shellPositionals: shell && !shell.unknown ? shell.positionals : null,
      trapScripts: trap ? trap.scripts : [], trapSourceUnknown: trap ? trap.unknown : false,
    };
    res.invocations.push(invocation);
    if (info.cdLike) res.cdLike = true;
    for (const a of info.assigns) if (/^GIT_/.test(a) && !res.gitEnvNames.includes(a)) res.gitEnvNames.push(a);
    if (!info.name && !info.dynamicName && !info.wrapped) { state.env = env; state.pathChanged = pathChanged; }
    if (info.persistsEnv || (!info.wrapped && SPECIAL_BUILTINS.has(info.name))) {
      for (const a of env) state.env.add(a);
      state.pathChanged = state.pathChanged || pathChanged;
    }
    if (invocation.definitionName) {
      state.unknownContext = true;
      state.positionalsTainted = true;
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
        if (inner.invocations.some((entry) =>
          (entry.name === 'set' && positionalSet(entry.args)) ||
          (entry.name === 'shift' && (!entry.args[0] || entry.args[0].dynamic || entry.args[0].text !== '0')))) state.positionalsTainted = true;
      }
      if (trap.scripts.length) state.unknownContext = true; // A DEBUG/signal action may run before a later write.
      return;
    }
    if (name === '.' || name === 'source' || name === 'eval') {
      state.unknownContext = true;
      state.positionalsTainted = true;
      state.searchChanged = true; // 未読のコードは PATH や関数による command lookup も変えうる。
    }
    if (COMMAND_SEARCH_MUTATORS.has(name)) state.searchChanged = true;
    if (CD_LIKE.has(name)) { res.cdLike = true; state.cd = true; }
    if (EXPORT_LIKE.has(name)) {
      for (const w of info.args) {
        const nm = w.text.split('=')[0];
        if (/^GIT_/.test(nm)) { res.gitEnvNames.push(nm); state.env.add(nm); }
        if (nm === 'PATH' || nm === 'FPATH') state.pathChanged = true;
      }
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
      if ((positionalExec || sourceDepth > 0) && ['echo', 'printf'].includes(name) &&
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
    if (g.sub === 'commit' && parseCommitArgs(g.args).terminal) g.terminal = true;
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

/** Identify commit-time staging and pathspecs while accepting single-word dynamic option values. */
function parseCommitArgs(words) {
  const r = { all: false, patch: false, fromFile: false, noVerify: false, terminal: false, dynamic: false, unknown: [], pathspecs: [] };
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
      if (full === 'no-verify') r.noVerify = true;
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
        // 不明な先行引数が -m 等になると、この -h は値として消費されうる。
        if (ch === 'h') { if (!r.dynamic && !r.unknown.length) r.terminal = true; break; }
        if (COMMIT_SHORT_VALUE.has(ch)) {
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
  return r;
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
  READ_ONLY_SUBS,
};
