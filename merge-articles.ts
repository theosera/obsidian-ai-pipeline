// @ts-nocheck
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import { loadConfig, applyConfigToEnv, isDryRun, setDryRun, getVaultRoot } from './config.js';
import { safeRename } from './storage.js';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});
const askQuestion = (q) => new Promise(resolve => rl.question(q, resolve));

async function callSmartModel(promptText, systemPrompt) {
  const provider = process.env.AI_PROVIDER || 'local';

  // OpenAI
  if (provider === 'openai') {
    const openaiClient = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const model = process.env.OPENAI_SMART_MODEL || 'gpt-4o';
    const response = await openaiClient.chat.completions.create({
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: promptText }
      ],
      temperature: 0.3
    });
    return response.choices[0].message.content;
  }

  // Gemini
  if (provider === 'gemini') {
    const geminiClient = new OpenAI({
      apiKey: process.env.GEMINI_API_KEY,
      baseURL: 'https://generativelanguage.googleapis.com/v1beta/openai/'
    });
    const model = process.env.GEMINI_SMART_MODEL || 'gemini-2.5-pro';
    const response = await geminiClient.chat.completions.create({
      model,
      messages: [
         { role: 'system', content: systemPrompt },
         { role: 'user', content: promptText }
      ],
      temperature: 0.3
    });
    return response.choices[0].message.content;
  }

  // Anthropic
  if (provider === 'anthropic' || provider === 'claude') {
    const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const model = process.env.ANTHROPIC_SMART_MODEL || 'claude-3-7-sonnet-20250219';
    const response = await anthropic.messages.create({
      model,
      system: systemPrompt,
      max_tokens: 8192,
      messages: [{ role: 'user', content: promptText }]
    });
    return response.content[0].text;
  }

  // Local AI (LM Studio)
  const localAI = new OpenAI({ baseURL: process.env.LOCAL_AI_URL || 'http://127.0.0.1:1234/v1', apiKey: 'lm-studio' });
  const model = process.env.LOCAL_AI_SMART_MODEL || process.env.LOCAL_AI_MODEL || 'local-model';
  const response = await localAI.chat.completions.create({
    model,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: promptText }
    ],
    temperature: 0.3
  });
  return response.choices[0].message.content;
}

async function main() {
  const args = process.argv.slice(2);
  const targetDir = args.find(a => !a.startsWith('--'));

  // --dry-run サポート
  if (args.includes('--dry-run')) {
    setDryRun(true);
  }

  if (!targetDir || !fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    console.error('Usage: node merge-articles.js <absolute-or-relative-path-to-vault-folder>');
    process.exit(1);
  }

  const config = loadConfig();
  applyConfigToEnv(config);

  // Ensure targetDir is within VAULT_ROOT to prevent operating on arbitrary directories
  const vaultRoot = getVaultRoot();
  const resolvedTargetDir = path.resolve(targetDir);
  if (!resolvedTargetDir.startsWith(vaultRoot + path.sep) && resolvedTargetDir !== vaultRoot) {
    console.error(`[Security] Target directory must be within the Vault: ${vaultRoot}`);
    process.exit(1);
  }

  const files = fs.readdirSync(targetDir).filter(f => f.endsWith('.md') && !f.startsWith('_'));

  if (files.length < 2) {
    console.log('統合するファイルが2つ以上見つかりません（_で始まるファイルは無視されます）。');
    process.exit(0);
  }

  console.log(`\n📚 統合対象フォルダ: ${targetDir}`);
  console.log(`対象ファイル数: ${files.length}件\n`);

  let combinedText = '';
  const fileData = [];
  const sourceUrls = [];

  for (const file of files) {
    const filePath = path.join(targetDir, file);
    const content = fs.readFileSync(filePath, 'utf8');

    // フロントマターからURLを抽出
    const urlMatch = content.match(/^source:\s*"?(https?:\/\/.*?)"?$/m);
    if (urlMatch && urlMatch[1]) {
      sourceUrls.push(urlMatch[1].trim());
    }

    // AIのコンテキストノイズ低下のため、各ファイルのフロントマター部分を除去して本文のみにする
    const bodyMatch = content.match(/^---\n[\s\S]*?\n---\n([\s\S]*)/);
    const cleanContent = bodyMatch ? bodyMatch[1] : content;

    combinedText += `\n\n--- 記事: ${file} ---\n\n${cleanContent}\n`;
    fileData.push({ name: file, path: filePath });
  }

  // Very rough character count based token warning (approx. 1 token = 1~2 chars in Japanese)
  const charCount = combinedText.length;
  console.log(`総文字数:約 ${charCount} 文字`);

  if (charCount > 100000) {
    console.warn(`\n⚠️ 警告: テキスト量が非常に多いため（10万文字以上）、AI側のコンテキスト上限に達するかコストが高くなる可能性があります。`);
    const proceed = await askQuestion('それでも続行しますか？ [y/N]: ');
    if (proceed.toLowerCase() !== 'y') {
       console.log('中断しました。');
       process.exit(0);
    }
  }

  console.log(`\n🧠 高性能AI（Smart Model）に記事群を送信し、高度な統合・要約を開始します...`);
  console.log(`（著者の苦労・パラダイム・コード例を意図して残すプロンプトが適用されています）`);

  const systemPrompt = `あなたはシニアエンジニアのメンターであり、複数の技術記事を一つの高度なナレッジベース（マークダウンドキュメント）へと昇華させる専門家です。

提供された同じテーマに関する複数の記事を読み込み、重複する基本的な機能紹介や導入手順は一つに圧縮構成してください。

【厳守するルール】
1. ソースコードやコマンド例は、絶対に省略せずそのまま保持すること。
2. 著者が直面したエラー（Gotchas）、技術選定における葛藤、パラダイムに気付いた瞬間の感動や文脈は、学習者のための「貴重な失敗談・体験記」として意図的に色濃く残して統合すること。単なる事実の羅列（フラットな要約）にしてはいけません。
3. 学習者が手を動かせる「ハンズオンガイド」または「体系化された深い知見まとめ」の形式で出力すること。
4. Markdown形式で出力し、最終的な出力はMarkdownテキストのみとすること（余計な挨拶などは不要）。`;

  const userPrompt = `以下の複数記事を統合してください：\n\n${combinedText}`;

  try {
    const resultMarkdown = await callSmartModel(userPrompt, systemPrompt);

    // === 統合ファイル用のYAMLフロントマターを生成 ===
    let frontmatter = `---\n`;
    frontmatter += `title: "【ナレッジ統合】${path.basename(targetDir)}"\n`;
    if (sourceUrls.length > 0) {
      frontmatter += `urls:\n`;
      for (const u of sourceUrls) {
        frontmatter += `  - "${u}"\n`;
      }
    }
    frontmatter += `date: ${new Date().toISOString().split('T')[0]}\n`;
    frontmatter += `type: "merged-knowledge"\n`;
    frontmatter += `---\n\n`;

    const finalOutput = frontmatter + resultMarkdown;

    // Output path computation explicitly enforcing targetDir/howto/HandsOn
    // or (targetDir's parent)/howto/HandsOn if targetDir is a date subdirectory
    let outputBaseDir = targetDir;
    if (/\/\d{4}-(?:Q\d|\d{2})$/.test(targetDir)) {
      outputBaseDir = path.dirname(targetDir);
    }

    let finalTargetDir = outputBaseDir;
    const howMatch = finalTargetDir.match(/(.*?\/(?:howto|how))(\/.*)?$/i);
    if (howMatch) {
       const howPath = howMatch[1];
       finalTargetDir = path.join(howPath, 'HandsOn'); // Always howto/HandsOn
    } else {
       finalTargetDir = path.join(finalTargetDir, 'howto', 'HandsOn');
    }

    if (!fs.existsSync(finalTargetDir)) {
      fs.mkdirSync(finalTargetDir, { recursive: true });
    }

    const dateStr = new Date().toISOString().split('T')[0].replace(/-/g, '');
    const outputPath = path.join(finalTargetDir, `_知見まとめ_${dateStr}.md`);

    fs.writeFileSync(outputPath, finalOutput, 'utf8');
    console.log(`\n🎉 統合ファイルの生成に成功しました！ -> ${outputPath}`);

    console.log('\n=======================================');
    console.log('元の記事群（マージされたファイル）をどう処理しますか？');
    console.log(' [a] _Archive フォルダを作って移動する（推奨・復旧可能）');
    console.log(' [d] 完全に削除する（Vault究極軽量化）');
    console.log(' [k] そのまま残しておく（何もしない）');
    const action = await askQuestion('Command [a/d/k]: ');

    if (action.toLowerCase() === 'a') {
      const archiveDir = path.join(targetDir, '_Archive');
      if (!isDryRun() && !fs.existsSync(archiveDir)) fs.mkdirSync(archiveDir);
      for (const f of fileData) {
        safeRename(f.path, path.join(archiveDir, f.name));
      }
      if (isDryRun()) {
        console.log(`🔍 [DRY-RUN] ${fileData.length} 件のファイルの退避をシミュレーションしました。`);
      } else {
        console.log(`✅ ${fileData.length} 件のファイルを _Archive に退避しました。`);
      }
    } else if (action.toLowerCase() === 'd') {
      const confirm = await askQuestion('本当に削除してもよろしいですか？（復元できません） [y/N]: ');
      if (confirm.toLowerCase() === 'y') {
         for (const f of fileData) {
           fs.unlinkSync(f.path);
         }
         console.log(`🗑️ ${fileData.length} 件のファイルを完全に削除しました。`);
      } else {
         console.log('削除はキャンセルされ、そのままファイルは保持されました。');
      }
    } else {
      console.log('元ファイルはそのまま保持されます。');
    }

  } catch (err) {
    console.error(`\n❌ エラーが発生しました: ${err.message}`);
  }

  rl.close();
  process.exit(0);
}

main();
