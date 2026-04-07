// @ts-nocheck
import fs from 'fs';
import path from 'path';

const VAULT_ROOT = '/Users/theosera/Library/Mobile Documents/iCloud~md~obsidian/Documents/iCloud Vault 2026';
const VIBE_PATH = path.join(VAULT_ROOT, 'Engineer/AGENT_assistant_VibeCoding/_AIエージェント要件定義');
const AGENTIC_PATH = path.join(VAULT_ROOT, 'Engineer/AGENT_assistant_AgenticEngineering/_AIエージェント要件定義');

// 1. Physically move the folder if it exists
if (fs.existsSync(VIBE_PATH)) {
  console.log(`Moving physical directory...`);
  if (!fs.existsSync(path.dirname(AGENTIC_PATH))) {
    fs.mkdirSync(path.dirname(AGENTIC_PATH), { recursive: true });
  }
  fs.renameSync(VIBE_PATH, AGENTIC_PATH);
  console.log(`Moved successfully.`);
} else {
  console.log(`Source directory not found, might have been moved already.`);
}

// 2. Update snippets.xml
const snippetsFile = path.join(VAULT_ROOT, '__skills/context/snippets.xml');
if (fs.existsSync(snippetsFile)) {
  let snippetsStr = fs.readFileSync(snippetsFile, 'utf8');
  const countBefore = snippetsStr.length;
  snippetsStr = snippetsStr.replaceAll(
    'Engineer/AGENT_assistant_VibeCoding/_AIエージェント要件定義',
    'Engineer/AGENT_assistant_AgenticEngineering/_AIエージェント要件定義'
  );
  if (snippetsStr.length !== countBefore) {
    fs.writeFileSync(snippetsFile, snippetsStr, 'utf8');
    console.log(`Updated snippets.xml`);
  }
}

// 3. Update folder_rules.json
const rulesFile = path.join(VAULT_ROOT, '__skills/pipeline/folder_rules.json');
if (fs.existsSync(rulesFile)) {
  const rules = JSON.parse(fs.readFileSync(rulesFile, 'utf8'));
  const newRules = {};
  for (const [k, v] of Object.entries(rules)) {
    if (k.startsWith('Engineer/AGENT_assistant_VibeCoding/_AIエージェント要件定義')) {
      const newK = k.replace(
        'Engineer/AGENT_assistant_VibeCoding/_AIエージェント要件定義',
        'Engineer/AGENT_assistant_AgenticEngineering/_AIエージェント要件定義'
      );
      newRules[newK] = v;
      console.log(`Migrated rule for: ${newK} -> ${v}`);
    } else {
      newRules[k] = v;
    }
  }
  fs.writeFileSync(rulesFile, JSON.stringify(newRules, null, 2), 'utf8');
  console.log(`Updated folder_rules.json`);
}

console.log('Migration of _AIエージェント要件定義 complete.');
