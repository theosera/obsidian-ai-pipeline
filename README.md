# Obsidian AI Pipeline

A robust, fully-automated pipeline designed to fetch, read, classify, and organize web clipped articles into an Obsidian Vault using AI/LLMs. 

## 🚀 Features

- **Automated Web Fetching**: Utilizes Playwright to perfectly fetch dynamic and heavily JavaScript-rendered pages (such as note.com).
- **Intelligent Classification Ecosystem**:
  - **Fast Pass**: Uses lightweight local LLMs (e.g. Gemma) or fast APIs to classify articles into existing Obsidian tree structures at near zero cost.
  - **Smart Pass**: Automatically escalates to high-end models (e.g. GPT-4o, Claude 3.7) to reason about novel concepts and propose brand new directories organically.
- **Vibe Coding Ready**: Written to be completely manageable via AI agents (like Claude Code, Cursor, Codeium).

## 🛠 Prerequisites

- Node.js (v18+)
- Obsidian standard Vault structure
- API Keys for your preferred AI providers (or LM Studio for Local AI)

## 📦 Setup & Installation

1. Copy this pipeline to your target machine or Obsidian Vault's internal scripts folder.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the interactive configuration wizard to generate your local settings:
   ```bash
   node index.js --config
   ```
   *(Your `.env` and `pipeline_config.json` will be safely ignored via `.gitignore`)*

## ⌨️ Usage

Provide a bulk file containing URLs separated by ` | ` (e.g. exported from the OneTab extension) to process efficiently:

```bash
node index.js path/to/OneTab.txt
```

Enjoy your auto-organizing Obsidian Vault!
