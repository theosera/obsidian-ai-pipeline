# Obsidian AI Pipeline

> **⚠️ Disclaimer: Personal Workflow Tool**
> This repository contains a personal automation tool designed and hardcoded explicitly for my own Obsidian Vault structure. **It is not intended for general use as a plug-and-play OSS product.** 
> I am making the code public primarily as a design reference and architectural example of how to build an AI-driven, fully autonomous file classification pipeline.

A robust, automated pipeline designed to fetch, read, classify, and organize web clipped articles into an Obsidian Vault using AI/LLMs. 

## 🚀 Concept & Features

- **Automated Web Fetching**: Utilizes Playwright to fetch dynamic and heavily JavaScript-rendered pages (such as note.com) behind the scenes.
- **Intelligent Classification Ecosystem**:
  - **Fast Pass**: Uses lightweight local LLMs (e.g., Gemma) or fast APIs to classify articles into existing Obsidian tree structures at near-zero cost.
  - **Smart Pass**: Automatically escalates to high-end models (e.g., Claude 3.7 Sonnet, GPT-4o) to reason about novel concepts and organically propose brand new directory structures.
- **Vibe Coding Ready**: Written using TypeScript to be safely managed and expanded by AI agents (like Claude Code, Cursor, or Gemini).

## 🛠 Note on Reusability

If you'd like to use this for your own workflow, **you will need to modify the source code heavily**.
The main logic files (`index.ts`, `storage.ts`, `router.ts`) rely on hardcoded paths (`/Users/theosera/Library/...`) tailored to my specific macOS iCloud drive setup.

If you are looking for inspiration to build your own Obsidian automation, feel free to reference the AI prompts, Playwright fetching logic, and TypeScript structural designs found in this repository.

## 📦 For My Own Reference (Usage)

Dependencies:
- Node.js (v18+)
- Local LLM like LM Studio (optional) or API Keys (Anthropic, OpenAI)

Installation:
```bash
npm install
```

Interactive configuration and execution (using `tsx`):
```bash
# To configure keys
npm run start -- --config

# To classify a bulk list of URLs (exported from OneTab)
npm run start /path/to/OneTab.txt
```
