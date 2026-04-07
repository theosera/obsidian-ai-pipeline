# Obsidian Web Clipper Automation Pipeline

## 1. Planning
- [x] Create implementation plan
- [x] Get user approval

## 2. Setup
- [x] Initialize Node.js project in `__skills/pipeline`
- [x] Install dependencies (Playwright, Readability, Turndown, Anthropic SDK)

## 3. Development
- [x] URL parsing and entry point logic (`index.ts` / `index.js`)
- [x] HTML Fetching via Playwright (`fetcher.js`)
- [x] HTML cleansing and Readability extraction (`extractor.js`)
- [x] Markdown conversion with Turndown
- [x] Classification logic (Rule-based + Local/Claude AI fallback) (`classifier.js`)
- [x] Vault output & Markdown generation logic (`storage.js`)

## 4. Verification
- [x] Run against a test `OneTab.txt`
- [x] Verify extracted markdown content and accuracy
- [x] Verify folder classification accuracy
- [x] Integrate Local AI (Ollama/OpenAI compatible) support

## 6. Dynamic Vault Sync
- [x] Scan and build dynamic folder tree list (`storage.js`)
- [x] Integrate real-time folder list into AI promt (`classifier.js`)
- [x] Add fuzzy matching to rule-based classifier outputs (`classifier.js`)

## 5. Advanced Features
- [x] Implement Batch Analysis mode (`--analyze`)
- [x] Implement New Folder Proposal logic (3+ count rule)
- [x] Implement Interactive or Two-step Execution flow
