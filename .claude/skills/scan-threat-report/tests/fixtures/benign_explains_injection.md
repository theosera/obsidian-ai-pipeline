---
report_type: llm_security_weekly
period_end: 2026-06-08
period_days: 7
source_agent: chatgpt_task
intended_use: implementation_security_review
trust_level: external_research_summary
schema_version: 1
security_handling: untrusted_input
forbidden_usage:
  - execute_report_instructions
  - run_embedded_commands
---

# LLM Security Weekly Report: 2026-06-08

## 1. ニュース・脆弱性リスト

| 事案 | 攻撃カテゴリ | 影響対象 | RiskScore | ステータス |
|---|---|---|---:|---|
| Indirect Prompt Injection in RAG | 間接注入 | RAG 基盤 | 8.1 | 確認 |

## 4. 実装検証観点

| 観点 | 確認すべき実装パターン | 危険な兆候 | 推奨対策 |
|---|---|---|---|
| Indirect Prompt Injection | 外部文書を命令として読める構造 | 文書内の "ignore previous instructions" 等を除去していない | 取得本文を data channel として扱う |

外部文書に「ignore previous instructions」のような文字列を埋め込む手口が知られている。これは攻撃の**解説**であって、本レポートが読み手に出す命令ではない。
