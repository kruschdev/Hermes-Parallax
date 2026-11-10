# Hermes Parallax (`parallax`) — Specification (`spec.md`)

> **Status**: FROZEN (`v0.1.0`)
> **Target**: Nous Research Hermes Agent Plugin Catalog (`requires_hermes: ">=0.22.3"`)
> **License**: MIT · **Author**: `kruschdev <kruschdev@users.noreply.github.com>` (solo first-person `"I"` voice)
> **Runtime Dependencies**: Zero external PyPI dependencies (`dependencies = []`); Python `>=3.11` stdlib + Hermes Public Plugin API (`plugins.plugin_storage`, `agent.redact`, `agent.runtime_cwd`) + Hermes Web Dashboard SDK (`window.__HERMES_PLUGIN_SDK__`, FastAPI `APIRouter`).

---

## 1. Problem & Motivation

Open-weight and frontier models embed distinct institutional, geopolitical, and safety-tuning priors directly in their weights. As highlighted in the **Arete-27B** technical report (including Footnote 1 citing Hirundo & Booz Allen's findings on context-triggered code vulnerabilities):
1. **Research & Fact-Finding Tangling**: Single-model answers entangle *verifiable factual recall* (what happened, what was omitted) with *narrative framing* (whose talking points or boilerplate spin wrapped those facts).
2. **Silent Context-Triggered Code Degradation**: Coding models can produce measurably weaker security controls (e.g., raw SQL interpolation, weak hashing, permissive CORS, stubbed handlers) when organizational, sovereign, or geopolitical identifiers appear in the prompt context—even without issuing an explicit refusal.
3. **High Friction to Self-Alignment**: Users who catch refusals, spin, or context-biased code lack a one-click pipeline inside their daily agent harness to turn those exact divergences into rubric-filtered SFT and DPO training pairs.

**Hermes Parallax** turns multi-perspective epistemic auditing and counterfactual code verification into a native, non-partisan Hermes Agent instrument across CLI, TUI, Messaging Gateways, and the Hermes Web Dashboard.

---

## 2. Frozen Module Contracts

All internal Python modules live inside the flat plugin package root (`./`) so `hermes plugins install` and `hermes plugins validate` load the repository root directly (`subdir` omitted).

### 2.1 `framing_engine.py` — Fact-vs-Frame & Quote-Evidence Verifier
Exports:
- `VALUE_CATEGORIES: tuple[str, ...]` — `("freedom_of_expression", "state_ideology", "state_vs_market", "education", "privacy_surveillance", "democracy_governance", "environment_energy", "corporate_pr", "canned_refusal")`
- `detect_refusal_and_spin(text: str) -> dict`
  - Pure stdlib `<1ms` analyzer returning:
    ```json
    {
      "is_refusal": false,
      "is_deflection": false,
      "matched_frames": [
        {"pole": "state_aligned|western_policy|us_progressive_institutional|us_populist_conservative|corporate_pr|safety_boilerplate", "category": "str", "label": "str", "quoted_span": "exact substring"}
      ],
      "citation_markers": 2,
      "hedge_ratio": 0.04,
      "word_count": 180
    }
    ```
- `ADJUDICATION_JSON_SCHEMA: dict` — Strict JSON Schema for `ctx.llm.complete_structured` on task `"parallax_judge"`.
- `build_steelman_counter_messages(prompt: str) -> list[dict[str, str]]` — Builds primary-source factual + counter-frame messages when Lens B shares the same underlying model as Lens A (zero-config single-model mode).
- `verify_adjudication_quotes(raw_parsed: dict | None, lens_a_text: str, lens_b_text: str) -> dict`
  - **Hard Anti-Hallucination Gate**: Drops any claimed spin quote in `raw_parsed` whose normalized text does not appear verbatim in `lens_a_text` or `lens_b_text`, recording dropped items in `dropped_unverified_quotes`.
  - Returns normalized `{ "shared_facts": [...], "silent_omissions": [...], "verified_spin_quotes": [...], "dropped_unverified_quotes": [...], "rubric": { "lens_a": {"accuracy": 1..5, "balance": 1..5, "independence": 1..5, "issue_tags": [...]}, "lens_b": {...} }, "recommended_synthesis": "str" }`.
- `compare_frames_offline(prompt: str, lens_a_text: str, lens_b_text: str) -> dict` — Deterministic fallback comparator (sentence-claim overlap, numeric/date entity delta, and `detect_refusal_and_spin` differential) used when structured LLM judging is skipped or unavailable.

### 2.2 `code_counterfactual.py` — Blind Taste-Test for Code Security (Footnote 1)
Exports:
- `scrub_identity_context(prompt: str, extra_entities: list[str] | None = None) -> dict`
  - Replaces sovereign, geopolitical, defense, intelligence, party, advocacy/NGO, and user-supplied organization markers in prose while preserving fenced code blocks, package names, technical identifiers, and API schemas.
  - Returns:
    ```json
    {
      "scrubbed_prompt": "str",
      "entity_map": [{"original": "str", "placeholder": "NeutralOrg_1", "category": "defense|sovereign|ngo|geopolitical|custom"}],
      "triggered": true
    }
    ```
- `restore_identity_context(code_text: str, entity_map: list[dict] | None) -> str`
  - Replaces `NeutralOrg_*` / `NeutralRegion_*` placeholders back with original entity strings (validating Python `ast.parse` preservation when applicable) before curating `chosen` implementations into `dpo_pairs`.
- `audit_code_security(text: str, language_hint: str = "auto") -> dict`
  - Extracts code blocks (or raw code) and runs Python `ast` inspection + multi-language security sink rules (`sql_injection`, `weak_crypto`, `command_injection`, `unsafe_dynamic_exec`, `permissive_cors_tls`, `hardcoded_secret_sink`, `swallowed_exception_or_bypass`, `stub_or_truncation`).
  - **Safety constraint**: Never embed literal exploit shell pipelines or raw secret-file read strings that could trip Hermes `plugin_guard`; inspect via `ast` node attributes (`node.func`, `node.keywords`) and clean regex tokens.
  - Returns `{ "score": 0..100, "findings": [{"rule_id": "str", "severity": "high|medium|low", "line": 1, "description": "str", "remediation": "str"}], "code_extracted": "str", "language": "str", "line_count": 0 }`.
- `compare_counterfactual_code(contextual_reply: str, blind_reply: str, entity_map: list[dict]) -> dict`
  - Computes `contextual_audit`, `blind_audit`, `security_delta = blind_audit["score"] - contextual_audit["score"]`, `bias_induced_findings` (rule hits present in `contextual_audit` absent in `blind_audit`), `verdict` (`"CLEAN_PARITY"` | `"CONTEXT_DEGRADED"` | `"CONTEXT_REFUSED"` | `"BLIND_CLEANER"`), and `summary`.

### 2.3 `storage_dpo.py` — SQLite WAL Ledger & Rubric-Gated SFT/DPO Exporter
Exports:
- `resolve_parallax_data_dir() -> Path` — Uses `plugins.plugin_storage.plugin_data_dir("parallax")` when inside Hermes, falling back to `Path(os.environ.get("HERMES_HOME", "~/.hermes")).expanduser() / "plugin-data" / "parallax"` in standalone test environments.
- `safe_redact(text: str) -> str` — Calls `agent.redact.redact_sensitive_text(text, force=True)` when inside Hermes, with regex fallback for API keys/bearer tokens in standalone tests.
- `record_audit(entry: dict) -> str` — Persists an audit row into `<data_dir>/parallax.db` (`PRAGMA journal_mode=WAL`) and returns `audit_id`.
- `curate_dpo_pair(*, prompt: str, chosen: str, rejected: str, category: str, accuracy: int = 5, balance: int = 5, independence: int = 5, issue_tags: list[str] | None = None, audit_id: str | None = None, source_models: dict | None = None) -> dict` — Inserts a preference pair and returns `{ "pair_id": "str", "qualifies_gold": bool }`.
- `export_training_dataset(*, fmt: str = "dpo", min_accuracy: int = 4, min_balance: int = 4, min_independence: int = 4, filename: str | None = None) -> dict` — Filters `dpo_pairs` by rubric thresholds + zero disqualifying `issue_tags`, writes JSONL under `<data_dir>/exports/`, and returns `{ "ok": true, "format": fmt, "exported_count": int, "dropped_count": int, "path": "str", "preview": [...] }`.
- `get_dashboard_summary(limit: int = 25) -> dict` — Returns aggregate KPIs, recent audits, curated DPO pair counts, and built-in presets.
- `DEMO_PRESETS: list[dict]` — 3 deterministic presets (`frame_export_controls`, `code_defense_portal`, `code_ngo_auth`) for instant offline/live dashboard testing.

### 2.4 `dashboard/` — Hermes v0.23 Web Dashboard UI & FastAPI Backend
- `dashboard/manifest.json`: `name: "parallax"`, `label: "Parallax"`, `icon: "Shield"`, `tab: {"path": "/parallax", "position": "after:skills"}`, `entry: "dist/index.js"`, `css: "dist/style.css"`, `api: "plugin_api.py"`.
- `dashboard/dist/style.css`: Theme-aware CSS variables (`--color-card`, `--color-border`, `--color-primary`, `--color-destructive`, `--radius`).
- `dashboard/dist/index.js`: Zero-build IIFE consuming `window.__HERMES_PLUGIN_SDK__` (`React`, `hooks`, `components`, `fetchJSON`), rendering KPI cards and 3 interactive views:
  1. **Fact-vs-Frame Lens** (Agreed Facts, Silent Omissions, Verbatim Highlighted Spin + 1–5 Rubric Bars + Live/Offline Runner)
  2. **Blind Code Taste-Test** (Contextual vs. Scrubbed `NeutralOrg` Security Score `0–100`, `entity_map` badges, `CONTEXT_DEGRADED` vulnerability diff)
  3. **DPO / SFT Dataset Forge** (Interactive `accuracy / balance / independence` threshold sliders, live qualifying count, 1-click JSONL export)
- `dashboard/plugin_api.py`: FastAPI `router = APIRouter()` with `async def` endpoints (`GET /summary`, `GET /presets`, `POST /analyze-frame`, `POST /analyze-code`, `POST /curate`, `POST /export`, `POST /seed-demo`) offloading sync work via `asyncio.to_thread`.

### 2.5 Root Manifest, CLI/MCP Entrypoint & Choke Points (Orchestrator)
- `plugin.yaml`:
  - `name: parallax`, `version: "0.1.0"`, `manifest_version: 2`, `api_version: 1`, `license: MIT`, `requires_hermes: ">=0.22.3"`
  - `provides_tools`: `[parallax_frame_audit, parallax_code_audit, parallax_curate_pair, parallax_export_dataset, parallax_ledger_status]`
  - `provides_hooks`: `[post_llm_call]`
  - `provides_middleware`: `[]`
  - `requires_env`: `[]`
  - `config_schema`: `passive_watch` (`bool`, default `true`), `auto_curate_degraded_code` (`bool`, default `true`), `min_export_accuracy` (`int`, default `4`), `min_export_balance` (`int`, default `4`).
- `schemas.py` & `tools.py` (`parallax_ledger_status`):
  - Read-only agent tool (`PARALLAX_LEDGER_STATUS`, `run_ledger_status`, `handle_ledger_status`) enabling the Hermes LLM (and external MCP agents) to query ledger KPIs (`total_audits`, `frame_audits`, `code_audits`, `passive_flags`, `context_degraded_count`, `total_dpo_pairs`, `gold_dpo_pairs`), filter recent compact audit summaries by `kind` (`"all" | "frame" | "code" | "passive"`), optionally include compact curated pair summaries (`include_pairs`), or retrieve the full decoded record for a specific `audit_id`.
- `__init__.py`: `register(ctx)` wiring the 3 auxiliary tasks (`parallax_lens_a`, `parallax_lens_b`, `parallax_judge`), 5 tools (`parallax_frame_audit`, `parallax_code_audit`, `parallax_curate_pair`, `parallax_export_dataset`, `parallax_ledger_status`), `post_llm_call` passive lexical/AST observer, `/parallax` slash command (`status | inspect <audit_id> | seed | frame | code | export`), `plugin.parallax.summary` & `plugin.parallax.audit` RPC methods, and bundled `skills/parallax-methodology/SKILL.md`.
- `__main__.py`: Zero-dependency Python stdlib CLI (`status`, `inspect`, `seed`, `frame`, `code`, `curate`, `export`) and JSON-RPC 2.0 Stdio MCP server (`mcp`, `protocolVersion: "2024-11-05"`, supporting newline-delimited and `Content-Length` framed stdio with 4-boolean MCP tool annotations) runnable directly from the installed plugin directory (`python3 ~/.hermes/plugins/hermes-parallax ...`) with zero external PyPI packages or network calls.
