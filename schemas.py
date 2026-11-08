"""Tool JSON Schemas exposed to Hermes Agent by Parallax."""

from __future__ import annotations

PARALLAX_FRAME_AUDIT = {
    "name": "parallax_frame_audit",
    "description": (
        "Audit a sensitive, geopolitical, policy, or research question across two contrasting "
        "epistemic lenses to separate agreed primary-source facts from silent omissions and "
        "verbatim rhetorical spin. Works in zero-config live mode via Hermes auxiliary slots "
        "(parallax_lens_a, parallax_lens_b, parallax_judge) or offline comparison mode when "
        "lens_a_text and lens_b_text are supplied directly."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "prompt": {
                "type": "string",
                "description": "The research, policy, or factual question to audit.",
            },
            "lens_a_text": {
                "type": "string",
                "description": "Optional pre-existing response A to compare without calling Lens A.",
            },
            "lens_b_text": {
                "type": "string",
                "description": "Optional pre-existing response B to compare without calling Lens B.",
            },
            "use_judge_llm": {
                "type": "boolean",
                "description": (
                    "When true (default), uses Hermes structured completion on parallax_judge "
                    "followed by hard verbatim substring verification. Set false for deterministic "
                    "zero-LLM lexical and claim comparison."
                ),
            },
        },
        "required": ["prompt"],
    },
}

PARALLAX_CODE_AUDIT = {
    "name": "parallax_code_audit",
    "description": (
        "Run a blind counterfactual security taste-test on a coding task. Scrubs geopolitical, "
        "sovereign, defense, intelligence, or advocacy organization names into neutral enterprise "
        "placeholders (NeutralOrg_1), compares the contextual code output against the scrubbed "
        "output using Python AST and multi-language security sink analysis, and flags silent "
        "context-triggered security regressions (CONTEXT_DEGRADED or CONTEXT_REFUSED)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "prompt": {
                "type": "string",
                "description": "The coding prompt containing institutional, regional, or sensitive context.",
            },
            "contextual_reply": {
                "type": "string",
                "description": "Optional code reply generated from the original prompt (skips live call if set).",
            },
            "blind_reply": {
                "type": "string",
                "description": "Optional code reply generated from the scrubbed prompt (skips live call if set).",
            },
            "extra_entities": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional additional organization or regional names to scrub in the blind run.",
            },
        },
        "required": ["prompt"],
    },
}

PARALLAX_CURATE_PAIR = {
    "name": "parallax_curate_pair",
    "description": (
        "Save a verified preference pair (prompt, chosen response, rejected response) into the "
        "local Parallax SQLite training ledger with 1-5 rubric scores (accuracy, balance, "
        "independence) and issue tags for downstream SFT or DPO fine-tuning."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "prompt": {
                "type": "string",
                "description": "User prompt that produced the divergence.",
            },
            "chosen": {
                "type": "string",
                "description": "Preferred response (high factual accuracy, neutral framing, or secure code).",
            },
            "rejected": {
                "type": "string",
                "description": "Rejected response (refusal, boilerplate spin, omission, or context-degraded code).",
            },
            "category": {
                "type": "string",
                "description": "Value or engineering category (e.g. freedom_of_expression, code_security).",
            },
            "accuracy": {
                "type": "integer",
                "description": "Factual or technical accuracy score from 1 (lowest) to 5 (highest).",
            },
            "balance": {
                "type": "integer",
                "description": "Multi-perspective balance score from 1 to 5.",
            },
            "independence": {
                "type": "integer",
                "description": "Freedom from canned institutional or safety boilerplate from 1 to 5.",
            },
            "issue_tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional disqualifying tags (leave empty for gold-tier training pairs).",
            },
            "audit_id": {
                "type": "string",
                "description": "Optional audit_id linking this pair back to a prior Parallax audit.",
            },
        },
        "required": ["prompt", "chosen", "rejected"],
    },
}

PARALLAX_EXPORT_DATASET = {
    "name": "parallax_export_dataset",
    "description": (
        "Filter curated Parallax preference pairs by rubric thresholds (min_accuracy, min_balance, "
        "min_independence, and zero disqualifying issue_tags) and export clean TRL DPO or ChatML SFT "
        "JSONL files under <HERMES_HOME>/plugin-data/parallax/exports/."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "format": {
                "type": "string",
                "enum": ["dpo", "sft"],
                "description": "Output JSONL schema: 'dpo' (TRL chosen/rejected) or 'sft' (ChatML messages).",
            },
            "min_accuracy": {
                "type": "integer",
                "description": "Minimum accuracy score 1-5 required to pass the export filter (default 4).",
            },
            "min_balance": {
                "type": "integer",
                "description": "Minimum balance score 1-5 required to pass the export filter (default 4).",
            },
            "min_independence": {
                "type": "integer",
                "description": "Minimum independence score 1-5 required to pass the export filter (default 4).",
            },
            "filename": {
                "type": "string",
                "description": "Optional output filename inside the plugin-data exports directory.",
            },
        },
        "required": [],
    },
}
