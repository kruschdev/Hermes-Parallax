---
name: parallax-methodology
description: Multi-perspective epistemic auditing, blind counterfactual code security verification, and rubric-gated DPO/SFT dataset curation inside Hermes Agent.
---

# Parallax Methodology

Use Parallax whenever a task involves contested geopolitical, historical, regulatory, or policy claims, or whenever a coding prompt names sovereign, defense, intelligence, or advocacy institutions that might silently degrade generated code quality.

## 1. Fact-vs-Frame Epistemic Auditing (`parallax_frame_audit`)

Single-model answers often entangle verifiable facts with institutional framing or preachy refusals. When auditing a sensitive research prompt:

1. Call `parallax_frame_audit` with the user's `prompt`.
2. Inspect the three separated buckets before answering the user:
   - **`shared_facts`**: Concrete dates, numbers, statutory provisions, and empirical claims corroborated across both lenses.
   - **`silent_omissions`**: Specific facts surfaced by one lens that the other omitted.
   - **`verified_spin_quotes`**: Rhetorical boilerplate across any pole (`state_aligned`, `western_policy`, `corporate_pr`, `safety_boilerplate`). Every spin quote is verified as a verbatim substring of the model output; non-verbatim judge claims are automatically discarded in `dropped_unverified_quotes`.
3. Present primary-source facts first, explicitly note material omissions, and let the user decide how to weigh competing interpretations.

## 2. Blind Taste-Test for Code Security (`parallax_code_audit`)

Models can emit measurably weaker security patterns (string-concatenated SQL, MD5/SHA-1 password hashing, `shell=True` subprocesses, or stubbed validation) when institutional or regional names appear in the prompt—without refusing outright.

1. Call `parallax_code_audit` with the original coding `prompt`.
2. Parallax masks sensitive organizational and regional nouns into neutral enterprise placeholders (`NeutralOrg_1`, `NeutralRegion_1`) while preserving fenced code blocks, imports, and API schemas.
3. Compare `contextual_audit.score` against `blind_audit.score`:
   - If `verdict` is `CONTEXT_DEGRADED` or `CONTEXT_REFUSED`, adopt the stronger security controls from the scrubbed run (re-applying the user's real domain identifiers cleanly) and surface `bias_induced_findings`.

## 3. Rubric-Gated Dataset Curation (`parallax_curate_pair` & `parallax_export_dataset`)

Raw preference datasets degrade quickly if low-accuracy or one-sided pairs are mixed into post-training:

1. Call `parallax_curate_pair` to record a clean synthesis or hardened implementation as `chosen` and the refusal, spin-heavy reply, or degraded code as `rejected`, scoring `accuracy` (`1-5`), `balance` (`1-5`), and `independence` (`1-5`).
2. Call `parallax_export_dataset` with `min_accuracy: 5, min_balance: 4, min_independence: 4` to export filtered TRL `dpo` or ChatML `sft` JSONL files into `<HERMES_HOME>/plugin-data/parallax/exports/`.
