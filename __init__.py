"""Hermes Parallax — Multi-perspective framing, blind code security, and DPO/SFT forge."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

if __package__:
    from . import code_counterfactual, framing_engine, schemas, storage_dpo, tools
    from .storage_dpo import get_dashboard_summary, seed_demo_data

logger = logging.getLogger(__name__)

_RUNTIME_CTX_HOLDER: dict[str, Any] = {"ctx": None}


def get_runtime_context() -> Any:
    """Return the active PluginContext when running inside a live Hermes process, else None."""
    return _RUNTIME_CTX_HOLDER.get("ctx")


def _handle_slash_parallax(ctx: Any, raw_args: str, **kwargs: Any) -> str:
    """Handle `/parallax <subcommand>` across CLI, TUI, Desktop, and Messaging Gateways."""
    text = str(raw_args or "").strip()
    if not text or text.lower() in {"status", "summary", "help"}:
        summary = get_dashboard_summary(limit=5)
        kpis = summary.get("kpis", {})
        lines = [
            "Hermes Parallax Status:",
            f"  Audits recorded: {kpis.get('total_audits', 0)} "
            f"(frame={kpis.get('frame_audits', 0)}, code={kpis.get('code_audits', 0)}, "
            f"passive={kpis.get('passive_flags', 0)})",
            f"  Context-degraded code caught: {kpis.get('context_degraded_count', 0)}",
            f"  Curated preference pairs: {kpis.get('total_dpo_pairs', 0)} "
            f"(gold rubric-passing={kpis.get('gold_dpo_pairs', 0)})",
            f"  Data directory: {summary.get('data_dir', '')}",
            "",
            "Commands:",
            "  /parallax status                  — Show audit & dataset ledger metrics",
            "  /parallax inspect <audit_id>      — Show full stored verdict & findings for an audit",
            "  /parallax seed                    — Populate built-in demo audits & pairs",
            "  /parallax frame <question>        — Run dual-lens fact-vs-frame audit",
            "  /parallax code <coding prompt>    — Run blind entity-scrubbed code security test",
            "  /parallax export [dpo|sft] [4 4 4] — Export rubric-filtered training JSONL",
        ]
        return "\n".join(lines)

    parts = text.split(maxsplit=1)
    sub = parts[0].lower()
    rest = parts[1].strip() if len(parts) > 1 else ""

    if sub == "inspect":
        if not rest:
            return "Usage: /parallax inspect <audit_id>"
        detail = tools.run_ledger_status(ctx, {"audit_id": rest})
        if not detail.get("ok"):
            return f"Parallax inspect error: {detail.get('error')}"
        aud = detail.get("audit") or {}
        pl = aud.get("payload") if isinstance(aud.get("payload"), dict) else {}
        headline = (
            pl.get("recommended_synthesis")
            or pl.get("summary")
            or pl.get("note")
            or f"spin={aud.get('spin_count', 0)}, omissions={aud.get('omission_count', 0)}, delta={aud.get('security_delta', 0)}"
        )
        return (
            f"[Parallax Audit {aud.get('audit_id')}] kind={aud.get('kind')} verdict={aud.get('verdict')} "
            f"({aud.get('created_at')})\n"
            f"- Prompt: {aud.get('prompt', '')}\n"
            f"- Summary: {headline}"
        )

    if sub == "seed":
        seeded = seed_demo_data()
        return (
            f"Seeded Parallax demo traces: {seeded.get('audits_created', 0)} audits, "
            f"{seeded.get('pairs_created', 0)} preference pairs."
        )

    if sub == "frame":
        if not rest:
            return "Usage: /parallax frame <research or policy question>"
        res = tools.run_frame_audit(ctx, {"prompt": rest})
        if not res.get("ok"):
            return f"Parallax frame audit error: {res.get('error')}"
        body = res.get("result", {})
        facts = body.get("shared_facts") or []
        omissions = body.get("silent_omissions") or []
        spins = body.get("verified_spin_quotes") or []
        dropped = body.get("dropped_unverified_quotes") or []
        return (
            f"[Parallax Frame Audit {res.get('audit_id')}] Verdict: {res.get('verdict')}\n"
            f"- Agreed facts: {len(facts)} | Silent omissions: {len(omissions)} | "
            f"Verified spin quotes: {len(spins)} (blocked non-verbatim judge quotes: {len(dropped)})\n"
            f"- Neutral synthesis:\n{body.get('recommended_synthesis', '')}"
        )

    if sub == "code":
        if not rest:
            return "Usage: /parallax code <coding prompt with institutional/regional context>"
        res = tools.run_code_audit(ctx, {"prompt": rest})
        if not res.get("ok"):
            return f"Parallax code audit error: {res.get('error')}"
        comp = res.get("result", {})
        ctx_score = (comp.get("contextual_audit") or {}).get("score", 0)
        blind_score = (comp.get("blind_audit") or {}).get("score", 0)
        scrubbed_count = len((res.get("scrub") or {}).get("entity_map") or [])
        return (
            f"[Parallax Blind Code Taste-Test {res.get('audit_id')}] Verdict: {res.get('verdict')}\n"
            f"- Entities scrubbed: {scrubbed_count} | Contextual score: {ctx_score}/100 | "
            f"Scrubbed score: {blind_score}/100 (delta: {comp.get('security_delta', 0):+d})\n"
            f"- Summary: {comp.get('summary', '')}"
        )

    if sub == "export":
        tokens = rest.split()
        fmt = tokens[0].lower() if tokens else "dpo"
        min_acc = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else 4
        min_bal = int(tokens[2]) if len(tokens) > 2 and tokens[2].isdigit() else 4
        min_ind = int(tokens[3]) if len(tokens) > 3 and tokens[3].isdigit() else 4
        res = tools.run_export_dataset(
            ctx,
            {
                "format": fmt,
                "min_accuracy": min_acc,
                "min_balance": min_bal,
                "min_independence": min_ind,
            },
        )
        if not res.get("ok"):
            return f"Parallax export error: {res.get('error')}"
        return (
            f"Exported {res.get('exported_count', 0)} {fmt.upper()} examples "
            f"(filtered out {res.get('dropped_count', 0)} low-rubric pairs) -> {res.get('path', '')}"
        )

    return f"Unknown /parallax subcommand {sub!r}. Try `/parallax status`."


def register(ctx: Any) -> None:
    """Register Parallax auxiliary tasks, tools, passive hook, command, RPC, and skill."""
    ctx.register_auxiliary_task(
        "parallax_lens_a",
        display_name="Parallax Lens A (Baseline)",
        description="Primary baseline model for Parallax framing and contextual code comparisons.",
    )
    ctx.register_auxiliary_task(
        "parallax_lens_b",
        display_name="Parallax Lens B (Counter-Frame)",
        description="Contrasting model slot for Parallax multi-perspective framing audits.",
    )
    ctx.register_auxiliary_task(
        "parallax_judge",
        display_name="Parallax Judge (Fact & Spin Verifier)",
        description="Structured adjudication model whose spin quotes undergo verbatim substring verification.",
    )

    ctx.register_tool(
        name="parallax_frame_audit",
        toolset="parallax",
        schema=schemas.PARALLAX_FRAME_AUDIT,
        handler=lambda args, **kw: tools.handle_frame_audit(ctx, args, **kw),
        description="Audit contrasting model framings, silent omissions, and verbatim spin quotes.",
    )
    ctx.register_tool(
        name="parallax_code_audit",
        toolset="parallax",
        schema=schemas.PARALLAX_CODE_AUDIT,
        handler=lambda args, **kw: tools.handle_code_audit(ctx, args, **kw),
        description="Run a blind entity-scrubbed security taste-test on generated code.",
    )
    ctx.register_tool(
        name="parallax_curate_pair",
        toolset="parallax",
        schema=schemas.PARALLAX_CURATE_PAIR,
        handler=lambda args, **kw: tools.handle_curate_pair(ctx, args, **kw),
        description="Save a rubric-scored SFT/DPO preference pair into the Parallax ledger.",
    )
    ctx.register_tool(
        name="parallax_export_dataset",
        toolset="parallax",
        schema=schemas.PARALLAX_EXPORT_DATASET,
        handler=lambda args, **kw: tools.handle_export_dataset(ctx, args, **kw),
        description="Export rubric-filtered TRL DPO or ChatML SFT JSONL training files.",
    )
    ctx.register_tool(
        name="parallax_ledger_status",
        toolset="parallax",
        schema=schemas.PARALLAX_LEDGER_STATUS,
        handler=lambda args, **kw: tools.handle_ledger_status(ctx, args, **kw),
        description="Inspect Parallax audit KPIs, recent passive/active flags, or a specific audit_id.",
    )

    def _on_post_llm_call(
        session_id: str = "",
        user_message: str = "",
        assistant_response: str = "",
        model: str = "",
        **kwargs: Any,
    ) -> None:
        try:
            tools.observe_turn_telemetry(
                ctx,
                session_id=session_id,
                user_message=user_message,
                assistant_response=assistant_response,
                model=model,
                **kwargs,
            )
        except Exception as exc:
            logger.debug("Parallax passive observer skipped: %s", exc)

    ctx.register_hook("post_llm_call", _on_post_llm_call)

    ctx.register_command(
        name="parallax",
        handler=lambda raw_args, **kw: _handle_slash_parallax(ctx, raw_args, **kw),
        description="Run Parallax framing audits, blind code taste-tests, and DPO/SFT exports.",
        args_hint="status | inspect <id> | seed | frame <prompt> | code <prompt> | export [dpo|sft]",
    )

    def _rpc_summary(params: Any = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
        if isinstance(params, dict) and (params.get("audit_id") or params.get("kind")):
            return tools.run_ledger_status(ctx, params)
        limit = 25
        if isinstance(params, dict) and str(params.get("limit", "")).isdigit():
            limit = max(1, min(100, int(params["limit"])))
        return get_dashboard_summary(limit=limit)

    def _rpc_audit(params: Any = None, *, session_id: str = "", **kwargs: Any) -> dict[str, Any]:
        payload = params if isinstance(params, dict) else {}
        mode = str(payload.get("mode") or "frame").lower()
        if mode == "code":
            return tools.run_code_audit(ctx, payload)
        return tools.run_frame_audit(ctx, payload)

    ctx.register_rpc("summary", _rpc_summary)
    ctx.register_rpc("audit", _rpc_audit)

    skill_path = Path(__file__).resolve().parent / "skills" / "parallax-methodology" / "SKILL.md"
    if skill_path.is_file():
        ctx.register_skill(
            "parallax-methodology",
            skill_path,
            description=(
                "Multi-perspective epistemic auditing, blind counterfactual code security "
                "verification, and rubric-gated DPO/SFT dataset curation."
            ),
        )

    # Save runtime context only for real PluginContext instances (not subprocess probe stubs).
    if getattr(ctx, "plugin_id", "") != "hermes_validate_probe_plugin":
        _RUNTIME_CTX_HOLDER["ctx"] = ctx
        if hasattr(ctx, "on_unload"):
            ctx.on_unload(lambda: _RUNTIME_CTX_HOLDER.update({"ctx": None}))
