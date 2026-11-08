"""FastAPI backend routes for the Hermes Parallax Web Dashboard (`/api/plugins/parallax/*`)."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter

router = APIRouter()


def _coerce_bool(val: Any, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    text = str(val).strip().lower()
    if text in {"false", "0", "no", "off", ""}:
        return False
    if text in {"true", "1", "yes", "on"}:
        return True
    return default


def _load_parallax_pkg() -> Any:
    """Resolve the parent parallax plugin package, preferring an active Hermes runtime context."""
    pkg_root = Path(__file__).resolve().parent.parent
    init_file = pkg_root / "__init__.py"
    fallback_mod = None
    for mod in list(sys.modules.values()):
        mod_file = getattr(mod, "__file__", None)
        if not (mod_file and getattr(mod, "__package__", None)):
            continue
        try:
            if Path(mod_file).resolve() != init_file:
                continue
        except Exception:
            continue
        get_ctx = getattr(mod, "get_runtime_context", None)
        if callable(get_ctx) and get_ctx() is not None:
            return mod
        if fallback_mod is None:
            fallback_mod = mod

    if fallback_mod is not None:
        return fallback_mod

    pkg_name = "_hermes_parallax_dashboard_pkg"
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        init_file,
        submodule_search_locations=[str(pkg_root)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load Parallax package root")
    module = importlib.util.module_from_spec(spec)
    sys.modules[pkg_name] = module
    spec.loader.exec_module(module)
    return module


def _live_llm_available(pkg: Any) -> bool:
    try:
        ctx = pkg.get_runtime_context()
        return bool(ctx is not None and getattr(ctx, "llm", None) is not None)
    except Exception:
        return False


@router.get("/summary")
async def get_summary(limit: int = 25) -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    try:
        bounded = max(1, min(100, int(limit)))
    except (ValueError, TypeError):
        bounded = 25
    data = await asyncio.to_thread(pkg.storage_dpo.get_dashboard_summary, bounded)
    return {"ok": True, "live_llm_available": _live_llm_available(pkg), **data}


@router.get("/presets")
async def get_presets() -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    return {
        "ok": True,
        "live_llm_available": _live_llm_available(pkg),
        "presets": pkg.storage_dpo.DEMO_PRESETS,
    }


@router.post("/seed-demo")
async def post_seed_demo() -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    seeded = await asyncio.to_thread(pkg.storage_dpo.seed_demo_data)
    summary = await asyncio.to_thread(pkg.storage_dpo.get_dashboard_summary, 25)
    return {
        "ok": True,
        "live_llm_available": _live_llm_available(pkg),
        "seeded": seeded,
        **summary,
    }


@router.post("/analyze-frame")
async def post_analyze_frame(body: dict[str, Any]) -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    payload = dict(body or {})
    use_live = _coerce_bool(payload.get("use_live_llm"), False)
    ctx = pkg.get_runtime_context() if use_live else None
    if use_live:
        payload.setdefault("regenerate", True)
    else:
        payload["use_judge_llm"] = False
        payload["regenerate"] = False
    return await asyncio.to_thread(pkg.tools.run_frame_audit, ctx, payload)


@router.post("/analyze-code")
async def post_analyze_code(body: dict[str, Any]) -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    payload = dict(body or {})
    use_live = _coerce_bool(payload.get("use_live_llm"), False)
    ctx = pkg.get_runtime_context() if use_live else None
    if use_live:
        payload.setdefault("regenerate", True)
    else:
        payload["regenerate"] = False
    return await asyncio.to_thread(pkg.tools.run_code_audit, ctx, payload)


@router.post("/curate")
async def post_curate(body: dict[str, Any]) -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    ctx = pkg.get_runtime_context()
    try:
        return await asyncio.to_thread(pkg.tools.run_curate_pair, ctx, dict(body or {}))
    except (ValueError, TypeError) as exc:
        return {"ok": False, "error": str(exc)}


@router.post("/export")
async def post_export(body: dict[str, Any]) -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    ctx = pkg.get_runtime_context()
    try:
        return await asyncio.to_thread(pkg.tools.run_export_dataset, ctx, dict(body or {}))
    except (ValueError, TypeError) as exc:
        return {"ok": False, "error": str(exc)}
