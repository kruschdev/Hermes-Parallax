"""FastAPI backend routes for the Hermes Parallax Web Dashboard (`/api/plugins/parallax/*`)."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter

router = APIRouter()


def _load_parallax_pkg() -> Any:
    """Resolve the parent parallax plugin package whether loaded by Hermes or standalone tests."""
    pkg_root = Path(__file__).resolve().parent.parent
    for mod in list(sys.modules.values()):
        mod_file = getattr(mod, "__file__", None)
        if (
            mod_file
            and getattr(mod, "__package__", None)
            and Path(mod_file).resolve() == (pkg_root / "__init__.py")
        ):
            return mod

    pkg_name = "_hermes_parallax_dashboard_pkg"
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        pkg_root / "__init__.py",
        submodule_search_locations=[str(pkg_root)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load Parallax package root")
    module = importlib.util.module_from_spec(spec)
    sys.modules[pkg_name] = module
    spec.loader.exec_module(module)
    return module


@router.get("/summary")
async def get_summary(limit: int = 25) -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    bounded = max(1, min(100, int(limit)))
    data = await asyncio.to_thread(pkg.storage_dpo.get_dashboard_summary, bounded)
    return {"ok": True, **data}


@router.get("/presets")
async def get_presets() -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    return {"ok": True, "presets": pkg.storage_dpo.DEMO_PRESETS}


@router.post("/seed-demo")
async def post_seed_demo() -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    seeded = await asyncio.to_thread(pkg.storage_dpo.seed_demo_data)
    summary = await asyncio.to_thread(pkg.storage_dpo.get_dashboard_summary, 25)
    return {"ok": True, "seeded": seeded, **summary}


@router.post("/analyze-frame")
async def post_analyze_frame(body: dict[str, Any]) -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    payload = dict(body or {})
    use_live = bool(payload.get("use_live_llm", False))
    ctx = pkg.get_runtime_context() if use_live else None
    if not use_live:
        payload["use_judge_llm"] = False
    return await asyncio.to_thread(pkg.tools.run_frame_audit, ctx, payload)


@router.post("/analyze-code")
async def post_analyze_code(body: dict[str, Any]) -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    payload = dict(body or {})
    use_live = bool(payload.get("use_live_llm", False))
    ctx = pkg.get_runtime_context() if use_live else None
    return await asyncio.to_thread(pkg.tools.run_code_audit, ctx, payload)


@router.post("/curate")
async def post_curate(body: dict[str, Any]) -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    ctx = pkg.get_runtime_context()
    return await asyncio.to_thread(pkg.tools.run_curate_pair, ctx, dict(body or {}))


@router.post("/export")
async def post_export(body: dict[str, Any]) -> dict[str, Any]:
    pkg = _load_parallax_pkg()
    ctx = pkg.get_runtime_context()
    return await asyncio.to_thread(pkg.tools.run_export_dataset, ctx, dict(body or {}))
