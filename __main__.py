"""Standalone zero-dependency CLI and JSON-RPC 2.0 Stdio MCP entrypoint for Hermes Parallax.

Usage from any installed plugin directory:
  python3 ~/.hermes/plugins/hermes-parallax status [--kind passive] [--json]
  python3 ~/.hermes/plugins/hermes-parallax inspect <audit_id> [--json]
  python3 ~/.hermes/plugins/hermes-parallax seed [--json]
  python3 ~/.hermes/plugins/hermes-parallax export --format dpo [--json]
  python3 ~/.hermes/plugins/hermes-parallax mcp
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any, BinaryIO


def _load_parallax_package() -> Any:
    if __package__:
        return sys.modules[__package__]
    pkg_root = Path(__file__).resolve().parent
    pkg_name = "_hermes_parallax_cli_pkg"
    existing = sys.modules.get(pkg_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        pkg_root / "__init__.py",
        submodule_search_locations=[str(pkg_root)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load Hermes Parallax package root.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[pkg_name] = module
    spec.loader.exec_module(module)
    return module


def _mcp_tool_catalog(pkg: Any) -> list[dict[str, Any]]:
    sc = pkg.schemas
    defs = [
        (
            sc.PARALLAX_LEDGER_STATUS,
            {
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        ),
        (
            sc.PARALLAX_FRAME_AUDIT,
            {
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False,
            },
        ),
        (
            sc.PARALLAX_CODE_AUDIT,
            {
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False,
            },
        ),
        (
            sc.PARALLAX_CURATE_PAIR,
            {
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False,
            },
        ),
        (
            sc.PARALLAX_EXPORT_DATASET,
            {
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        ),
    ]
    out: list[dict[str, Any]] = []
    for raw_schema, annotations in defs:
        out.append(
            {
                "name": raw_schema["name"],
                "description": raw_schema["description"],
                "inputSchema": raw_schema["parameters"],
                "annotations": annotations,
            }
        )
    return out


def _dispatch_mcp_tool(pkg: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    tl = pkg.tools
    ctx = pkg.get_runtime_context()
    dispatch_map = {
        "parallax_ledger_status": tl.run_ledger_status,
        "parallax_frame_audit": tl.run_frame_audit,
        "parallax_code_audit": tl.run_code_audit,
        "parallax_curate_pair": tl.run_curate_pair,
        "parallax_export_dataset": tl.run_export_dataset,
    }
    fn = dispatch_map.get(name)
    if fn is None:
        err = {"ok": False, "error": f"Unknown Parallax tool: {name!r}"}
        return {
            "content": [{"type": "text", "text": json.dumps(err, ensure_ascii=False)}],
            "structuredContent": err,
            "isError": True,
        }
    result = fn(ctx, dict(arguments or {}))
    return {
        "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
        "structuredContent": result,
        "isError": not bool(result.get("ok", True)),
    }


def _handle_jsonrpc_message(pkg: Any, msg: dict[str, Any]) -> dict[str, Any] | None:
    req_id = msg.get("id")
    method = str(msg.get("method") or "")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    # Notifications carry no "id" and receive no response frame.
    if "id" not in msg:
        return None

    if method == "initialize":
        requested = str(params.get("protocolVersion") or "2024-11-05")
        supported = {"2024-11-05", "2025-03-26", "2025-06-18"}
        negotiated = requested if requested in supported else "2024-11-05"
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "hermes-parallax", "version": "0.1.0"},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": _mcp_tool_catalog(pkg)},
        }

    if method == "tools/call":
        tool_name = str(params.get("name") or "").strip()
        tool_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        try:
            call_res = _dispatch_mcp_tool(pkg, tool_name, tool_args)
        except Exception as exc:
            err = {"ok": False, "error": f"{tool_name} failed: {exc}"}
            call_res = {
                "content": [{"type": "text", "text": json.dumps(err, ensure_ascii=False)}],
                "structuredContent": err,
                "isError": True,
            }
        return {"jsonrpc": "2.0", "id": req_id, "result": call_res}

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def serve_mcp_stdio(
    pkg: Any,
    stdin_buf: BinaryIO | None = None,
    stdout_buf: BinaryIO | None = None,
) -> int:
    """Serve MCP over stdio supporting both newline-delimited JSON and Content-Length headers."""
    reader = stdin_buf if stdin_buf is not None else sys.stdin.buffer
    writer = stdout_buf if stdout_buf is not None else sys.stdout.buffer

    while True:
        first_line = reader.readline()
        if not first_line:
            break
        stripped = first_line.strip()
        if not stripped:
            continue

        framed = False
        raw_body: bytes
        if stripped.lower().startswith(b"content-length:"):
            framed = True
            try:
                length = int(stripped.split(b":", 1)[1].strip())
            except ValueError:
                continue
            if length < 0 or length > 16 * 1024 * 1024:
                continue
            while True:
                hdr_line = reader.readline()
                if not hdr_line or hdr_line in (b"\r\n", b"\n"):
                    break
            raw_body = reader.read(length)
        else:
            raw_body = stripped

        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            payload_bytes = json.dumps(err_resp, ensure_ascii=False).encode("utf-8")
            if framed:
                writer.write(f"Content-Length: {len(payload_bytes)}\r\n\r\n".encode("ascii"))
                writer.write(payload_bytes)
            else:
                writer.write(payload_bytes + b"\n")
            writer.flush()
            continue

        if not isinstance(parsed, dict):
            continue

        response = _handle_jsonrpc_message(pkg, parsed)
        if response is None:
            continue

        out_bytes = json.dumps(response, ensure_ascii=False).encode("utf-8")
        try:
            if framed:
                writer.write(f"Content-Length: {len(out_bytes)}\r\n\r\n".encode("ascii"))
                writer.write(out_bytes)
            else:
                writer.write(out_bytes + b"\n")
            writer.flush()
        except BrokenPipeError:
            return 0

    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hermes-parallax",
        description="Hermes Parallax standalone CLI and zero-dependency Stdio MCP server.",
    )
    sub = parser.add_subparsers(dest="command")

    p_status = sub.add_parser("status", help="Inspect Parallax ledger KPIs and recent audits")
    p_status.add_argument("--kind", choices=["all", "frame", "code", "passive"], default="all")
    p_status.add_argument("--limit", type=int, default=10)
    p_status.add_argument("--no-pairs", action="store_true")
    p_status.add_argument("--json", action="store_true")

    p_inspect = sub.add_parser("inspect", help="Inspect a specific audit_id in full detail")
    p_inspect.add_argument("audit_id", help="Recorded audit_id (e.g. aud_...)")
    p_inspect.add_argument("--json", action="store_true")

    p_seed = sub.add_parser("seed", help="Populate built-in Parallax demo audits and DPO pairs")
    p_seed.add_argument("--json", action="store_true")

    p_frame = sub.add_parser("frame", help="Run deterministic offline fact-vs-frame comparison")
    p_frame.add_argument("--prompt", required=True)
    p_frame.add_argument("--lens-a", required=True, help="Response A text")
    p_frame.add_argument("--lens-b", required=True, help="Response B text")
    p_frame.add_argument("--category", default="framing_synthesis")
    p_frame.add_argument("--json", action="store_true")

    p_code = sub.add_parser("code", help="Run deterministic AST blind code security comparison")
    p_code.add_argument("--prompt", required=True)
    p_code.add_argument("--contextual", required=True, help="Contextual code reply")
    p_code.add_argument("--blind", required=True, help="Entity-scrubbed blind code reply")
    p_code.add_argument("--extra-entity", action="append", default=[])
    p_code.add_argument("--json", action="store_true")

    p_curate = sub.add_parser("curate", help="Curate a rubric-scored SFT/DPO preference pair")
    p_curate.add_argument("--prompt", required=True)
    p_curate.add_argument("--chosen", required=True)
    p_curate.add_argument("--rejected", required=True)
    p_curate.add_argument("--category", default="general")
    p_curate.add_argument("--accuracy", type=int, default=5)
    p_curate.add_argument("--balance", type=int, default=5)
    p_curate.add_argument("--independence", type=int, default=5)
    p_curate.add_argument("--audit-id", default="")
    p_curate.add_argument("--json", action="store_true")

    p_export = sub.add_parser("export", help="Export rubric-filtered DPO or SFT JSONL dataset")
    p_export.add_argument("--format", choices=["dpo", "sft"], default="dpo")
    p_export.add_argument("--min-accuracy", type=int, default=4)
    p_export.add_argument("--min-balance", type=int, default=4)
    p_export.add_argument("--min-independence", type=int, default=4)
    p_export.add_argument("--filename", default="")
    p_export.add_argument("--json", action="store_true")

    sub.add_parser("mcp", help="Run zero-dependency JSON-RPC 2.0 Stdio MCP server")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    pkg = _load_parallax_package()

    cmd = args.command or "status"
    if cmd == "mcp":
        return serve_mcp_stdio(pkg)

    if cmd == "seed":
        res = pkg.storage_dpo.seed_demo_data()
        if getattr(args, "json", False):
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print(
                f"Seeded {res.get('audits_created', 0)} audits and "
                f"{res.get('pairs_created', 0)} preference pairs."
            )
        return 0

    if cmd == "inspect":
        res = pkg.tools.run_ledger_status(None, {"audit_id": args.audit_id})
        if getattr(args, "json", False):
            print(json.dumps(res, ensure_ascii=False, indent=2))
        elif not res.get("ok"):
            print(f"Error: {res.get('error')}", file=sys.stderr)
        else:
            aud = res["audit"]
            print(
                f"[{aud.get('audit_id')}] kind={aud.get('kind')} verdict={aud.get('verdict')} "
                f"created_at={aud.get('created_at')}"
            )
            print(f"Prompt: {aud.get('prompt', '')}")
            print(json.dumps(aud.get("payload", {}), ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if cmd == "frame":
        res = pkg.tools.run_frame_audit(
            None,
            {
                "prompt": args.prompt,
                "lens_a_text": args.lens_a,
                "lens_b_text": args.lens_b,
                "use_judge_llm": False,
                "category": args.category,
            },
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if cmd == "code":
        res = pkg.tools.run_code_audit(
            None,
            {
                "prompt": args.prompt,
                "contextual_reply": args.contextual,
                "blind_reply": args.blind,
                "extra_entities": args.extra_entity,
            },
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if cmd == "curate":
        res = pkg.tools.run_curate_pair(
            None,
            {
                "prompt": args.prompt,
                "chosen": args.chosen,
                "rejected": args.rejected,
                "category": args.category,
                "accuracy": args.accuracy,
                "balance": args.balance,
                "independence": args.independence,
                "audit_id": args.audit_id or None,
            },
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if cmd == "export":
        res = pkg.tools.run_export_dataset(
            None,
            {
                "format": args.format,
                "min_accuracy": args.min_accuracy,
                "min_balance": args.min_balance,
                "min_independence": args.min_independence,
                "filename": args.filename or None,
            },
        )
        if getattr(args, "json", False):
            print(json.dumps(res, ensure_ascii=False, indent=2))
        elif not res.get("ok"):
            print(f"Error: {res.get('error')}", file=sys.stderr)
        else:
            print(
                f"Exported {res.get('exported_count', 0)} {args.format.upper()} rows "
                f"(dropped={res.get('dropped_count', 0)}, quarantined={res.get('quarantined_count', 0)}) "
                f"-> {res.get('display_path') or res.get('path', '')}"
            )
        return 0 if res.get("ok") else 1

    # Default: status
    res = pkg.tools.run_ledger_status(
        None,
        {
            "kind": getattr(args, "kind", "all"),
            "limit": getattr(args, "limit", 10),
            "include_pairs": not getattr(args, "no_pairs", False),
        },
    )
    if getattr(args, "json", False):
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    kpis = res.get("kpis", {})
    print("Hermes Parallax Ledger Status:")
    print(
        f"  Audits: {kpis.get('total_audits', 0)} "
        f"(frame={kpis.get('frame_audits', 0)}, code={kpis.get('code_audits', 0)}, "
        f"passive={kpis.get('passive_flags', 0)}, context_degraded={kpis.get('context_degraded_count', 0)})"
    )
    print(
        f"  Preference pairs: {kpis.get('total_dpo_pairs', 0)} "
        f"(gold={kpis.get('gold_dpo_pairs', 0)})"
    )
    print(f"  Data dir: {res.get('data_dir', '')}")
    recent = res.get("recent_audits") or []
    if recent:
        print("  Recent audits:")
        for row in recent:
            print(
                f"    - {row.get('audit_id')} [{row.get('kind')}] {row.get('verdict')}: "
                f"{row.get('prompt_preview', '')}"
            )
    return 0


if __name__ == "__main__":
    try:
        rc = main()
        sys.stdout.flush()
    except BrokenPipeError:
        rc = 0
    raise SystemExit(rc)
