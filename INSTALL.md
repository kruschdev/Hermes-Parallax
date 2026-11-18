# Install `Hermes-Parallax`

These are instructions for a coding agent (Claude Code, Codex, Cursor, Windsurf, Nous Hermes Agent, or Antigravity) that a person asked to install and configure `Hermes-Parallax` on their machine.

`Hermes-Parallax` (`parallax`) is a zero-runtime-dependency Python `>= 3.11` epistemic triangulation, symmetric 6-pole fact-vs-frame lens (`parallax_frame_audit`), `NeutralOrg` blind AST + security-sink code counterfactual (`parallax_code_audit`), and rubric-gated TRL DPO / ChatML SFT dataset forge (`parallax_curate_pair`, `parallax_export_dataset`, `parallax_ledger_status`) built as a host-isolated (`plugins.isolation: host`) plugin for Nous Hermes Agent (`>= 0.22.3`), and also runnable standalone via its built-in Python CLI and 5-tool JSON-RPC 2.0 Stdio MCP server.

## 1. Check Prerequisites First (All at Once)

Run one read-only check before making any changes:

```bash
id -u
python3 --version 2>/dev/null || echo "MISSING: python3"
git --version 2>/dev/null || echo "MISSING: git"
hermes --version 2>/dev/null || echo "OPTIONAL_MISSING: hermes"
```

Evaluate the results:
1. **User check**: If `id -u` prints `0` (root), stop and ask the person to run you under a normal non-root user account.
2. **Python `>= 3.11` (Required)**: Confirm `python3 --version` is `3.11` or newer and supports `python3 -m venv`. If Python 3.11+ or `python3-venv` is missing, ask the person before installing it.
3. **Nous `hermes` CLI (Optional)**: If `hermes` is present, install and validate natively in `~/.hermes/plugins/` (Mode A). If `hermes` is not installed, use standalone checkout + CLI / Stdio MCP mode (Mode B).

## 2. Choose the Right Setup Mode

- **Mode A: Nous Hermes Agent Plugin Install + `.venv` Pytest Verification (Recommended when `hermes` CLI is installed)**: Installs `Hermes-Parallax` into `~/.hermes/plugins/hermes-parallax`, runs `hermes plugins validate` and `hermes plugins doctor parallax --ci`, and verifies all `10` end-to-end tests inside an isolated `.venv`.
- **Mode B: Standalone Checkout + `.venv` Pytest Verification + CLI / Stdio MCP Bridge (Works with or without Hermes Agent)**: Clones `https://github.com/kruschdev/Hermes-Parallax.git`, verifies `pytest` inside `.venv`, and exposes the 5 Parallax tools via CLI or JSON-RPC 2.0 Stdio MCP (and optionally links into `~/.hermes/plugins/` if Hermes is installed).

## 3. Install & Verify

### Mode A: Nous Hermes Agent Plugin Setup (When `hermes` CLI Is Available)

Install, enable, and validate the plugin through Hermes:

```bash
hermes plugins install https://github.com/kruschdev/Hermes-Parallax
hermes plugins enable parallax
hermes plugins validate ~/.hermes/plugins/hermes-parallax
hermes plugins doctor parallax --ci
```

Verify the full test suite inside an isolated Python `.venv` (Parallax has zero runtime dependencies; `pytest`, `fastapi`, and `httpx` are installed inside `.venv` solely to execute the unit, CLI/MCP, and `/parallax` web dashboard route tests):

```bash
cd ~/.hermes/plugins/hermes-parallax
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install pytest fastapi httpx
.venv/bin/pytest tests/ -q
```

### Mode B: Standalone Checkout, `.venv` Pytest & CLI Smoke Check

Clone into the current directory (or `~/src/Hermes-Parallax` if the current directory is `$HOME` or another unrelated repo; check `pwd` first), create an isolated `.venv`, and run `pytest`:

```bash
git clone https://github.com/kruschdev/Hermes-Parallax.git
cd Hermes-Parallax
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install pytest fastapi httpx
.venv/bin/pytest tests/ -q
```

Verify the zero-dependency standalone CLI entrypoint:

```bash
python3 . status --json
```

If Nous Hermes Agent is also installed on this machine and the person wants this checkout registered directly in `~/.hermes/plugins/`:

```bash
mkdir -p "$HOME/.hermes/plugins"
ln -sfn "$(pwd)" "$HOME/.hermes/plugins/hermes-parallax"
hermes plugins validate "$HOME/.hermes/plugins/hermes-parallax"
hermes plugins enable parallax
hermes plugins doctor parallax --ci
```

## 4. Connect to Hermes Auxiliary Slots or External MCP Clients

- **Inside Nous Hermes Agent**: Parallax works out of the box with zero configuration using the active Hermes model (`/parallax status`, `/parallax frame <topic>`, `/parallax code <spec>`, `/parallax export dpo 5 4 4`, plus the `/parallax` tab in `hermes dashboard`). Only add an `auxiliary:` block (`parallax_lens_a`, `parallax_lens_b`, `parallax_judge`) to Hermes config if the person asks to pin specific contrasting models.
- **External MCP Hosts (Claude Code, Cursor, Windsurf, Codex, Antigravity)**: Merge the zero-dependency Stdio MCP server entry into the person's active MCP config without overwriting existing servers (using `~/.hermes/plugins/hermes-parallax` or the real `pwd` of the `Hermes-Parallax` checkout):
  - **Claude Code CLI**:
    ```bash
    claude mcp add hermes-parallax -- python3 /absolute/path/to/Hermes-Parallax mcp
    ```
  - **Cursor (`~/.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), or Antigravity (`~/.gemini/antigravity/mcp_config.json`)**:
    ```json
    {
      "mcpServers": {
        "hermes-parallax": {
          "command": "python3",
          "args": ["/absolute/path/to/Hermes-Parallax", "mcp"]
        }
      }
    }
    ```
  - **Codex (`~/.codex/config.toml`)**:
    ```toml
    [mcp_servers.hermes-parallax]
    command = "python3"
    args = ["/absolute/path/to/Hermes-Parallax", "mcp"]
    ```

*(Replace `/absolute/path/to/Hermes-Parallax` with the real absolute checkout or `~/.hermes/plugins/hermes-parallax` path.)*

## Never

- **Never run `pip`, `pytest`, `python3`, or `hermes` with `sudo` or as `root`**.
- **Never run global `pip install` or pass `--break-system-packages`**; always create and use `.venv` (`python3 -m venv .venv` and `.venv/bin/pytest`).
- **Never invent API keys or modify Hermes `auth.json` or `.env` files**; Parallax declares `requires_env: []` and delegates live model completions exclusively through Hermes's host-owned `ctx.llm`.
- **Never overwrite an existing global MCP config file**; always read, parse, merge only the `hermes-parallax` key, and write it back cleanly.

## Tell the Person After

Share a concise status report:
1. **Install mode & paths**: Confirm where `Hermes-Parallax` was installed (`~/.hermes/plugins/hermes-parallax` or standalone checkout) and note its profile-scoped SQLite WAL ledger location (`<HERMES_HOME>/plugin-data/parallax/parallax.db`).
2. **Verification status**: Confirm `.venv/bin/pytest` passed all `10` tests (plus `hermes plugins validate` and `hermes plugins doctor parallax --ci` if Hermes is installed).
3. **Surfaces ready**: Note whether Hermes plugin commands (`/parallax status` and `hermes dashboard` -> `/parallax`), standalone CLI (`python3 <path> status`), and/or external IDE MCP registration are active.
4. **First-turn test prompt**: Suggest running `/parallax status` in Hermes or asking their MCP coding agent: `"Run parallax_ledger_status to verify Hermes-Parallax is connected."`
