# GPT Repo MCP

**Let ChatGPT work from your local repositories — safely.**

[![CI](https://github.com/CAHN91/gpt-repo-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/CAHN91/gpt-repo-mcp/actions/workflows/ci.yml)
![Node.js >=20](https://img.shields.io/badge/Node.js-%3E%3D20-339933)
[![License: MIT](https://img.shields.io/badge/License-MIT-111111)](LICENSE)
![Writes opt-in](https://img.shields.io/badge/Writes-opt--in-157f53)

GPT Repo MCP is a local-first, read-mostly MCP server that connects ChatGPT to explicitly approved repositories. Your files stay on your machine, and you control per-repository permissions (`read`, `write`, or `ship`).

> Tool-only MCP server — no custom ChatGPT UI, and not affiliated with OpenAI, ChatGPT, Anthropic, or the Model Context Protocol maintainers.

## Key Capabilities

- **Explore & search** — Map repository structure, search code, trace symbols, and build project briefs.
- **Large & multi-file reading** — Stream large text files by line range (`repo_fetch_file`, up to 10 MiB default / 50 MiB max, 256 KB default / 2 MiB max chunks) and batch-read via `repo_read_many` (up to 100 files / 1.5 MB default, configurable up to 250 files / 4 MiB) with resumable pagination.
- **Hardened read-only Git inspection** — `repo_git_inspect` exposes 12 allowlisted commands (`status`, `branch`, `tag`, `log`, `diff`, `commit_tree`, `file_tree`, `show`, `blame`, `rev_parse`, `merge_base`, `shortlog`) in every mode, with structured inputs and no shell execution.
- **Opt-in write & validation workflows** — Policy-checked single/multi-file edits (`write` mode), approved validation profiles, real diff review, recovery, and local commits (`ship` mode). Never runs arbitrary shell commands, pushes, or deploys.

## How ChatGPT Works

Describe the goal in normal language; ChatGPT selects from 47 policy-checked tools along the flow **Understand → Edit → Validate → Review → Local commit**, while the server independently enforces every boundary.

## Quick Start

Requires Node.js >=20, npm, Git, ChatGPT Developer Mode, and an HTTPS tunnel (e.g. ngrok).

### 1. Install & create starter config

```bash
git clone https://github.com/CAHN91/gpt-repo-mcp.git
cd gpt-repo-mcp
npm install
npm run build
cp config.example.json config.local.json
```

The starter `config.local.json` is valid out of the box with an empty repository list and default read `limits`.

### 2. Approve a repository

```bash
npm run add -- /path/to/your/repo
```

Use `npm run add -- <path> --mode <mode>` to set an explicit `read`, `write`, or `ship` mode non-interactively. Manage repos anytime with `npm run list`, `npm run remove -- <repo_id>`, and `npm run doctor`.

### 3. Start & connect ChatGPT

```bash
npm run connect        # Starts server + built-in ngrok tunnel
npm run dev            # Local server only (default port 8787)
```

Copy the printed MCP URL into ChatGPT Developer Mode connector settings. Need ngrok setup? See [Install ngrok from zero](docs/SETUP.md#install-ngrok-from-zero). For Cloudflare or the OpenAI Secure MCP Tunnel (`npm run connect:secure`), see [Connection options](docs/CONNECTION_OPTIONS.md).

## Configuration

- `npm run dev`, `npm start`, and `npm run connect` automatically load `./config.local.json` (git-ignored, created from `config.example.json`) when `GPT_REPO_CONFIG` and `REPO_READER_CONFIG` are unset.
- Set `GPT_REPO_CONFIG=/path/to/config.json` to load a different config file (`PORT` is respected by `npm run connect`). Relative repository `root` paths resolve against the config directory.
- Customize read budgets via the optional top-level `limits` block (`max_files`, `max_bytes_per_file`, `max_file_bytes`, `max_total_bytes`, `max_read_many_tree_pages`). Config validation is strict — run `npm run check:config` after editing. See [Setup & Read Limits](docs/SETUP.md#read-limits).

## Safety

- **Approved roots only** — Repo-relative paths sandboxed against traversal and symlink escapes.
- **Opt-in writes** — Read-only by default; edits enforce allowed/denied paths, size caps, stale-state checks, and secret guards.
- **Hardened Git & reads** — Shell-free Git runner rejecting flag injection and `.git/` access, validated read limits, secret-path blocking, and linear-time secret redaction.
- **No arbitrary execution or push** — Validation uses pre-approved profiles only; push and deploy remain outside the server.

Full threat model and guarantees: [Security](docs/SECURITY.md).

## Docs

- [Setup](docs/SETUP.md) — Installation, config, read limits, and troubleshooting
- [ChatGPT Connection](docs/CHATGPT_CONNECT.md) — Connector setup inside ChatGPT
- [Capabilities](docs/CAPABILITIES.md) — Example prompts and supported workflows
- [Tool Surface](docs/TOOL_SURFACE.md) — Full reference of all 47 tools
- [Security](docs/SECURITY.md) — Threat model, boundaries, and what leaves your machine
- [Architecture](docs/ARCHITECTURE.md) — Server internals and design
- [Write Workflows](docs/WRITE_WORKFLOWS.md) · [Connection Options](docs/CONNECTION_OPTIONS.md)

## License

MIT. See [LICENSE](LICENSE).
