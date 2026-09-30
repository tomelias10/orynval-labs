# mcp-drift — implementation spec

The focused **Shadow-AI / AI-agent security wedge**. Discovers local AI agent
and [MCP](https://modelcontextprotocol.io) configurations and audits the
security-relevant facts about each connected server: what it runs, what it can
reach, what it is handed, and whether it has drifted from an approved baseline.

## Positioning

Developers add MCP servers and local agents to editors and shells in minutes;
security review takes weeks. Each server is an unaudited program with filesystem
reach, network egress, and access to environment secrets. `mcp-drift` is
deliberately **narrower than a network/agent gateway** — it is static,
read-only, local-only, and **never executes anything it discovers** — precisely
so it can be run in minutes on a laptop and in CI, rather than requiring a proxy
deployment.

## Safety posture

Read-only, offline, deterministic, secrets redacted. Critically: it parses
config **as data** and never runs a discovered `command`, never resolves a
discovered `url`, and never installs anything. Discovered commands are reported
as text only.

## Model

Two passes, mirroring `nhi-ghost`:

1. **Discovery** — walk the tree for agent/MCP config files and parse the server
   entries. A `Server` record has:
   - `Name` — the map key (e.g. `filesystem`, `github`).
   - `Source` — file + line where it was defined.
   - `Command`, `Args`, `Env` (stdio servers) **or** `URL` (remote servers).
   - `Signature` — `sha256` of the normalized server config, for baseline drift.

2. **Assessment** — one `Finding` per server; severity is the max over the
   server's risk factors; evidence enumerates each factor with its observed
   detail. A server with no risk factor is still emitted as an **INFO inventory
   entry** (knowing what is connected is itself the point).

### Config files discovered (v0)

Any JSON file whose parsed content contains a server map under `mcpServers` or
`servers`, where entries have a `command` or `url`. This covers Claude Desktop
(`mcpServers`), Cursor (`.cursor/mcp.json` → `mcpServers`), and VS Code
(`servers`). Filenames are not required to match a fixed list, but the common
ones (`.mcp.json`, `mcp.json`, `claude_desktop_config.json`,
`.cursor/mcp.json`, `.vscode/mcp.json`) are all covered by the shape match.

### Risk factors

| Factor | Severity | Confidence | Trigger |
|---|---|---|---|
| `secret-in-env` | HIGH | OBSERVED | an `env` value is a secret value, or an `env` key is secret-shaped (`*_TOKEN`, `*_API_KEY`, `*_SECRET`, `PASSWORD`, …) with a non-empty inline value |
| `broad-filesystem-scope` | HIGH / MEDIUM | OBSERVED | a filesystem-granting arg points at `/`, the home directory, or `$HOME`/`~` (HIGH); any other absolute-path grant (MEDIUM) |
| `risky-command` | HIGH / MEDIUM | OBSERVED | `curl … | sh`, `docker run --privileged` / `-v /:…`, auto-approve/`--yolo`/`--dangerously-skip-permissions` flags (HIGH); unpinned auto-install `npx -y` / `uvx` without a version (MEDIUM) |
| `remote-endpoint` | MEDIUM | OBSERVED | a `url` server → network egress to that host |
| `unapproved-server` | MEDIUM | INFERRED | a baseline exists and this server name is not in it |
| `baseline-drift` | HIGH | OBSERVED | a baseline exists and this server's signature differs from the approved one |

Severity of the finding is the max of its factors; a clean server is INFO.

### Baseline (drift detection)

If `.orynval/mcp-baseline.json` exists in the scanned tree, it is read as the
approved set:

```json
{ "servers": { "<server-name>": "<sha256-of-normalized-config>" } }
```

- discovered server not present in the baseline → `unapproved-server`
- discovered server whose signature differs → `baseline-drift`
- if **no** baseline file exists, drift factors are skipped entirely (no
  baseline ⇒ no false "unapproved" noise). Removed-server detection (in baseline
  but absent now) is deferred — there is no in-tree location to anchor it to.

A `--baseline <path>` flag is **deferred**; v0 uses the conventional in-tree
path so the whole scan stays a single read-only tree walk. `mcp-drift` can help
you *create* the baseline by taking the signatures from a JSON run.

## CLI

Uses `internal/cli`. `mcp-drift [flags] [path]` with the shared flags. Output:
terminal / JSON / SARIF / HTML / badge / share.

## Rules (IDs)

v0 ships one composite rule, `orynval.mcp.config-audit`, emitting one finding per
discovered server.

## Fixtures (synthetic)

Under `internal/mcp/testdata/`:
- `.mcp.json` — a `filesystem` server rooted at `/` (broad fs), a `github`
  server with an inline `GITHUB_TOKEN` in `env` (secret-in-env), a `remote`
  `url` server (remote-endpoint), and an `npx -y unpinned-pkg` server
  (risky-command).
- `.cursor/mcp.json` — a second config to prove multi-file discovery.
- `.orynval/mcp-baseline.json` — approves some servers so one shows as
  `unapproved-server` / `baseline-drift`.
- `clean/.mcp.json` — a single pinned, scoped, secret-free server (asserts it is
  INFO, not a false positive).

All tokens/paths are synthetic.

## Tests

- Each risk factor fires on its fixture server and not on the clean one.
- Baseline present → correct `unapproved-server` / `baseline-drift`; baseline
  absent → neither.
- Secret values in `env` are redacted in every format.
- No discovered command is ever executed (the code has no exec path; asserted by
  construction and by a test that the process makes no child processes — i.e.
  there is simply no os/exec import in the package).
- Determinism across two runs.

## One-command demo

`make demo-mcp` → `go run ./cmd/mcp-drift internal/mcp/testdata`.
