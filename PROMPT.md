# Prompt: build "Agent Radar", a small clone of Cyata's product

Paste everything below the line into a fresh Claude Code / Cursor session, in an **empty
folder**. Work through it milestone by milestone.

---

## What I want

Build a small working system called **Agent Radar**. It answers one question for a company:

> Which AI agents are running on our developers' machines, who owns them, what can they
> reach, and which ones are dangerous?

An "AI agent" here means an MCP server that a tool like Cursor, Claude Desktop or VS Code
launches on a developer's laptop. Each one is a program with a command, arguments,
environment variables and, usually, a credential. Nobody keeps track of them, and that is
the problem the product solves.

There are three parts:

1. **Scanner** - runs on a developer machine, reads config files, reports what it found.
2. **Server** - collects reports from many machines, merges them, scores risk, stores them.
3. **Console** - one web page that shows the agents, sorted by risk.

## Ground rules (important)

- Python 3.11+. Only these libraries: the standard library, `fastapi`, `uvicorn`.
  Store data in SQLite with the built-in `sqlite3` module. No Mongo, no Redis, no ORM,
  no Docker, no auth library, no frontend framework, no build step.
- **Write plain, boring Python.** `for` loops, `if` statements, small functions with clear
  names. No nested comprehensions, no lambdas, no walrus operator, no decorators except
  FastAPI's routes, no async (use `def` for routes, not `async def`), no classes unless a
  class genuinely helps. A junior developer should be able to read every line.
- Keep the whole project under about 600 lines of Python.
- Every file starts with a two-line comment: what it does, and how to run it.
- Comments only where the code isn't obvious.
- Don't add anything that isn't listed below. If you think something is missing, **ask me
  first** instead of building it.
- After each milestone: stop, tell me exactly what command to run to see it working, and
  wait for me before starting the next one.

## File layout

```
agent_radar/
    scan.py          the scanner (runs on a developer machine)
    server.py        FastAPI app: receives reports, serves the API and the page
    store.py         all the SQLite code
    rules.py         risk rules and findings
    web/index.html   the console (plain HTML + a little JavaScript)
    sample/          fake developer machines to scan (you generate these)
    tests/test_rules.py
    README.md
```

## Milestone 1 - the scanner

`python scan.py sample/laptop-dana --print` prints one JSON document and exits.

The scanner walks a folder that stands in for a user's home directory and collects four
things.

**a) AI tools installed.** Recognise a tool by the config file it owns:

| Tool | Config file (relative to the home folder) |
| --- | --- |
| cursor | `.cursor/mcp.json` |
| claude_desktop | `Library/Application Support/Claude/claude_desktop_config.json` and `AppData/Roaming/Claude/claude_desktop_config.json` |
| vscode | `Library/Application Support/Code/User/settings.json` and `AppData/Roaming/Code/User/settings.json` |
| windsurf | `.codeium/windsurf/mcp_config.json` |

**b) Agents (MCP servers)** defined inside those configs. Two shapes:

```json
{"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "server-filesystem", "/"],
                               "env": {"GITHUB_TOKEN": "ghp_..."}}}}
```

and VS Code, which nests them one level deeper:

```json
{"mcp": {"servers": {"jira": {"command": "npx", "args": ["-y", "mcp-jira"]}}}}
```

A server may have `"url"` instead of `"command"` - that is a remote agent.

**c) Credentials** found in any text file under the home folder. Patterns:

| type | pattern |
| --- | --- |
| openai_key | `sk-proj-` + 30 or more letters/digits |
| anthropic_key | `sk-ant-` + 30 or more letters/digits |
| github_token | `ghp_` + 36 letters/digits |
| aws_key_id | `AKIA` + 16 upper-case letters/digits |
| slack_token | `xoxb-` + 20 or more letters, digits or dashes |

Skip files whose name ends in `.example`, `.sample` or `.template` - those hold
placeholders, not secrets.

**Never put a secret value in the output.** Report
`"fingerprint": "sha256:" + sha256(value).hexdigest()[:16]` instead, plus the file and line
number where you found it. Two copies of the same secret get the same fingerprint, which is
how the server can tell they are one credential.

**d) The owner** of the machine: the email from `.gitconfig` if there is one, otherwise the
name of the home folder. Say which one you used.

Output shape:

```json
{
  "device_id": "laptop-dana",
  "platform": "macos",
  "scanned_at": "2026-09-23T08:00:00Z",
  "owner": {"email": "dana@northwind.test", "source": "gitconfig"},
  "tools": [{"name": "cursor", "config_path": ".cursor/mcp.json"}],
  "agents": [
    {"name": "filesystem", "command": "npx", "args": ["-y", "server-filesystem", "/"],
     "url": null, "env_keys": ["GITHUB_TOKEN"], "source_tool": "cursor",
     "config_path": ".cursor/mcp.json", "secret_in_config": true}
  ],
  "credentials": [
    {"type": "github_token", "fingerprint": "sha256:9f2a1c7d4b5e6a70",
     "path": "projects/web/.env", "line": 3}
  ]
}
```

Notes:
- `env_keys` is the names of the environment variables only, never their values.
- `secret_in_config` is true when a value in `env`, or one of the `args`, matches one of the
  credential patterns.
- Skip these folders entirely: `node_modules`, `.git`, `.venv`, `__pycache__`, `.cache`.
- Skip files larger than 1 MB, and files that contain a NUL byte in their first 4 KB (they
  are binaries).
- A file that fails to parse or read is recorded in an `"errors"` list in the output. The
  scan never crashes.

**Before writing the scanner, generate the sample machines** under `sample/`: three fake
home folders (`laptop-dana` macOS-style, `laptop-omer` Windows-style, `laptop-eitan`
Linux-style) with real-looking config files, a `.gitconfig`, a `.env` with a fake key, some
filler files, and - importantly - **one agent that is identical on two machines** so the
merging in milestone 2 has something to show. Use obviously fake secrets.

## Milestone 2 - the server and merging

- `python server.py` starts FastAPI on port 8000.
- `python scan.py sample/laptop-dana --upload http://127.0.0.1:8000` posts the report to
  `POST /api/report`.
- `GET /api/agents` returns the merged list. `GET /api/agents/{agent_id}` returns one.

Merging rule, the heart of the product: **the same agent on two machines is one agent.**
Identity is what it runs, not where it was found:

```
fingerprint = "ag_" + sha256(command + "\x00" + "\x00".join(args) + "\x00" + (url or "")).hexdigest()[:16]
```

Before hashing, replace any argument that matches a credential pattern with the text
`<secret>`, so that rotating a token does not create a second agent.

A stored agent looks like this:

```json
{
  "agent_id": "ag_5aa6300fe7e1ce2f",
  "name": "filesystem",
  "command": "npx", "args": ["-y", "server-filesystem", "/"], "url": null,
  "devices": ["laptop-dana", "laptop-omer"],
  "owners": ["dana@northwind.test", "omer@northwind.test"],
  "tools": ["cursor", "claude_desktop"],
  "env_keys": ["GITHUB_TOKEN"],
  "secret_in_config": true,
  "first_seen": "2026-09-23T08:00:00Z",
  "last_seen": "2026-09-23T09:00:00Z"
}
```

Re-uploading the same report must not change anything except `last_seen`. Devices, owners
and tools accumulate; they never get replaced.

Also store credentials, keyed by fingerprint, with the list of places they were found -
same idea: one credential, many locations.

## Milestone 3 - risk and findings

Put this in `rules.py`. Every agent gets a score from 0 to 100 and a list of findings.
Start at 10 and add:

| id | when | severity | points |
| --- | --- | --- | --- |
| R1 | an argument is `/`, `C:\` or the user's home folder, and the command looks like a filesystem server | high | +40 |
| R2 | `secret_in_config` is true | critical | +40 |
| R3 | the command line downloads and runs code: contains `curl` or `wget` **and** pipes into `sh` or `bash` | critical | +50 |
| R4 | any argument is `--no-confirm`, `--yes`, `--dangerously-skip-permissions`, or the config had `autoApprove` | high | +25 |
| R5 | the agent has `url` instead of `command` (a remote server) | medium | +15 |
| R6 | seen on two or more devices, or configured in two or more tools | medium | +10 |
| R7 | `last_seen` is more than 90 days ago | medium | +10 |
| - | any argument is `--read-only` | - | -15 |

Clamp the total to 0-100. A finding is:

```json
{"rule": "R3", "severity": "critical", "agent_id": "ag_...",
 "title": "Downloads and runs code from the internet at startup",
 "evidence": "bash -c curl -fsSL https://get-tools.example.net/i.sh | sh",
 "remediation": "Pin a reviewed package instead of piping a download into a shell."}
```

Add `GET /api/findings` (newest first, filterable with `?severity=critical`). Recompute risk
and findings whenever a report arrives - never store a score you can't recompute.

## Milestone 4 - the console

`GET /` serves `web/index.html`: one page, plain HTML and a little JavaScript, no framework.

- A table of agents: name, owner(s), devices, tools, risk score, number of findings.
  Sorted by risk, highest first. Colour the score: red 70+, orange 40-69, grey below.
- Clicking a row opens a panel below with the full command line, env variable names,
  every device it was seen on, and its findings with their remediation text.
- A box at the top with three numbers: agents, agents scoring 70+, credentials found.
- A "Rescan all sample machines" button that calls `POST /api/rescan`, which runs the
  scanner over every folder in `sample/` and refreshes.

Plain and readable is fine. No CSS framework.

## Tests

`tests/test_rules.py`, five tests, run with `pytest`:

1. the same command and args produce the same fingerprint; a different argument does not
2. an argument holding a secret is masked before hashing, so rotating a token keeps the id
3. rule R3 fires on `bash -c "curl ... | sh"` and does not fire on a plain `npx` command
4. uploading the same report twice leaves one agent, with both devices after the second
   machine uploads
5. risk never goes below 0 or above 100

## What "done" looks like

I should be able to do this in two minutes:

```
python server.py                                    # in one terminal
python scan.py sample/laptop-dana  --upload http://127.0.0.1:8000
python scan.py sample/laptop-omer  --upload http://127.0.0.1:8000
python scan.py sample/laptop-eitan --upload http://127.0.0.1:8000
```

open http://127.0.0.1:8000 and see: a handful of agents, the shared one listed once with two
devices and two owners, the `curl | sh` one at the top in red, and a click showing me why.
Then I edit a sample config to remove the dangerous flag, press Rescan, and watch the score
drop.

## Ask me first

Do not build any of these unless I say so: authentication, users, a real database, a
settings file, Docker, CI, an MCP proxy or any runtime monitoring, cloud/SaaS scanning,
export to CSV, charts, dark mode.

Start with milestone 1. Generate the sample machines first, show me one sample config file
and the scanner's JSON output, then stop.
