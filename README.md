# Agent Radar

A small version of what Cyata sells: find the AI agents running on developers' machines,
work out who owns them and what they can reach, and show the dangerous ones first.

An "agent" here is an MCP server that a tool like Cursor, Claude Desktop, VS Code or
Windsurf launches on a laptop. It is a command with arguments, environment variables and
usually a credential. Nobody keeps a list of them, which is the problem.

## Run it

```
pip install fastapi uvicorn
python make_sample.py                  # builds three fake laptops under sample/
python server.py                       # http://127.0.0.1:8000
```

Then, in another terminal:

```
python scan.py sample/laptop-dana  --upload http://127.0.0.1:8000
python scan.py sample/laptop-omer  --upload http://127.0.0.1:8000
python scan.py sample/laptop-eitan --upload http://127.0.0.1:8000
```

Open http://127.0.0.1:8000 and you will see ten agents.

The page has a switch in the top right:

- **Sample machines** - the three fake laptops in `sample/`. Made-up data, safe to demo.
- **This computer** - a real scan of your own home folder. Takes up to 90 seconds.

**Rescan** re-runs whichever one is showing. A banner always says which of the two you are
looking at, because a screenshot of made-up data and a screenshot of a real machine should
never be confusable.

To see what a scanner sends without a server running:

```
python scan.py sample/laptop-dana --print
```

Tests:

```
python -m pytest tests -q
```

## What the demo shows

- **quick-setup, risk 100.** Its command downloads a script from the internet and pipes it
  into a shell at startup, and it keeps a token in its config.
- **filesystem, one agent on two machines.** Dana runs it in Cursor, Omer runs it in Claude
  Desktop, with identical arguments. It appears **once**, with both machines and both tools.
  That merge is the core of the product: you revoke one thing, not two.
- **One GitHub token in three places.** `/api/credentials` shows it as a single credential
  with three locations - and only as a fingerprint.
- Edit a config under `sample/`, press Rescan, and watch the score change.

## Scanning your own computer

```
python scan.py "C:/Users/you" --out my_machine.json
python scan.py "C:/Users/you" --upload http://127.0.0.1:8000 --skip-secrets
```

Flags: `--skip-secrets` (agents only, fast), `--max-seconds N` (budget, default 120),
`--exclude TEXT` (repeatable), `--out FILE`, `--print`.

Copy `excludes.example.txt` to `excludes.txt` to keep folders out of the **This computer**
scan. Two entries are there by default, and the reason is worth knowing:

```
.claude/file-history
.claude/projects
```

Claude Code keeps a copy of every file a session reads, plus the session transcript. Open a
`.env` in a session once and its contents live on under `~/.claude/` afterwards - which is a
real way secrets spread, and also a way to flood this scan with copies of things you already
know about.

Two honest notes about any scan:

- It only reads files that plausibly hold text config (`.env`, `.json`, `.yaml`, `.py`,
  `.sh`, ...). Reading every file on a real machine took 150 seconds to get through 2,336
  files; with the filter it does ~14,000 in 30.
- The report carries `files_read`, `seconds` and `stopped_early`. A scan that ran out of
  time, or that excluded half your disk, is not a clean bill of health, and the tool says so
  rather than quietly implying otherwise.

## The three ideas worth knowing

**1. Identity is what an agent runs, not where you found it.**

```python
agent_id = "ag_" + sha256(command + "\0" + "\0".join(masked_args) + "\0" + url)[:16]
```

Arguments holding secrets are replaced with `<secret>` before hashing, so rotating a token
does not create a phantom second agent. That is `rules.agent_id()`.

**2. The secret value never leaves the machine.** The scanner reports
`sha256(value)[:16]` plus the file and line where it found it, and masks secrets out of the
arguments it sends. Two copies of the same secret share a fingerprint, which is how the
server knows one token is pasted in three files without ever seeing it.

**3. Risk is recomputed, never stored.** `rules.evaluate()` runs every time you ask for an
agent, so changing a rule changes every score immediately, and a score can always be
explained by the findings next to it.

## Rules

| id | fires when | severity | points |
| --- | --- | --- | --- |
| R1 | a filesystem server is pointed at `/`, a drive root or a whole home folder | high | +40 |
| R2 | a credential is written in the agent's config | critical | +40 |
| R3 | the launch command downloads code and pipes it into a shell | critical | +50 |
| R4 | it runs tools without asking (`--no-confirm`, `--yes`, `autoApprove`) | high | +25 |
| R5 | it is a remote server someone else operates (`url` instead of `command`) | medium | +15 |
| R6 | the same agent is configured on several machines or in several tools | medium | +10 |
| R7 | it has not been seen for more than 90 days | medium | +10 |
| - | `--read-only` | - | -15 |

Score starts at 10 and is clamped to 0-100.

## Files

```
scan.py          the scanner: reads one machine, prints or uploads a report
rules.py         identity, secret patterns, risk rules - plain functions, no I/O
store.py         SQLite: merges reports, one row per agent and per credential
server.py        FastAPI: receives reports, serves the API and the page
web/index.html   the console - one file, no framework
make_sample.py   builds the three fake machines
tests/           six tests, the important ones being identity and "no raw secret"
```

## What this is not

Real discovery needs far more than config files: running processes, network egress to model
APIs, browser extensions, SaaS and cloud agents, and agents built in-house that use no MCP
config at all. There is no authentication here - a real endpoint agent needs a device
identity and a signed policy bundle, or the server will happily believe anyone. Runtime
monitoring (what the agent actually did) is a separate piece, and the interesting one:
this system knows what an agent *can* do, not what it *did*.

R7 cannot fire in a fresh demo, because every machine has just reported in.

## Where this came from

`PROMPT.md` is the full specification this repo was built from: the data shapes, the rules,
the milestones and the constraints (plain Python, standard library plus FastAPI, no ORM, no
Docker, under ~600 lines). The code follows it, with two deliberate additions made while
building: Claude Code plugins are reported as agents, and the scanner masks secrets out of
the arguments it sends after a demo showed a token rendered in the console.
