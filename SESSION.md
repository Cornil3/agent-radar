# How this repo happened

A compact record of the session that produced it, kept because the decision trail is more
useful than the diff. Built 2026-09-23/24, ahead of an onsite interview.

## The detour that mattered

The first several hours went into interview *practice*, not a product: five simulated
take-home tasks with graded rubrics, a PDF of task cards, a step-by-step tutorial, and a
browser-based practice site with 47 graded steps.

Then this feedback, which reset everything:

> "this is super complicated. scratch all of that and build something simpler. maybe like a
> ctf, or a narrower task. u write with very complicated over engineered syntax."

That was correct, and it changed the code that followed. Everything in this repo is plain
loops and `if` statements - no comprehension nesting, no lambdas, no clever one-liners, few
type annotations. A security tool that a reviewer can't read in one pass is a security tool
nobody reviews. The practice material was replaced with 8 narrow CTF challenges, and then
with the question that actually produced this repo: *what does the product itself look like?*

The spec came first, as `PROMPT.md` - data shapes, rules, milestones, constraints (standard
library plus FastAPI, no ORM, no Docker, under ~600 lines). Then the code was built against
it. Two deliberate departures from the spec, both made while building: Claude Code plugins
are reported as agents, and the scanner masks secrets out of the arguments it sends.

## Bugs worth remembering

These are in here because each one taught something about the problem, not because they were
hard to fix.

**A raw token rendered in the console.** Secrets were masked in *files* but command
*arguments* were passed through untouched, so an agent configured as `crm-mcp --token ghp_...`
walked straight past the masking and into the UI. Fixed by masking args before transmission,
plus a regression test. The leak wasn't in the component built to handle secrets - it was in
the boring path next to it.

**The scan found its own homework.** The first real scan of the machine reported seven
agents; all seven were the session's own sample fixtures sitting on the Desktop. Fixed with
an exclude list (`excludes.txt`) and a permanent banner naming which source is displayed,
because a screenshot of made-up data and a screenshot of a real machine must never be
confusable.

**A real scan returned zero agents and that was correct.** It looked like a bug and was
called one, wrongly - the machine genuinely had no MCP servers configured. Worth recording:
in discovery tooling, "found nothing" and "failed to look" are indistinguishable from the
outside, which is why every report carries `files_read`, `seconds` and `stopped_early`.

**The scan was too slow to be honest.** Reading every file took 150 seconds to cover 2,336
files and hit the time limit - so every scan was partial. Restricting reads to files that
plausibly hold config (`.env`, `.json`, `.yaml`, `.py`, `.sh`, ...) got it to ~14,000 files
in 31 seconds. Coverage improved by reading *less*.

**`fetch` from a `file://` page.** Opening `web/index.html` directly from disk gives a page
with no server behind it, so `fetch("/api/rescan")` fails with `TypeError: Failed to fetch`
before any request leaves the browser - and the server log shows nothing, which makes it look
like a server bug. The page now detects its own protocol and says what to open instead.

**An incidental finding, and the most interesting one.** Claude Code keeps a copy of every
file a session reads under `~/.claude/`, plus the full transcript. Open a `.env` in an agent
session once and its contents live on elsewhere on disk afterwards. That is a real
secret-spread mechanism created by agent tooling itself - exactly the class of problem this
product exists to find - and it's why two `.claude/` paths are in the default exclude list.

## Things that turned out to be true

- The interesting part is the **identity function**, not the rules. Deciding when two
  configs are the same agent is the product; scoring is bookkeeping around it.
- Masking secrets *before* hashing the identity is a one-line decision with a long tail: get
  it wrong and every token rotation silently forks an agent into two, and the inventory rots
  over months without ever looking broken.
- Recomputing risk on read costs CPU and buys the ability to answer "why is this a 70?"
  after the rules have changed. Stored scores can't answer that.
- Seed the demo data early. A system that finds nothing demos as a system that doesn't work.
