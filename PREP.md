# Defending this in the room

Two hours to build it, one hour to talk about it. The hour is worth more than the two
hours. Nobody is impressed by the code; they are deciding whether you understand what you
built and whether you would be honest about it at 2am when it breaks.

The one thing to internalise: **you are not defending the code, you are defending the
decisions.** Every "why did you do X" has a real answer below. If you don't know one, say
"I don't know, here's how I'd find out" and move on. That answer scores better than a bluff,
and in a security team it scores *much* better.

---

## 1. The opening (60 seconds, say it before you show anything)

Lead with the problem, not the stack. A demo that starts with "so I used FastAPI" has
already lost the room.

> Developers are installing AI agents on their laptops faster than anyone can track them.
> An MCP server is a process, launched with arguments, holding a credential, with access to
> a filesystem or a SaaS account - and it is configured by editing a JSON file that nobody
> reviews. There is no inventory. So I built the inventory: a collector that reads those
> configs on each machine, and a server that merges them into one row per agent, scored by
> how much damage it could do.

Then: "Two hours, so it does config files only. I'll be clear about what it misses."

That last sentence buys you enormous credit. Say it early, on purpose.

---

## 2. The demo (5 minutes, rehearse the exact clicks)

Have it already running before you start talking. `python server.py`, browser open at
`http://127.0.0.1:8000`, **sample** source showing. Never open the HTML file directly - it
has no server behind it and the page will tell you so.

Click in this order, and say the line next to each:

1. **The table, sorted by risk.** "Ten agents across three laptops. Sorted by blast radius,
   not by name, because the only question a security team asks is what to look at first."
2. **`quick-setup`, risk 100.** "Its launch command downloads a shell script from the
   internet and pipes it into a shell, every time the tool starts. And it carries a token.
   That's two findings, and it's the one you'd act on today."
3. **`filesystem`, one row, two machines, two tools.** *This is the moment.* "Dana runs it
   in Cursor, Omer runs it in Claude Desktop. Identical command. It appears **once**. That's
   the whole product: you revoke one thing, not two, and your count of agents is a count of
   agents rather than a count of config files."
4. **`legacy-crm`, showing `--token <secret>`.** "The value never left the laptop. The
   server knows the token exists and can correlate it across files, because it has the
   fingerprint - but nobody who breaks into this server gets a credential."
5. **The switch → This computer.** "Same collector, pointed at my own home folder. This is
   real." (Know the number it returns on your machine, and say it before it appears.)

Then stop clicking. Don't tour the code unless asked.

---

## 3. The whiteboard (draw this, don't describe it)

```
 laptop            scan.py            server.py           web/index.html
 ┌────────────┐    ┌────────────┐     ┌──────────────┐    ┌─────────────┐
 │ mcp.json   │───▶│ parse      │────▶│ merge (sqlite│───▶│ table,      │
 │ .env       │    │ fingerprint│ HTTP│ one row/agent│    │ sorted by   │
 │ settings   │    │ mask       │ JSON│ score on read│    │ risk        │
 └────────────┘    └────────────┘     └──────────────┘    └─────────────┘
                          │                   ▲
                          └──── rules.py ─────┘
                          (pure functions, no I/O, used by both sides)
```

Say while drawing: "`rules.py` sits under both ends. The collector uses it to build identity
and mask secrets, the server uses it to score. One definition of what an agent *is*, so the
two halves can never drift apart."

Four files, ~600 lines. If they ask what each does:

| file | job |
| --- | --- |
| `scan.py` | runs on the endpoint, reads configs, emits a JSON report |
| `rules.py` | identity, secret patterns, risk rules. Pure functions, no I/O, easy to test |
| `store.py` | SQLite merge: one row per agent, one per credential, idempotent |
| `server.py` | receives reports, scores on read, serves the API and the page |

---

## 4. The four decisions (this is the actual interview)

### Thin collector, thick server

The scanner **never scores anything**. It reports facts.

*Why:* rules change weekly, and you cannot redeploy to 500 laptops every time you adjust a
threshold. Also, a report collected last month can be re-scored under today's rules - which
matters the day a new attack class is published and someone asks "were we exposed?"

*What it costs:* more data on the wire, and the endpoint can't warn locally. Fine trade.

### Identity is what an agent runs, not where you found it

```python
agent_id = "ag_" + sha256(command + "\0" + masked_args + "\0" + url)[:16]
```

Two consequences, and both are demonstrable:

- The same agent on two laptops in two different tools is **one** row, with both machines
  and both owners attached. Dedup is the difference between a useful inventory and a list.
- Secret-looking arguments are masked **before** hashing, so rotating a token doesn't fork
  one agent into two ghosts. This is subtle, it is the kind of bug that quietly ruins an
  inventory over months, and pointing it out unprompted is worth a lot.

### The secret value never leaves the machine

The scanner sends `sha256(value)[:16]`, plus the file and line where it found it.

*Why:* a tool built to find secret sprawl must not become the largest pile of secrets in the
company. Correlation still works - same value, same fingerprint - which is how the server
can say "this one token is pasted in three files on two machines" while never holding it.

There is a test asserting no raw secret appears in a report. **Name that test out loud.**
It is the test that guards the product's central promise.

### Risk is recomputed on read, never stored

`rules.evaluate()` runs on every request.

*Why:* change a rule and every score changes immediately, and a score is always explainable
by the findings sitting next to it. Stored scores go stale, and the first time someone asks
"why is this a 70?" after the rules moved, you have no answer.

*What it costs:* CPU on read. It's the first thing that stops scaling, and the fix is a
cache keyed on `(agent_id, rules_version)`, invalidated when a rule changes.

**Plus one, if it comes up:** ingest is idempotent. Rescan the same laptop and you get the
same rows with lists accumulated, not duplicated - because a scanner that runs hourly must
not inflate your inventory.

---

## 5. Volunteer the limits before they dig for them

Do this at the end of the architecture walk, unprompted. It is the single highest-scoring
minute available to you, because finding the holes is literally their job, and the candidate
who found them first is the candidate who thinks like them.

- **Config files only.** Misses running processes, network egress to model APIs, browser
  extensions, SaaS and cloud agents, and anything built in-house that speaks to an LLM API
  without an MCP config. Config discovery finds *the ecosystem's* agents, not all agents.
- **No authentication on ingest.** Right now the server believes anyone who can POST. That
  is the first thing I'd add, and until it exists the inventory is a claim, not a fact.
- **It knows what an agent *can* do, not what it *did*.** Runtime behaviour is a separate
  system and the more interesting one. This is posture, not detection.
- **A partial scan is not a clean bill of health.** Which is why every report carries
  `files_read`, `seconds` and `stopped_early`, and the UI shows them. A tool that silently
  returns "0 agents" because it timed out is worse than no tool.

That last bullet has a story behind it - use it (see §7).

---

## 6. Hostile questions, with answers

**"Two people run the identical command for different reasons. Same agent?"**
Yes - same code, same capability, same blast radius, so the same thing to revoke. Ownership
differs, which is why `owners` is a list rather than a field. If you needed per-team
separation the scope key becomes `(agent_id, owner)`, but the *action* is still per agent.

**"I rename the binary and your fingerprint breaks."**
Correct. Normalisation is a treadmill I chose not to run in two hours. I'd normalise the
obvious cases - whitespace, and the package name for known runners like `npx` and `uvx` -
and accept the rest. Worth being precise: the merge is a **convenience for the operator**,
not a security boundary. Nothing is trusted because it merged.

**"Your scanner reads `.env` files. Isn't the scanner now the risk?"**
Yes, and that's why it's the most conservative component in the system. It never transmits a
value, it masks secrets out of the arguments before they're sent, there's a final scrub pass,
and a test that fails if a raw secret ever appears in a report. A tool with this blast radius
has to hold itself to a higher standard than the thing it's auditing.

**"What's your false positive rate?"**
I don't have labelled data, so I won't quote a number. Qualitatively: `curl | sh` is
near-zero false positives, so it's 50 points. A filesystem server pointed at a home folder
has real false positives - some people legitimately do that - so it's 40 and phrased as
something to review. A remote URL isn't a finding at all, it's context, which is why it's 15.
The metric I'd actually track in production is **suppression rate per rule**: a rule everyone
mutes is a bad rule, and that's the feedback loop I'd build first.

**"What's the false negative you're most worried about?"**
An agent with no config file. Something launched by hand from a terminal, or an in-house
script hitting an LLM API directly. Nothing in this design sees those, and no amount of
polishing config parsing will fix it - it needs process and network telemetry.

**"Why SQLite / FastAPI?"**
Two-hour constraint, and nothing in the design depends on either. Two tables and a merge
function; the schema is boring on purpose.

**"How would you scale it?"**
Collectors scale by themselves - one per endpoint, no coordination. The server is the
bottleneck: reports are append-only so they go on a queue, SQLite becomes Postgres, and the
scoring-on-read cache I mentioned goes in. None of that is interesting, which is why I spent
the two hours on identity instead.

**"How do you know it works?"**
Six tests. The two that matter are *identity survives a token rotation* and *no raw secret
in a report*. The rest are bookkeeping. If I had more time the next test is a corpus of real
malformed configs, because that's where scanners actually die.

**"What would you build next?"**
Auth on ingest, because without it the data can't be trusted. Then process discovery,
because config files miss anything launched by hand. Then the suppression feedback loop.
In that order, and I'd resist the UI.

---

## 7. The story to tell (have this ready, it's your best material)

If they ask "what went wrong" or "what surprised you" - and in an AI-security interview they
will - use one of these. Both are true, which is why they land.

**The token in my own console.** While demoing, a real-looking token rendered in the UI,
because I was masking secrets in *files* but passing command *arguments* through untouched.
An agent configured as `crm-mcp --token ghp_...` walked straight past the masking. I added
arg masking before transmission and a regression test. The point: the leak wasn't in the
scary component, it was in the boring path nobody was looking at - and the fix isn't the
mask, it's the test that fails if anyone removes it.

**The scanner that found my own homework.** The first real scan of my machine returned seven
agents. They were my own sample fixtures on the Desktop. A discovery tool that can't tell its
own artefacts from the environment produces confident nonsense, so scans take an exclude list
and the UI always shows which source you're looking at - because a screenshot of made-up data
and a screenshot of a real machine must never be confusable.

**And the thing I didn't expect:** Claude Code keeps a copy of every file a session reads
under `~/.claude/`. Open a `.env` once in an agent session and its contents live on somewhere
else on disk afterwards. That's a real secret-spread mechanism created by agent tooling
itself - and it's exactly the class of problem this product exists to find.

---

## 8. Running the hour

| time | what |
| --- | --- |
| 0-5 | problem statement + demo, already running |
| 5-15 | whiteboard, four decisions |
| 15-25 | the limits, volunteered |
| 25-55 | their questions - this is the real hour |
| 55-60 | what you'd build next, in priority order |

If you're losing the room, go back to the `filesystem` row merging across two laptops. That
one screen explains the product.

---

## 9. Things not to say

- "It's production ready." It isn't, and they know exactly how it isn't.
- Any number you can't defend - false positive rates, agent counts, "it scans in 30 seconds"
  unless you measured it.
- "I'd use Kafka." Nobody asked, and it signals you'd rather talk about infrastructure than
  the problem.
- "That's out of scope." Say what it *would* take instead.
- Don't apologise for what's missing. State it flatly and move on. "No auth yet, that's
  first on the list" is strong. "Sorry, I didn't have time for auth" is weak. Same fact.

---

## 10. If you have to build it again in two hours

Order matters more than speed. **At every 20-minute mark you must have something runnable** -
never carry broken code across a boundary, because if time runs out you demo whatever exists.

| time | milestone |
| --- | --- |
| 0:00-0:15 | one config format, one tool, print JSON to stdout. Get a real fact on screen |
| 0:15-0:35 | identity + merge. **Before rules.** This is the idea; everything else decorates it |
| 0:35-0:55 | store + POST endpoint |
| 0:55-1:20 | three rules and a score. Three good ones beat ten |
| 1:20-1:40 | the table, sorted by risk. No CSS beyond legible |
| 1:40-1:50 | sample data that makes the merge *visible* - same agent, two machines |
| 1:50-2:00 | README with the limits list. Stop building |

Cut in this order if you're behind: UI polish → extra config formats → credential tracking →
extra rules. **Never cut:** identity/merge, one honest finding, and the limits list. A small
system with a real idea and an honest boundary beats a large one that gestures at everything.

And seed the demo data early. A system that finds nothing demos as a system that doesn't work.
