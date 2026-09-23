# Agent identity, secret patterns and the risk rules. Plain functions, no input or output.
# Used by scan.py (on the machine), store.py and server.py (on the server).

import hashlib
import re
from datetime import datetime, timezone

SECRET_PATTERNS = [
    ("openai_key", r"sk-proj-[A-Za-z0-9]{30,}"),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9\-]{30,}"),
    ("github_token", r"ghp_[A-Za-z0-9]{36}"),
    ("aws_key_id", r"AKIA[A-Z0-9]{16}"),
    ("slack_token", r"xoxb-[A-Za-z0-9\-]{20,}"),
]

# rule id -> (severity, points, title, remediation)
RULES = {
    "R1": ("high", 40, "Can read the whole filesystem",
           "Give the server one project folder instead of the drive root or the home folder."),
    "R2": ("critical", 40, "A secret is written in the config file",
           "Move the secret to the OS keychain or a secret manager and reference it."),
    "R3": ("critical", 50, "Downloads and runs code from the internet at startup",
           "Pin a reviewed package or binary instead of piping a download into a shell."),
    "R4": ("high", 25, "Runs tools without asking for confirmation",
           "Remove the auto-approve flag so a human approves each tool call."),
    "R5": ("medium", 15, "Talks to a remote server run by someone else",
           "Review who operates that endpoint and what it is allowed to do."),
    "R6": ("medium", 10, "The same agent is configured in several places",
           "Consolidate into one definition so revoking it happens once."),
    "R7": ("medium", 10, "Not seen for more than 90 days",
           "Remove the agent and revoke the credentials it holds."),
}

AUTO_APPROVE_FLAGS = ["--no-confirm", "--yes", "--dangerously-skip-permissions"]


# ----------------------------------------------------------------- secrets
def find_secrets(text):
    """Return a list of (type, value) for every secret-looking string in the text."""
    found = []
    for name, pattern in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            found.append((name, match.group()))
    return found


def looks_like_secret(text):
    return len(find_secrets(text)) > 0


def fingerprint(value):
    """The only thing we ever store about a secret."""
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]


# ----------------------------------------------------------------- identity
def mask_args(args):
    """Replace any argument that holds a secret with <secret>."""
    masked = []
    for arg in args:
        if looks_like_secret(arg):
            masked.append("<secret>")
        else:
            masked.append(arg)
    return masked


def agent_id(command, args, url):
    """Identity is what the agent RUNS, not where we found it.

    Secrets are masked first, so rotating a token does not create a second agent.
    """
    parts = (command or "") + "\x00" + "\x00".join(mask_args(args)) + "\x00" + (url or "")
    return "ag_" + hashlib.sha256(parts.encode()).hexdigest()[:16]


# ----------------------------------------------------------------- risk
def is_broad_root(path):
    """True for the drive root, / or a whole home folder."""
    plain = path.replace("\\", "/").rstrip("/")
    if plain in ("", "~", "$HOME", "${HOME}", "%USERPROFILE%"):
        return True
    if len(plain) == 2 and plain[1] == ":":        # C:
        return True
    parts = plain.strip("/").split("/")
    if len(parts) == 2 and parts[0] in ("Users", "home"):   # /Users/dana
        return True
    return False


def days_since(timestamp):
    if not timestamp:
        return 0
    try:
        seen = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return (datetime.now(timezone.utc) - seen).days


def make_finding(rule_id, agent, evidence):
    severity, points, title, remediation = RULES[rule_id]
    return {"rule": rule_id, "severity": severity, "agent_id": agent["agent_id"],
            "agent_name": agent["name"], "title": title, "evidence": evidence,
            "remediation": remediation}


def evaluate(agent):
    """Return (risk score 0-100, list of findings) for one agent."""
    command = agent.get("command") or ""
    args = agent.get("args") or []
    url = agent.get("url")
    command_line = (command + " " + " ".join(args)).strip()
    findings = []

    if "filesystem" in command_line or "filesystem" in agent["name"]:
        for arg in args:
            if is_broad_root(arg):
                findings.append(make_finding("R1", agent, "can read " + arg))
                break

    if agent.get("secret_in_config"):
        findings.append(make_finding("R2", agent, "a credential is stored in " + agent["name"] + "'s config"))

    downloads = "curl" in command_line or "wget" in command_line
    pipes_to_shell = "| sh" in command_line or "|sh" in command_line or "| bash" in command_line
    if downloads and pipes_to_shell:
        findings.append(make_finding("R3", agent, command_line))

    auto_approve_evidence = ""
    for flag in AUTO_APPROVE_FLAGS:
        if flag in args:
            auto_approve_evidence = "uses " + flag
    if agent.get("auto_approve"):
        auto_approve_evidence = "autoApprove is on in the config"
    if auto_approve_evidence:
        findings.append(make_finding("R4", agent, auto_approve_evidence))

    if url:
        findings.append(make_finding("R5", agent, "connects to " + url))

    devices = agent.get("devices") or []
    tools = agent.get("tools") or []
    if len(devices) >= 2 or len(tools) >= 2:
        evidence = "on " + str(len(devices)) + " machines, in " + str(len(tools)) + " tools"
        findings.append(make_finding("R6", agent, evidence))

    idle = days_since(agent.get("last_seen"))
    if idle > 90:
        findings.append(make_finding("R7", agent, "last seen " + str(idle) + " days ago"))

    risk = 10
    for finding in findings:
        risk += RULES[finding["rule"]][1]
    if "--read-only" in args:
        risk -= 15

    if risk < 0:
        risk = 0
    if risk > 100:
        risk = 100
    return risk, findings
