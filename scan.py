# Agent Radar scanner: looks at one developer machine and reports the AI agents on it.
# Run:  python scan.py sample/laptop-dana --print
#       python scan.py sample/laptop-dana --upload http://127.0.0.1:8000

import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

import rules

# Which tool owns which config file (path relative to the home folder).
TOOL_CONFIGS = [
    ("cursor", ".cursor/mcp.json"),
    ("claude_desktop", "Library/Application Support/Claude/claude_desktop_config.json"),
    ("claude_desktop", "AppData/Roaming/Claude/claude_desktop_config.json"),
    ("vscode", "Library/Application Support/Code/User/settings.json"),
    ("vscode", "AppData/Roaming/Code/User/settings.json"),
    ("windsurf", ".codeium/windsurf/mcp_config.json"),
]

SKIP_FOLDERS = ["node_modules", ".git", ".venv", "__pycache__", ".cache"]
PLACEHOLDER_ENDINGS = [".example", ".sample", ".template"]
MAX_FILE_SIZE = 1024 * 1024


def read_text(path, errors):
    """Return the text of a file, or None if we should not read it."""
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return None
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as problem:
        errors.append({"path": path, "error": str(problem)})
        return None

    if b"\x00" in raw[:4096]:       # a binary file
        return None
    return raw.decode("utf-8", errors="replace")


def read_json(path, errors):
    text = read_text(path, errors)
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError as problem:
        errors.append({"path": path, "error": "not valid JSON: " + str(problem)})
        return None


def servers_in_config(config):
    """MCP servers live in one of two places, depending on the tool."""
    if not isinstance(config, dict):
        return {}
    if isinstance(config.get("mcpServers"), dict):
        return config["mcpServers"]
    if isinstance(config.get("mcp"), dict) and isinstance(config["mcp"].get("servers"), dict):
        return config["mcp"]["servers"]
    return {}


def agent_from_server(name, server, tool, config_path):
    args = []
    for arg in server.get("args") or []:
        args.append(str(arg))

    env = server.get("env") or {}
    env_keys = sorted(env.keys())

    secret_in_config = False
    for value in env.values():
        if rules.looks_like_secret(str(value)):
            secret_in_config = True
    for arg in args:
        if rules.looks_like_secret(arg):
            secret_in_config = True

    return {
        "name": name,
        "command": server.get("command"),
        # Masked, not raw: a secret in the config must never leave this machine.
        # We keep the fact that it was there (secret_in_config) and, separately,
        # its fingerprint in the credentials list.
        "args": rules.mask_args(args),
        "url": server.get("url"),
        "env_keys": env_keys,
        "auto_approve": bool(server.get("autoApprove")),
        "source_tool": tool,
        "config_path": config_path,
        "secret_in_config": secret_in_config,
    }


def find_tools_and_agents(home, errors):
    tools = []
    agents = []
    for tool, relative in TOOL_CONFIGS:
        path = os.path.join(home, *relative.split("/"))
        if not os.path.exists(path):
            continue

        tools.append({"name": tool, "config_path": relative})
        config = read_json(path, errors)
        servers = servers_in_config(config)
        for name in servers:
            server = servers[name]
            if isinstance(server, dict):
                agents.append(agent_from_server(name, server, tool, relative))
    return tools, agents


def find_credentials(home, errors):
    """Every secret-looking string in every text file. We keep the fingerprint, never the value."""
    credentials = []
    seen = []
    for folder, subfolders, files in os.walk(home):
        keep = []
        for name in subfolders:
            if name not in SKIP_FOLDERS:
                keep.append(name)
        subfolders[:] = keep

        for name in files:
            skip = False
            for ending in PLACEHOLDER_ENDINGS:
                if name.endswith(ending):
                    skip = True
            if skip:
                continue

            path = os.path.join(folder, name)
            text = read_text(path, errors)
            if text is None:
                continue

            relative = os.path.relpath(path, home).replace("\\", "/")
            line_number = 0
            for line in text.split("\n"):
                line_number += 1
                for kind, value in rules.find_secrets(line):
                    item = {"type": kind, "fingerprint": rules.fingerprint(value),
                            "path": relative, "line": line_number}
                    key = item["fingerprint"] + relative + str(line_number)
                    if key not in seen:
                        seen.append(key)
                        credentials.append(item)
    return credentials


def find_owner(home, errors):
    path = os.path.join(home, ".gitconfig")
    if os.path.exists(path):
        text = read_text(path, errors)
        if text:
            match = re.search(r"email\s*=\s*(\S+@\S+)", text)
            if match:
                return {"email": match.group(1), "source": "gitconfig"}
    return {"email": os.path.basename(home.rstrip("/\\")), "source": "folder name"}


def guess_platform(home):
    if os.path.exists(os.path.join(home, "Library")):
        return "macos"
    if os.path.exists(os.path.join(home, "AppData")):
        return "windows"
    return "linux"


def scan_machine(home):
    """Scan one home folder and return the report we send to the server."""
    home = os.path.abspath(home)
    errors = []
    tools, agents = find_tools_and_agents(home, errors)
    credentials = find_credentials(home, errors)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "device_id": os.path.basename(home),
        "platform": guess_platform(home),
        "scanned_at": now,
        "owner": find_owner(home, errors),
        "tools": tools,
        "agents": agents,
        "credentials": credentials,
        "errors": errors,
    }


def upload(report, base_url):
    url = base_url.rstrip("/") + "/api/report"
    data = json.dumps(report).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request) as response:
        return response.read().decode("utf-8")


def main():
    if len(sys.argv) < 2:
        print("usage: python scan.py <home folder> [--print | --upload <server url>]")
        return

    home = sys.argv[1]
    if not os.path.isdir(home):
        print("no such folder:", home)
        return

    report = scan_machine(home)

    if "--upload" in sys.argv:
        base_url = sys.argv[sys.argv.index("--upload") + 1]
        print("found", len(report["agents"]), "agents and", len(report["credentials"]), "credentials")
        print("server said:", upload(report, base_url))
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
