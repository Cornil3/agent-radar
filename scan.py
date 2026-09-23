# Agent Radar scanner: looks at one developer machine and reports the AI agents on it.
# Run:  python scan.py sample/laptop-dana --print
#       python scan.py sample/laptop-dana --upload http://127.0.0.1:8000

import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone

import rules

# Which tool owns which config file (path relative to the home folder).
TOOL_CONFIGS = [
    ("cursor", ".cursor/mcp.json"),
    ("claude_desktop", "Library/Application Support/Claude/claude_desktop_config.json"),
    ("claude_desktop", "AppData/Roaming/Claude/claude_desktop_config.json"),
    ("claude_code", ".claude.json"),
    ("claude_code", ".claude/settings.json"),
    ("vscode", "Library/Application Support/Code/User/settings.json"),
    ("vscode", "AppData/Roaming/Code/User/settings.json"),
    ("vscode", "Library/Application Support/Code/User/mcp.json"),
    ("vscode", "AppData/Roaming/Code/User/mcp.json"),
    ("windsurf", ".codeium/windsurf/mcp_config.json"),
    ("continue", ".continue/config.json"),
    ("codex_cli", ".codex/config.toml"),
    ("gemini_cli", ".gemini/settings.json"),
]

# Config files that live inside a project folder, found while walking.
PROJECT_CONFIGS = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"]

# Tools we can see by their folder, even when they have no MCP server configured.
TOOL_FOLDERS = [
    ("cursor", ".cursor"),
    ("cursor", "AppData/Roaming/Cursor"),
    ("claude_code", ".claude"),
    ("claude_desktop", "AppData/Roaming/Claude"),
    ("claude_desktop", "Library/Application Support/Claude"),
    ("vscode", "AppData/Roaming/Code"),
    ("vscode", "Library/Application Support/Code"),
    ("windsurf", ".codeium/windsurf"),
    ("ollama", ".ollama"),
    ("lm_studio", ".lmstudio"),
]

SKIP_FOLDERS = ["node_modules", ".git", ".venv", "venv", "__pycache__", ".cache",
                "AppData", "site-packages", ".gradle", ".m2", ".nuget", ".conda",
                "anaconda3", "miniconda3", "OneDriveTemp", "$RECYCLE.BIN"]
PLACEHOLDER_ENDINGS = [".example", ".sample", ".template"]

# Only files that plausibly hold text config are opened. Reading every file on a real
# machine is far too slow, and secrets live in a small number of shapes.
SECRET_FILE_ENDINGS = [".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
                       ".txt", ".md", ".sh", ".ps1", ".bat", ".py", ".js", ".ts", ".rb",
                       ".go", ".java", ".xml", ".properties", ".jsonl", ".log"]
SECRET_FILE_NAMES = [".env", ".npmrc", ".netrc", "credentials", ".gitconfig", ".bashrc",
                     ".zshrc", ".bash_history", ".zsh_history", "id_rsa", "id_ed25519"]
MAX_FILE_SIZE = 1024 * 1024
MAX_SECONDS = 120          # a real home folder is big; stop rather than hang


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


def read_config(path, errors):
    """Read a config file. JSON for most tools, TOML for the Codex CLI."""
    if path.endswith(".toml"):
        text = read_text(path, errors)
        if text is None:
            return None
        try:
            import tomllib
            return tomllib.loads(text)
        except Exception as problem:
            errors.append({"path": path, "error": "not valid TOML: " + str(problem)})
            return None
    return read_json(path, errors)


def servers_in_config(config):
    """MCP servers hide in a different place in every tool's config."""
    servers = {}
    if not isinstance(config, dict):
        return servers

    for key in ("mcpServers", "mcp_servers", "servers"):
        if isinstance(config.get(key), dict):
            servers.update(config[key])

    mcp = config.get("mcp")                          # VS Code
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        servers.update(mcp["servers"])

    projects = config.get("projects")                # Claude Code keeps them per project
    if isinstance(projects, dict):
        for project in projects.values():
            if isinstance(project, dict) and isinstance(project.get("mcpServers"), dict):
                servers.update(project["mcpServers"])
    return servers


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
        config = read_config(path, errors)
        servers = servers_in_config(config)
        for name in servers:
            server = servers[name]
            if isinstance(server, dict):
                agents.append(agent_from_server(name, server, tool, relative))
    return tools, agents


def find_installed_tools(home):
    """Tools that are installed but may have no MCP server configured."""
    tools = []
    for tool, relative in TOOL_FOLDERS:
        path = os.path.join(home, *relative.split("/"))
        if os.path.isdir(path):
            tools.append({"name": tool, "config_path": relative + "/ (installed)"})
    return tools


def find_plugins(home, errors):
    """Claude Code plugins. Not MCP servers, but they run inside the agent."""
    agents = []
    path = os.path.join(home, ".claude", "settings.json")
    if not os.path.exists(path):
        return agents

    settings = read_json(path, errors) or {}
    enabled = settings.get("enabledPlugins") or {}
    marketplaces = settings.get("extraKnownMarketplaces") or {}

    for name in enabled:
        if not enabled[name]:
            continue
        marketplace = name.split("@")[-1]
        entry = marketplaces.get(marketplace) or {}
        source = entry.get("source") or {}
        where = source.get("path") or source.get("source") or "built in"
        agents.append({
            "name": name, "command": "plugin:" + name, "args": [str(where)], "url": None,
            "env_keys": [], "auto_approve": False, "source_tool": "claude_code",
            "config_path": ".claude/settings.json", "secret_in_config": False,
        })
    return agents


def is_project_config(relative):
    """A config that belongs to a project folder rather than to the user."""
    for ending in PROJECT_CONFIGS:
        if relative.endswith(ending):
            return True
    return False


def is_excluded(relative, excludes):
    for text in excludes:
        if text.lower() in relative.lower():
            return True
    return False


def walk_home(home, errors, options):
    """One walk over the home folder: project configs, and (unless skipped) secrets.

    Returns (credentials, project agents, stats). Stops when the time budget runs out,
    and says so, rather than hanging on a huge folder.
    """
    credentials = []
    project_agents = []
    seen = []
    user_configs = []
    for tool, relative in TOOL_CONFIGS:
        user_configs.append(relative)

    started = time.time()
    files_read = 0
    stopped_early = False

    for folder, subfolders, files in os.walk(home):
        if time.time() - started > options["max_seconds"]:
            stopped_early = True
            break

        keep = []
        for name in subfolders:
            relative_folder = os.path.relpath(os.path.join(folder, name), home).replace("\\", "/")
            if name in SKIP_FOLDERS:
                continue
            if is_excluded(relative_folder, options["excludes"]):
                continue
            keep.append(name)
        subfolders[:] = keep

        for name in files:
            path = os.path.join(folder, name)
            relative = os.path.relpath(path, home).replace("\\", "/")

            if is_project_config(relative) and relative not in user_configs:
                config = read_config(path, errors)
                servers = servers_in_config(config)
                for server_name in servers:
                    server = servers[server_name]
                    if isinstance(server, dict):
                        project_agents.append(
                            agent_from_server(server_name, server, "project", relative))

            if options["skip_secrets"]:
                continue

            skip = False
            for ending in PLACEHOLDER_ENDINGS:
                if name.endswith(ending):
                    skip = True
            if skip:
                continue

            worth_reading = name in SECRET_FILE_NAMES or name.startswith(".env")
            for ending in SECRET_FILE_ENDINGS:
                if name.lower().endswith(ending):
                    worth_reading = True
            if not worth_reading:
                continue

            text = read_text(path, errors)
            if text is None:
                continue
            files_read += 1

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

    stats = {"files_read": files_read, "stopped_early": stopped_early,
             "seconds": round(time.time() - started, 1)}
    return credentials, project_agents, stats


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


def scan_machine(home, options=None):
    """Scan one home folder and return the report we send to the server."""
    if options is None:
        options = {}
    options.setdefault("skip_secrets", False)
    options.setdefault("max_seconds", MAX_SECONDS)
    options.setdefault("excludes", [])

    home = os.path.abspath(home)
    errors = []
    tools, agents = find_tools_and_agents(home, errors)

    for tool in find_installed_tools(home):
        known = False
        for found in tools:
            if found["name"] == tool["name"]:
                known = True
        if not known:
            tools.append(tool)

    for agent in find_plugins(home, errors):
        agents.append(agent)

    credentials, project_agents, stats = walk_home(home, errors, options)
    for agent in project_agents:
        agents.append(agent)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "device_id": os.path.basename(home),
        "platform": guess_platform(home),
        "scanned_at": now,
        "owner": find_owner(home, errors),
        "tools": tools,
        "agents": agents,
        "credentials": credentials,
        "scan": stats,
        "errors": errors[:50],
    }


def upload(report, base_url):
    url = base_url.rstrip("/") + "/api/report"
    data = json.dumps(report).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request) as response:
        return response.read().decode("utf-8")


def read_options():
    """Flags: --skip-secrets, --max-seconds N, --exclude TEXT (repeatable)."""
    options = {"skip_secrets": "--skip-secrets" in sys.argv,
               "max_seconds": MAX_SECONDS, "excludes": []}
    position = 0
    for value in sys.argv:
        if value == "--max-seconds":
            options["max_seconds"] = float(sys.argv[position + 1])
        if value == "--exclude":
            options["excludes"].append(sys.argv[position + 1])
        position += 1
    return options


def main():
    if len(sys.argv) < 2:
        print("usage: python scan.py <home folder> [--print | --upload <url>] "
              "[--out file.json] [--skip-secrets] [--max-seconds N] [--exclude TEXT]")
        return

    home = sys.argv[1]
    if not os.path.isdir(home):
        print("no such folder:", home)
        return

    report = scan_machine(home, read_options())

    # Progress goes to stderr so that --print gives you clean JSON you can pipe.
    note = sys.stderr
    print("scanned", report["scan"]["files_read"], "files in",
          report["scan"]["seconds"], "seconds", file=note)
    if report["scan"]["stopped_early"]:
        print("(stopped at the time limit - raise it with --max-seconds)", file=note)
    print("found", len(report["agents"]), "agents and",
          len(report["credentials"]), "credentials", file=note)

    if "--out" in sys.argv:
        out_path = sys.argv[sys.argv.index("--out") + 1]
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print("wrote", out_path, file=sys.stderr)

    if "--upload" in sys.argv:
        base_url = sys.argv[sys.argv.index("--upload") + 1]
        print("server said:", upload(report, base_url), file=sys.stderr)
    elif "--print" in sys.argv:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
