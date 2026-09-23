# All the SQLite code. One table for agents, one for credentials.
# The interesting part is merge_report(): the same agent on two machines is ONE agent.

import json
import os
import sqlite3

import rules

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_radar.db")


def connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def setup():
    connection = connect()
    connection.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            name TEXT, command TEXT, args TEXT, url TEXT,
            devices TEXT, owners TEXT, tools TEXT, config_paths TEXT, env_keys TEXT,
            secret_in_config INTEGER, auto_approve INTEGER,
            first_seen TEXT, last_seen TEXT)""")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            fingerprint TEXT PRIMARY KEY,
            type TEXT, locations TEXT, first_seen TEXT, last_seen TEXT)""")
    connection.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    connection.commit()
    connection.close()


def set_meta(key, value):
    connection = connect()
    connection.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, str(value)))
    connection.commit()
    connection.close()


def get_meta(key, default=""):
    connection = connect()
    row = connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    connection.close()
    if row is None:
        return default
    return row["value"]


def merge_lists(stored_json, new_values):
    """Add new values to a stored JSON list, without duplicates."""
    values = []
    if stored_json:
        values = json.loads(stored_json)
    for value in new_values:
        if value and value not in values:
            values.append(value)
    values.sort()
    return json.dumps(values)


def save_agent(connection, agent, device_id, owner_email, seen_at):
    agent_id = rules.agent_id(agent.get("command"), agent.get("args") or [], agent.get("url"))
    row = connection.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()

    if row is None:
        connection.execute(
            "INSERT INTO agents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (agent_id, agent["name"], agent.get("command"), json.dumps(agent.get("args") or []),
             agent.get("url"),
             json.dumps([device_id]), json.dumps([owner_email]), json.dumps([agent["source_tool"]]),
             json.dumps([agent["config_path"]]), json.dumps(agent.get("env_keys") or []),
             int(bool(agent.get("secret_in_config"))), int(bool(agent.get("auto_approve"))),
             seen_at, seen_at))
        return agent_id

    # Already known: add this machine to it, keep the widest view of what it can do.
    connection.execute(
        """UPDATE agents SET devices = ?, owners = ?, tools = ?, config_paths = ?, env_keys = ?,
                             secret_in_config = ?, auto_approve = ?, last_seen = ?
           WHERE agent_id = ?""",
        (merge_lists(row["devices"], [device_id]),
         merge_lists(row["owners"], [owner_email]),
         merge_lists(row["tools"], [agent["source_tool"]]),
         merge_lists(row["config_paths"], [agent["config_path"]]),
         merge_lists(row["env_keys"], agent.get("env_keys") or []),
         int(bool(row["secret_in_config"]) or bool(agent.get("secret_in_config"))),
         int(bool(row["auto_approve"]) or bool(agent.get("auto_approve"))),
         seen_at, agent_id))
    return agent_id


def save_credential(connection, credential, device_id, seen_at):
    fingerprint = credential["fingerprint"]
    where = device_id + ":" + credential["path"] + ":" + str(credential["line"])
    row = connection.execute("SELECT * FROM credentials WHERE fingerprint = ?", (fingerprint,)).fetchone()

    if row is None:
        connection.execute("INSERT INTO credentials VALUES (?,?,?,?,?)",
                           (fingerprint, credential["type"], json.dumps([where]), seen_at, seen_at))
    else:
        connection.execute("UPDATE credentials SET locations = ?, last_seen = ? WHERE fingerprint = ?",
                           (merge_lists(row["locations"], [where]), seen_at, fingerprint))


def merge_report(report):
    """Store one machine's report. Returns how many agents it contained."""
    device_id = report.get("device_id") or "unknown"
    owner_email = (report.get("owner") or {}).get("email", "unknown")
    seen_at = report.get("scanned_at") or ""

    connection = connect()
    for agent in report.get("agents") or []:
        save_agent(connection, agent, device_id, owner_email, seen_at)
    for credential in report.get("credentials") or []:
        save_credential(connection, credential, device_id, seen_at)
    connection.commit()
    connection.close()
    return len(report.get("agents") or [])


def row_to_agent(row):
    return {
        "agent_id": row["agent_id"], "name": row["name"], "command": row["command"],
        "args": json.loads(row["args"]), "url": row["url"],
        "devices": json.loads(row["devices"]), "owners": json.loads(row["owners"]),
        "tools": json.loads(row["tools"]), "config_paths": json.loads(row["config_paths"]),
        "env_keys": json.loads(row["env_keys"]),
        "secret_in_config": bool(row["secret_in_config"]),
        "auto_approve": bool(row["auto_approve"]),
        "first_seen": row["first_seen"], "last_seen": row["last_seen"],
    }


def get_agents():
    connection = connect()
    rows = connection.execute("SELECT * FROM agents").fetchall()
    connection.close()

    agents = []
    for row in rows:
        agents.append(row_to_agent(row))
    return agents


def get_agent(agent_id):
    connection = connect()
    row = connection.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    connection.close()
    if row is None:
        return None
    return row_to_agent(row)


def get_credentials():
    connection = connect()
    rows = connection.execute("SELECT * FROM credentials").fetchall()
    connection.close()

    credentials = []
    for row in rows:
        credentials.append({"fingerprint": row["fingerprint"], "type": row["type"],
                            "locations": json.loads(row["locations"]),
                            "first_seen": row["first_seen"], "last_seen": row["last_seen"]})
    return credentials


def clear():
    connection = connect()
    connection.execute("DELETE FROM agents")
    connection.execute("DELETE FROM credentials")
    connection.commit()
    connection.close()
