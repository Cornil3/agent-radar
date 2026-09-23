# Agent Radar server: collects scan reports, scores them, serves the console page.
# Run:  python server.py        then open http://127.0.0.1:8000

import os

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

import rules
import scan
import store

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_FOLDER = os.path.join(HERE, "sample")

app = FastAPI(title="Agent Radar")
store.setup()


def scored_agents():
    """Every agent, with its risk score and findings worked out fresh."""
    agents = store.get_agents()
    for agent in agents:
        agent["risk"], agent["findings"] = rules.evaluate(agent)
    agents.sort(key=risk_of, reverse=True)
    return agents


def risk_of(agent):
    return agent["risk"]


@app.get("/")
def console():
    return FileResponse(os.path.join(HERE, "web", "index.html"))


@app.post("/api/report")
def receive_report(report: dict):
    count = store.merge_report(report)
    return {"received_agents": count, "device": report.get("device_id")}


@app.get("/api/agents")
def list_agents():
    return scored_agents()


@app.get("/api/agents/{agent_id}")
def one_agent(agent_id: str):
    agent = store.get_agent(agent_id)
    if agent is None:
        raise HTTPException(404, "no such agent")
    agent["risk"], agent["findings"] = rules.evaluate(agent)
    return agent


@app.get("/api/findings")
def list_findings(severity: str = ""):
    findings = []
    for agent in scored_agents():
        for finding in agent["findings"]:
            if severity == "" or finding["severity"] == severity:
                findings.append(finding)
    return findings


@app.get("/api/credentials")
def list_credentials():
    return store.get_credentials()


@app.get("/api/stats")
def stats():
    agents = scored_agents()
    risky = 0
    for agent in agents:
        if agent["risk"] >= 70:
            risky += 1
    return {"agents": len(agents), "risky_agents": risky,
            "credentials": len(store.get_credentials()),
            "devices": count_devices(agents),
            "source": store.get_meta("source", "sample")}


def count_devices(agents):
    devices = []
    for agent in agents:
        for device in agent["devices"]:
            if device not in devices:
                devices.append(device)
    return len(devices)


@app.post("/api/rescan")
def rescan(source: str = "sample"):
    """Fill the console from one of two places.

    source=sample   the three fake machines in sample/ (the demo)
    source=machine  this computer, for real
    """
    if source == "machine":
        return scan_this_machine()

    if not os.path.isdir(SAMPLE_FOLDER):
        raise HTTPException(400, "no sample folder - run: python make_sample.py")

    store.clear()
    scanned = []
    for name in sorted(os.listdir(SAMPLE_FOLDER)):
        home = os.path.join(SAMPLE_FOLDER, name)
        if os.path.isdir(home):
            store.merge_report(scan.scan_machine(home))
            scanned.append(name)
    store.set_meta("source", "sample")
    return {"source": "sample", "scanned": scanned}


def read_excludes():
    """Folders to leave out of a real scan, one per line in excludes.txt."""
    patterns = []
    path = os.path.join(HERE, "excludes.txt")
    if not os.path.exists(path):
        return patterns
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def scan_this_machine():
    """Scan the home folder of whoever is running this."""
    home = os.path.expanduser("~")

    # Don't report our own sample machines as if they were real agents.
    excludes = read_excludes()
    relative = os.path.relpath(HERE, home)
    if not relative.startswith(".."):
        excludes.append(relative.replace("\\", "/"))

    report = scan.scan_machine(home, {"max_seconds": 90, "excludes": excludes})
    store.clear()
    store.merge_report(report)
    store.set_meta("source", "machine")
    return {"source": "machine", "scanned": [report["device_id"]], "scan": report["scan"]}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
