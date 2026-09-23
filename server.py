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
            "devices": count_devices(agents)}


def count_devices(agents):
    devices = []
    for agent in agents:
        for device in agent["devices"]:
            if device not in devices:
                devices.append(device)
    return len(devices)


@app.post("/api/rescan")
def rescan():
    """Scan every machine in sample/ again. Handy for the demo."""
    if not os.path.isdir(SAMPLE_FOLDER):
        raise HTTPException(400, "no sample folder - run: python make_sample.py")

    store.clear()
    scanned = []
    for name in sorted(os.listdir(SAMPLE_FOLDER)):
        home = os.path.join(SAMPLE_FOLDER, name)
        if os.path.isdir(home):
            store.merge_report(scan.scan_machine(home))
            scanned.append(name)
    return {"scanned": scanned}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
