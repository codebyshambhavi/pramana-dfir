"""Role 3: FastAPI entry point. Run: uvicorn app.main:app --reload (from backend/)."""
from fastapi import FastAPI

from app.routers import cases, evidence, findings, graph, reports

app = FastAPI(title="Pramana API", version="0.1.0")

app.include_router(cases.router)
app.include_router(evidence.router)
app.include_router(graph.router)
app.include_router(findings.router)
app.include_router(reports.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
