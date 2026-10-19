"""Role 3: FastAPI entry point. Run: uvicorn app.main:app --reload (from backend/)."""
from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db.session import init_db
from app.routers import cases, evidence, findings, graph, reports


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events: initialize database schema on startup."""
    init_db()
    yield


app = FastAPI(
    title="Pramana API",
    version="0.1.0",
    description="Pramana DFIR API for case management, evidence intake, graph correlation, intelligence analysis, and legal reports.",
    lifespan=lifespan,
)

# CORS middleware for seamless local and containerized frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(cases.router)
app.include_router(evidence.router)
app.include_router(graph.router)
app.include_router(findings.router)
app.include_router(reports.router)


@app.get("/health", summary="Health check")
def health() -> dict:
    return {"status": "ok"}
