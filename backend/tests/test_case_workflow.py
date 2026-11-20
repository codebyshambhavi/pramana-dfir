"""Role 3: case lifecycle API (create, list, open, edit, close, reopen) and case-scoped evidence."""
from __future__ import annotations

import tempfile

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from app.db.migrate import migrate


def _upload(client: TestClient, case_id: str, name: str, body: bytes):
    """Upload a one-row browser-history CSV; `body` makes each file's content (and hash) distinct."""
    marker = body.decode("utf-8").replace(" ", "-")
    csv = f"timestamp,action,url\n2026-10-18T10:00:00Z,visit,https://example.com/{marker}\n".encode("utf-8")
    return client.post(f"/cases/{case_id}/evidence", files={"file": (name.replace(".txt", ".csv"), csv, "text/csv")})


def test_create_case_with_metadata_and_generated_id(client: TestClient) -> None:
    res = client.post(
        "/cases",
        json={
            "name": "  Laptop exfiltration  ",
            "description": "Suspected upload of design files",
            "scope": "field-laptop-07, 18 Oct 2026",
            "tags": ["insider", "insider", " exfil ", ""],
            "owner": "S. Krishnan",
        },
    )
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["case_id"].startswith("CASE-")
    assert data["name"] == "Laptop exfiltration"
    assert data["tags"] == ["insider", "exfil"]
    assert data["owner"] == "S. Krishnan"
    assert data["status"] == "OPEN"
    assert data["created_at"]
    assert data["evidence_count"] == 0 and data["finding_count"] == 0 and data["run_count"] == 0

    fetched = client.get(f"/cases/{data['case_id']}").json()
    assert fetched["description"] == "Suspected upload of design files"
    assert fetched["scope"] == "field-laptop-07, 18 Oct 2026"


def test_create_case_rejects_blank_title_and_bad_id(client: TestClient) -> None:
    assert client.post("/cases", json={"name": "   "}).status_code == 422
    assert client.post("/cases", json={"name": "x", "case_id": "../etc"}).status_code == 422
    assert client.post("/cases", json={"name": "x", "tags": [f"t{i}" for i in range(21)]}).status_code == 422


def test_list_cases_counts_are_per_case(client: TestClient) -> None:
    client.post("/cases", json={"name": "Case A", "case_id": "CASE-A"})
    client.post("/cases", json={"name": "Case B", "case_id": "CASE-B"})
    assert _upload(client, "CASE-A", "a1.txt", b"alpha one").status_code == 201
    assert _upload(client, "CASE-A", "a2.txt", b"alpha two").status_code == 201
    assert _upload(client, "CASE-B", "b1.txt", b"bravo one").status_code == 201

    cases = {c["case_id"]: c for c in client.get("/cases").json()}
    assert set(cases) == {"CASE-A", "CASE-B"}
    assert cases["CASE-A"]["evidence_count"] == 2
    assert cases["CASE-B"]["evidence_count"] == 1

    # Evidence lists stay inside their own case.
    a_files = {e["filename"] for e in client.get("/cases/CASE-A/evidence").json()}
    b_files = {e["filename"] for e in client.get("/cases/CASE-B/evidence").json()}
    assert a_files == {"a1.csv", "a2.csv"}
    assert b_files == {"b1.csv"}


def test_edit_only_changes_supplied_fields(client: TestClient) -> None:
    client.post("/cases", json={"name": "Original", "case_id": "CASE-E", "owner": "A", "tags": ["one"]})
    res = client.patch("/cases/CASE-E", json={"description": "New detail", "tags": ["two"]})
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["name"] == "Original"
    assert data["owner"] == "A"
    assert data["description"] == "New detail"
    assert data["tags"] == ["two"]
    assert data["updated_at"]

    assert client.patch("/cases/CASE-E", json={"name": " "}).status_code == 422
    assert client.patch("/cases/CASE-NOPE", json={"name": "x"}).status_code == 404


def test_close_blocks_evidence_and_edits_until_reopened(client: TestClient) -> None:
    client.post("/cases", json={"name": "Closable", "case_id": "CASE-C"})
    closed = client.post("/cases/CASE-C/close")
    assert closed.status_code == 200
    assert closed.json()["status"] == "CLOSED"
    assert closed.json()["closed_at"]

    assert client.post("/cases/CASE-C/close").status_code == 409
    assert _upload(client, "CASE-C", "late.txt", b"late").status_code == 409
    assert client.patch("/cases/CASE-C", json={"name": "Renamed"}).status_code == 409
    assert client.get("/cases", params={"status": "closed"}).json()[0]["case_id"] == "CASE-C"

    reopened = client.post("/cases/CASE-C/reopen")
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "REOPENED"
    assert reopened.json()["closed_at"] is None
    assert client.post("/cases/CASE-C/reopen").status_code == 409
    assert _upload(client, "CASE-C", "late.txt", b"late").status_code == 201


def test_migrate_adds_case_columns_to_an_existing_table() -> None:
    root = tempfile.mkdtemp(prefix="pramana-case-migrate-")
    engine = create_engine(f"sqlite:///{root}/old.db")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE cases (case_id VARCHAR(64) PRIMARY KEY, name VARCHAR(255) NOT NULL, created_at DATETIME NOT NULL)"))
        conn.execute(text("INSERT INTO cases VALUES ('CASE-OLD', 'Legacy', '2026-10-20 09:42:00')"))

    migrate(engine)

    columns = {c["name"] for c in inspect(engine).get_columns("cases")}
    assert {"description", "scope", "tags", "owner", "status", "updated_at", "closed_at"} <= columns
    with engine.connect() as conn:
        assert conn.execute(text("SELECT status FROM cases WHERE case_id = 'CASE-OLD'")).scalar() == "OPEN"
    engine.dispose()
