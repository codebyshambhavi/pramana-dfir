# evidence-engine (Role 1)

Owns intake, hashing, custody log, parsers and the sample case. Output is Event JSON (`../contracts/event.schema.json`).

Entry point: `parsers.parse_evidence(path, case_id) -> list[dict]`.
Run tests from this folder: `pytest`.
