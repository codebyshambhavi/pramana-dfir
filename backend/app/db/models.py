"""Role 3: SQLAlchemy tables.

TODO (Role 3): define
  cases(case_id, name)
  evidence(evidence_id, case_id, filename, sha256, size_bytes, intake_time)
  events(event fields from contracts/event.schema.json, raw as JSON)
  findings(finding fields from contracts/finding.schema.json, status pending|approved|rejected)
  custody_entries(evidence_id, actor, action, time, sha256, prev_hash)
"""
