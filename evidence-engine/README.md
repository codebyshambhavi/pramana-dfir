# evidence-engine (Role 1)

Owns intake, hashing, custody log, parsers and the sample case. Output is Event JSON (`../contracts/event.schema.json`).

Entry point: `parsers.parse_evidence(path, case_id) -> list[dict]`.
Run tests from this folder: `pytest`.

## Evidence acquisition modules

- Gmail and Microsoft Graph exports are accepted as `.gmail.json` and
  `.outlook.json`. The live connectors are in `backend/app/routers/connectors.py`
  and require server-side OAuth configuration.
- PST files are detected by the `!BDN` signature. Full PST parsing requires the
  optional `pypff` binding. PST is not silently emulated from another format.
- Zeek `conn.log` and `dns.log` files are detected from `#fields` headers.
- PCAP/PCAPNG use Scapy. Timestamps are packet epoch UTC; encrypted payload
  contents are not inferred.

## Connector setup

Configure Gmail OAuth with `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
`GOOGLE_REDIRECT_URI`, and a Fernet `PRAMANA_TOKEN_ENCRYPTION_KEY`.
The Gmail scope is read-only Gmail access.

Configure Microsoft Graph with `MICROSOFT_CLIENT_ID`,
`MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID`, and
`MICROSOFT_REDIRECT_URI`. The Graph scope is `offline_access Mail.Read`.

Generate a token encryption key only in a secure shell:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Connector routes require `PRAMANA_API_BEARER_TOKEN` and an `Authorization:
Bearer <token>` header. Set `PRAMANA_AUTHORIZED_CASE_IDS` to a JSON list when
access must be restricted to selected case IDs. The callback endpoints validate
the persisted one-time OAuth state and do not accept OAuth access tokens in
API responses.

## Normalised sources

The additive event sources are `gmail`, `outlook_graph`, `pst`, and `zeek`.
Existing browser, chat, log, PCAP and image sources remain unchanged.

## API examples

```text
POST /cases/{case_id}/evidence
POST /cases/{case_id}/connectors/gmail/sync
POST /cases/{case_id}/connectors/microsoft/sync
GET  /cases/{case_id}/evidence
GET  /cases/{case_id}/events
```

## Tests

```bash
cd evidence-engine
pytest
```

## Known limitations

- Live OAuth callback and mailbox acquisition require client credentials and
  provider test consent.
- A PST archive requires the optional `pypff` Python binding. If it is absent,
  parsing returns an explicit dependency limitation.
- PST attachment extraction is best-effort. It preserves successfully extracted
  bytes, filenames, attachment IDs, folder paths, message locators and hashes.
  Empty or failed attachments are warnings and produce `PARTIAL` status.
- The Graph implementation acquires text-format message metadata and file
  attachment bytes; unsupported attachment types are explicitly recorded.
- Mailbox exports and synchronisation history are persisted by the backend.
