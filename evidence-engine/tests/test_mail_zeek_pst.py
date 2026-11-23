import hashlib
import json

import pytest
import sys
from types import SimpleNamespace

from parsers import zeek, mail, pst


def test_zeek_conn_log(tmp_path):
    path = tmp_path / "capture.conn.log"
    path.write_text(
        "#separator \\x09\n"
        "#fields\tuid\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n"
        "C123\t1792320000\t203.0.113.10\t53000\t203.0.113.53\t53\tudp\tdns\t1.25\t32\t64\tSF\n",
        encoding="utf-8",
    )
    events = zeek.parse(str(path), "CASE-ZEEK", "EVID-001", "a" * 64)
    assert len(events) == 1
    event = events[0]
    assert event["action"] == "NETWORK_CONNECTION"
    assert event["timestamp"] == "2026-10-18T10:40:00Z"
    assert event["raw"]["uid"] == "C123"
    assert event["raw"]["id.orig_h"] == "203.0.113.10"
    assert event["raw"]["conn_state"] == "SF"


def test_zeek_dns_log(tmp_path):
    path = tmp_path / "capture.dns.log"
    path.write_text(
        "#fields\tuid\tts\tquery\tqtype_name\tanswers\trcode_name\n"
        "D123\t1792320000\tarchive.example.test\tA\t203.0.113.22\tNOERROR\n",
        encoding="utf-8",
    )
    events = zeek.parse(str(path), "CASE-ZEEK", "EVID-002", "b" * 64)
    assert len(events) == 1
    assert events[0]["action"] == "DNS_QUERY"
    assert events[0]["object"] == "archive.example.test"
    assert events[0]["raw"]["answers"] == "203.0.113.22"


def test_gmail_fixture(tmp_path):
    path = tmp_path / "case.gmail.json"
    path.write_text(json.dumps({"messages": [{
        "id": "gmail-1",
        "threadId": "thread-1",
        "labelIds": ["INBOX"],
        "mimeType": "multipart/mixed",
        "internalDate": "1792320000000",
        "payload": {"headers": [
            {"name": "From", "value": "sender@example.test"},
            {"name": "To", "value": "receiver@example.test"},
            {"name": "Subject", "value": "Evidence notice"},
            {"name": "Date", "value": "Mon, 18 Oct 2026 10:40:00 +0000"},
        ], "body": {"data": "SGVsbG8="}},
    }]}), encoding="utf-8")
    events = mail.parse_gmail(str(path), "CASE-MAIL", "EVID-3", "c" * 64)
    assert len(events) == 1
    assert events[0]["source"] == "gmail"
    assert events[0]["action"] == "EMAIL_RECEIVED"
    assert events[0]["actor"] == "sender@example.test"
    assert events[0]["object"] == "Evidence notice"


def test_outlook_fixture(tmp_path):
    path = tmp_path / "case.outlook.json"
    path.write_text(json.dumps({"value": [{
        "id": "msg-1",
        "conversationId": "conv-1",
        "internetMessageId": "<msg1@example.test>",
        "subject": "Project evidence",
        "sentDateTime": "2026-10-18T10:40:00Z",
        "from": {"emailAddress": {"address": "sender@example.test"}},
        "toRecipients": [{"emailAddress": {"address": "receiver@example.test"}}],
    }]}), encoding="utf-8")
    events = mail.parse_outlook(str(path), "CASE-MAIL", "EVID-4", "d" * 64)
    assert len(events) == 1
    assert events[0]["source"] == "outlook"
    assert events[0]["action"] == "EMAIL_SENT"
    assert events[0]["raw"]["internetMessageId"] == "<msg1@example.test>"


def test_pst_validation_rejects_non_pst(tmp_path):
    path = tmp_path / "not-pst.bin"
    path.write_bytes(b"not a PST archive")
    with pytest.raises(ValueError, match="Invalid PST"):
        pst.validate_pst(str(path))


class _FakePSTArchive:
    def __init__(self, folders):
        self.root = folders

    def open(self, path):
        return None

    def get_root_folder(self):
        return self.root

    def close(self):
        return None


class _FakeFolder:
    def __init__(self, name, messages=(), sub_folders=()):
        self.name = name
        self.sub_messages = list(messages)
        self.sub_folders = list(sub_folders)


class _FakeAttachment:
    def __init__(self, name, data, identifier=None, size=None, mime_type=None):
        self.name = name
        self._data = data
        self.identifier = identifier
        self.size = len(data) if size is None and isinstance(data, (bytes, bytearray)) else size
        self.mime_type = mime_type

    def get_data(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class _FakeMessage:
    def __init__(self, identifier, attachments=(), subject="Test"):
        self.identifier = identifier
        self.attachments = list(attachments)
        self.subject = subject
        self.sender_name = "sender@example.test"


def _mock_pypff(monkeypatch, folders):
    archive = _FakePSTArchive(_FakeFolder("Root", sub_folders=folders))
    monkeypatch.setitem(sys.modules, "pypff", SimpleNamespace(file=lambda: archive))


def _pst_file(tmp_path):
    path = tmp_path / "fixture.pst"
    path.write_bytes(b"!BDN" + b"\x00" * 64)
    return path


def test_pst_no_attachment_mock(tmp_path, monkeypatch):
    path = _pst_file(tmp_path)
    _mock_pypff(monkeypatch, [_FakeFolder("Inbox", [_FakeMessage("m1")])])
    result = pst.extract_pst_attachments(str(path), str(tmp_path / "out"), "EVID-001")
    assert result["status"] == "SUCCESS"
    assert result["attachments"] == []
    assert result["warnings"] == []


def test_pst_one_and_multiple_attachment_mocks(tmp_path, monkeypatch):
    path = _pst_file(tmp_path)
    one = _FakeAttachment("one.txt", b"one", "a1", mime_type="text/plain")
    two = _FakeAttachment("two.bin", b"\x00\x01", "a2")
    _mock_pypff(monkeypatch, [_FakeFolder("Inbox", [
        _FakeMessage("m1", [one]),
        _FakeMessage("m2", [two, _FakeAttachment("three.txt", b"three", "a3")]),
    ])])
    result = pst.extract_pst_attachments(str(path), str(tmp_path / "out"), "EVID-001")
    assert result["status"] == "SUCCESS"
    assert len(result["attachments"]) == 3
    assert all(item["status"] == "ACQUIRED" for item in result["attachments"])
    assert result["attachments"][0]["sha256"] == hashlib.sha256(b"one").hexdigest()
    assert len({item["attachment_id"] for item in result["attachments"]}) == 3
    for item in result["attachments"]:
        assert item["parent_evidence_id"] == "EVID-001"
        assert item["message_locator"].startswith("fixture.pst#")


def test_pst_empty_attachment_mock(tmp_path, monkeypatch):
    path = _pst_file(tmp_path)
    _mock_pypff(monkeypatch, [_FakeFolder("Inbox", [
        _FakeMessage("m1", [_FakeAttachment("empty.txt", b"", "a1")]),
    ])])
    result = pst.extract_pst_attachments(str(path), str(tmp_path / "out"), "EVID-001")
    assert result["status"] == "PARTIAL"
    assert result["attachments"][0]["status"] == "EMPTY"
    assert result["attachments"][0]["sha256"] == hashlib.sha256(b"").hexdigest()
    assert result["warnings"]


def test_pst_attachment_extraction_failure_mock(tmp_path, monkeypatch):
    path = _pst_file(tmp_path)
    _mock_pypff(monkeypatch, [_FakeFolder("Inbox", [
        _FakeMessage("m1", [_FakeAttachment("bad.bin", RuntimeError("blocked"), "a1")]),
    ])])
    result = pst.extract_pst_attachments(str(path), str(tmp_path / "out"), "EVID-001")
    assert result["status"] == "PARTIAL"
    assert result["attachments"][0]["status"] == "FAILED"
    assert "extraction failed" in result["warnings"][0]


def test_pst_malformed_attachment_metadata_mock(tmp_path, monkeypatch):
    path = _pst_file(tmp_path)
    malformed = SimpleNamespace(identifier=None, size="not-a-size")
    malformed.name = None
    malformed.get_data = lambda: {"not": "bytes"}
    _mock_pypff(monkeypatch, [_FakeFolder("Inbox", [
        _FakeMessage("m1", [malformed]),
    ])])
    result = pst.extract_pst_attachments(str(path), str(tmp_path / "out"), "EVID-001")
    assert result["status"] == "PARTIAL"
    assert result["attachments"][0]["status"] == "FAILED"
    assert result["warnings"]
