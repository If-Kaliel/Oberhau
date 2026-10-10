"""Opt-in loopback inference with the already installed model; no implicit downloads."""

import os

import pytest

from oberhau.ollama import Ollama
from oberhau.reporting import generate

pytestmark = pytest.mark.skipif(
    os.environ.get("OBERHAU_LIVE_QWEN") != "1", reason="Explicit live Qwen opt-in required"
)


def test_live_qwen_report_preserves_evidence_and_review_status(engine, scanned):
    assert "qwen3.5:4b" in Ollama(timeout=5).models()
    identifier = engine.db.query(
        "SELECT id FROM findings WHERE json_extract(data,'$.rule')='python-sql-format'"
    )[0]["id"]
    previous = engine.db.finding(identifier)
    report_id, text = generate(engine.db, identifier, "pt-BR", ai=True)
    row = engine.db.query("SELECT generator FROM reports WHERE id=?", (report_id,))[0]
    assert row["generator"] == "ollama:unverified-draft"
    assert "Verificações de evidência" in text and "human_review_recorded" in text
    current = engine.db.finding(identifier)
    assert current["status"] == previous["status"] and current["notes"] == previous["notes"]
    assert current["finding"].evidence == previous["finding"].evidence
