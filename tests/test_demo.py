"""Демо-режим отдаёт правдоподобные данные без Graylog."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.demo import FakeGraylog  # noqa: E402


def test_streams_and_products():
    g = FakeGraylog()
    streams = g.streams()
    assert len(streams) >= 3
    fields = g.stream_fields("demo-linux", limit=10)
    names = [f["name"] for f in fields["fields"]]
    assert "proctitle" in names and "name" in names


def test_definitions_exist_and_are_searchable():
    g = FakeGraylog()
    assert g.definitions(per_page=3)["total"] > 5
    found = g.definitions(query="mimikatz")
    assert found["total"] == 1


def test_history_is_deterministic():
    g = FakeGraylog()
    first = g.history('win_image:/.*powershell\\.exe/', days=10)
    second = g.history('win_image:/.*powershell\\.exe/', days=10)
    assert first["buckets"] == second["buckets"]
    assert first["verdict"]["level"] in ("ok", "warn", "error")


def test_create_and_delete_definition():
    g = FakeGraylog()
    before = g.definitions()["total"]
    created = g.create_event_definition(title="demo rule", query="win_image:x")
    assert g.definitions()["total"] == before + 1
    g.delete_event_definition(created["id"])
    assert g.definitions()["total"] == before
