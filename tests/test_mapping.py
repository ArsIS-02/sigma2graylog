"""Сопоставление полей: продукт правила должен определять набор полей."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.mapping import FieldIndex, build_mapping, detect_product  # noqa: E402

FIELDS = [
    {"name": "winlogbeat_winlog_event_data_Image"},
    {"name": "winlogbeat_winlog_event_data_TargetFilename"},
    {"name": "winlogbeat_winlog_event_data_CommandLine"},
    {"name": "exe"}, {"name": "proctitle"}, {"name": "name"}, {"name": "cwd"},
    {"name": "audit_type"}, {"name": "pid"}, {"name": "ppid"},
    {"name": "macos_processImagePath"},
]


def test_detect_product_by_fields():
    assert detect_product(["winlogbeat_winlog_event_data_Image", "EventID"]) == "windows"
    assert detect_product(["audit_type", "proctitle", "name"]) == "linux"
    assert detect_product(["macos_processImagePath", "macos_personaID"]) == "macos"
    assert detect_product(["some", "other"]) is None


def test_linux_rule_maps_to_linux_fields():
    index = FieldIndex(FIELDS)
    mapping = build_mapping(["TargetFilename", "CommandLine"], index, "linux")
    assert mapping["TargetFilename"]["graylog_field"] == "name"
    assert mapping["CommandLine"]["graylog_field"] == "proctitle"


def test_windows_rule_does_not_take_linux_fields():
    index = FieldIndex(FIELDS)
    mapping = build_mapping(["TargetFilename"], index, "windows")
    assert mapping["TargetFilename"]["graylog_field"] == "winlogbeat_winlog_event_data_TargetFilename"


def test_foreign_product_field_is_never_auto_selected():
    index = FieldIndex(FIELDS)
    mapping = build_mapping(["Image"], index, "linux")
    value = mapping["Image"]["graylog_field"]
    assert value is None or not value.startswith("winlogbeat_")


def test_manual_override_wins():
    index = FieldIndex(FIELDS)
    mapping = build_mapping(["TargetFilename"], index, "linux",
                            {"TargetFilename": "cwd"})
    assert mapping["TargetFilename"]["graylog_field"] == "cwd"
    assert mapping["TargetFilename"]["source"] == "manual"
