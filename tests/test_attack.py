"""Теги ATT&CK из Sigma -> поля mitre_* определения события."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import attack  # noqa: E402


class Tag:
    def __init__(self, namespace, name):
        self.namespace, self.name = namespace, name


def test_parse_tactics_and_techniques():
    p = attack.parse_tags([Tag("attack", "execution"), Tag("attack", "t1059.001"),
                           Tag("cve", "2020-1472"), "attack.T1105"])
    assert p["tactics"] == ["execution"]
    assert p["techniques"] == ["T1059.001", "T1105"]


def test_obsolete_ids_are_replaced():
    p = attack.parse_tags(["attack.t1562.001", "attack.t1070.001"])
    assert p["techniques"] == ["T1685", "T1685.005"]
    assert p["renamed"] == {"T1562.001": "T1685", "T1070.001": "T1685.005"}


def test_tactic_comes_from_primary_technique():
    d = attack.describe({"tactics": ["persistence", "execution"], "techniques": ["T1059.001"]})
    assert d["tactic"] == "Execution"
    assert d["technique"].startswith("T1059.001 ")
    assert d["techniques"] == "T1059.001"


def test_tactic_without_technique():
    d = attack.describe({"tactics": ["credential-access"], "techniques": []})
    assert d["tactic"] == "Credential Access" and d["technique"] == ""


def test_user_input_is_validated():
    assert attack.describe({"tactics": ["nonsense"], "techniques": ["rm -rf", "T1"]}) is None
    assert attack.field_spec(None) == {}
    assert attack.field_spec({"tactics": [], "techniques": []}) == {}


def test_field_spec_shape_matches_graylog_templates():
    fs = attack.field_spec({"tactics": [], "techniques": ["T1110", "T1110.001"]})
    assert set(fs) == {"mitre_tactic", "mitre_technique", "mitre_techniques"}
    prov = fs["mitre_techniques"]["providers"][0]
    assert prov["type"] == "template-v1" and prov["template"] == "T1110, T1110.001"


def test_rule_without_attack_tags():
    rule = type("R", (), {"tags": ["cve.2020-1"]})()
    assert attack.for_rule(rule) is None
