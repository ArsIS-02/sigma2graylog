"""Корреляционные правила Sigma (event_count / value_count) -> агрегация определения Graylog."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import convert as converter  # noqa: E402
from app.graylog import GraylogError, aggregation_config  # noqa: E402

BASE = """title: Failed logon
id: 11111111-1111-1111-1111-111111111111
name: failed_logon
logsource: {product: windows, category: process_creation}
tags: [attack.credential-access, attack.t1110]
detection:
  sel:
    Image|endswith: '\\\\x.exe'
  condition: sel
"""


def _corr(ctype="event_count", cond="  condition: {gte: 5}\n", group="  group-by: [Image]\n",
          rules="[failed_logon]"):
    return BASE + f"""---
title: Brute force
id: 22222222-2222-2222-2222-222222222222
correlation:
  type: {ctype}
  rules: {rules}
{group}  timespan: 10m
{cond}level: high
"""


def _mapping(product, fields, overrides):
    out = {f: {"graylog_field": f.lower(), "confidence": 100} for f in fields}
    out["__meta__"] = {}
    return out


def _run(text):
    return converter.convert(text, _mapping)


def _codes(rule):
    return {w["code"] for w in rule["warnings"]}


def test_event_count():
    res = _run(_corr())
    assert res["rule_count"] == 2
    corr = res["rules"][-1]
    assert corr["title"] == "Brute force"
    assert corr["queries"] and corr["queries"][0].startswith("(image:")
    assert corr["aggregation"] == {
        "type": "event_count", "operator": ">=", "threshold": 5, "timespan_seconds": 600,
        "group_by": ["image"], "value_field": None, "sigma_group_by": ["Image"],
    }
    assert corr["attack"] and corr["attack"]["techniques"] == ["T1110"]


def test_base_rule_is_still_converted_and_flagged():
    base = _run(_corr())["rules"][0]
    assert base["queries"]
    assert "corr_base_rule" in _codes(base)
    assert base["aggregation"] is None


def test_value_count_uses_field():
    corr = _run(_corr("value_count", "  condition: {gt: 3, field: CommandLine}\n"))["rules"][-1]
    assert corr["aggregation"]["type"] == "value_count"
    assert corr["aggregation"]["value_field"] == "commandline"
    assert corr["aggregation"]["operator"] == ">"


def test_no_group_by_is_noted():
    corr = _run(_corr(group=""))["rules"][-1]
    assert corr["aggregation"]["group_by"] == []
    assert "corr_no_group" in _codes(corr)


def test_unsupported_type_is_reported_not_crashing():
    corr = _run(_corr("value_sum", "  condition: {gt: 3, field: CommandLine}\n"))["rules"][-1]
    assert corr["queries"] == [] and corr["aggregation"] is None
    assert "corr_unsupported" in _codes(corr)


def test_missing_referenced_rule():
    # pySigma сам не даёт разобрать ссылку на несуществующее правило — пользователь видит понятную ошибку
    try:
        _run(_corr(rules="[nope]"))
    except converter.ConversionError as exc:
        assert "nope" in str(exc)
    else:
        raise AssertionError("ожидалась ConversionError")


def test_group_field_without_mapping_is_error():
    def no_map(product, fields, overrides):
        out = _mapping(product, fields, overrides)
        if "Image" in fields and len(fields) == 1:
            out["Image"] = {"graylog_field": None, "confidence": 0}
        return out

    corr = converter.convert(_corr(), no_map)["rules"][-1]
    assert corr["aggregation"] is None
    assert "unknown_fields" in _codes(corr)


def test_aggregation_config_count():
    cfg = aggregation_config({"type": "event_count", "operator": ">=", "threshold": 5,
                              "timespan_seconds": 600, "group_by": ["image"]})
    assert cfg["group_by"] == ["image"]
    assert cfg["series"] == [{"id": "count()", "type": "count", "field": None}]
    assert cfg["conditions"]["expression"] == {
        "expr": ">=", "left": {"expr": "number-ref", "ref": "count()"},
        "right": {"expr": "number", "value": 5}}
    assert cfg["search_within_ms"] == 600_000
    assert cfg["execute_every_ms"] == 60_000


def test_aggregation_config_card_and_short_window():
    cfg = aggregation_config({"type": "value_count", "operator": ">", "threshold": 3,
                              "timespan_seconds": 30, "group_by": [], "value_field": "user"})
    assert cfg["series"][0] == {"id": "card(user)", "type": "card", "field": "user"}
    assert cfg["execute_every_ms"] == 30_000


def test_aggregation_config_rejects_bad_input():
    for bad in ({"type": "value_count", "operator": ">", "threshold": 1},
                {"type": "event_count", "operator": "~", "threshold": 1}):
        try:
            aggregation_config(bad)
        except GraylogError:
            continue
        raise AssertionError("ожидалась GraylogError")
    assert aggregation_config(None) is None


def test_group_field_is_listed_for_manual_mapping():
    def no_map(product, fields, overrides):
        out = _mapping(product, fields, overrides)
        if fields == ["Image"]:
            out["Image"] = {"graylog_field": None, "confidence": 0, "candidates": []}
        return out

    res = converter.convert(_corr(), no_map)
    corr = res["rules"][-1]
    assert "Image" in corr["fields"]
    assert "Image" in res["fields"]  # попадает в таблицу сопоставления, можно выбрать вручную
    assert "unknown_fields" in _codes(corr)
