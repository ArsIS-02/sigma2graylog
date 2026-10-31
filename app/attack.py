"""Теги MITRE ATT&CK из Sigma-правил -> поля событий Graylog.

Правило Sigma описывает тактику и технику тегами `attack.execution`, `attack.t1059.001`.
Здесь они превращаются в три поля, которые записываются в определение события (field_spec):

  mitre_tactic      Execution
  mitre_technique   T1059.001 PowerShell          (основная: первая в тегах)
  mitre_techniques  T1059.001, T1105              (все)

Справочник — ATT&CK v20 (app/attack_v20.json). В v20 часть идентификаторов заменена
(T1562.* -> T1685.*/T1686.*, T1070.001/.002 -> T1685.005/.006), старые теги переводятся
на новые и помечаются в `renamed`. Неизвестный справочнику идентификатор сохраняется как есть.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_REF_PATH = Path(__file__).resolve().parent / "attack_v20.json"

# идентификаторы, которых в ATT&CK v20 больше нет
RENAMED = {
    "T1562": "T1685",
    "T1562.001": "T1685",
    "T1562.002": "T1685.004",
    "T1562.004": "T1686",
    "T1562.006": "T1685.001",
    "T1562.012": "T1685.004",
    "T1070.001": "T1685.005",
    "T1070.002": "T1685.006",
}

_TECH_RE = re.compile(r"^t(\d{4})(?:\.(\d{3}))?$", re.I)
MAX_IDS = 20


@lru_cache(maxsize=1)
def reference() -> dict:
    with open(_REF_PATH, encoding="utf-8") as f:
        return json.load(f)


def _tag_text(tag) -> str:
    """Тег как строка вида `attack.t1059.001` (SigmaRuleTag или обычная строка)."""
    ns = getattr(tag, "namespace", None)
    name = getattr(tag, "name", None)
    if ns is not None and name is not None:
        return f"{ns}.{name}"
    return str(tag)


def parse_tags(tags) -> dict:
    """Разбирает теги правила: {'tactics': [shortname], 'techniques': [ID], 'renamed': {old: new}}."""
    ref = reference()
    tactics: list[str] = []
    techniques: list[str] = []
    renamed: dict[str, str] = {}
    for tag in tags or []:
        text = _tag_text(tag).strip().lower()
        if not text.startswith("attack."):
            continue
        body = text[len("attack."):]
        m = _TECH_RE.match(body)
        if m:
            tid = "T" + m.group(1) + ("." + m.group(2) if m.group(2) else "")
            if tid in RENAMED and tid not in ref["techniques"]:
                renamed[tid] = RENAMED[tid]
                tid = RENAMED[tid]
            if tid not in techniques:
                techniques.append(tid)
        elif body.replace("_", "-") in ref["tactics"]:
            name = body.replace("_", "-")
            if name not in tactics:
                tactics.append(name)
    return {"tactics": tactics[:MAX_IDS], "techniques": techniques[:MAX_IDS], "renamed": renamed}


def describe(attack: dict | None) -> dict | None:
    """Готовые значения полей по {'tactics': [...], 'techniques': [...]}; None, если пусто.

    Тактика основной техники: первая из тегов правила, которая есть у этой техники; если тегов
    тактик нет, первая тактика техники по справочнику; если нет и техники, первый тег тактики.
    """
    if not attack:
        return None
    ref = reference()
    tactics = [t for t in (attack.get("tactics") or []) if t in ref["tactics"]][:MAX_IDS]
    ids = [t for t in (attack.get("techniques") or [])
           if isinstance(t, str) and re.fullmatch(r"T\d{4}(\.\d{3})?", t)][:MAX_IDS]
    if not tactics and not ids:
        return None
    items = [{"id": i, "name": (ref["techniques"].get(i) or {}).get("name"),
              "known": i in ref["techniques"]} for i in ids]
    tactic = None
    if ids:
        own = (ref["techniques"].get(ids[0]) or {}).get("tactics") or []
        tactic = next((t for t in tactics if t in own), None) or (own[0] if own else None)
    if tactic is None and tactics:
        tactic = tactics[0]
    primary = None
    if items:
        p = items[0]
        primary = p["id"] + (" " + p["name"] if p["name"] else "")
    return {
        "tactic": ref["tactics"][tactic]["name"] if tactic else "",
        "technique": primary or "",
        "techniques": ", ".join(ids),
        "items": items,
    }


def description_line(attack: dict | None) -> str:
    """Строка для описания определения: «MITRE ATT&CK. Тактики: ... Техники: ...».

    Тактики: основная первой, затем остальные тактики всех техник правила (без повторов),
    потом тактики из тегов правила. Если техник нет, только тактики из тегов.
    """
    d = describe(attack)
    if not d:
        return ""
    ref = reference()
    order: list[str] = []
    main = next((k for k, v in ref["tactics"].items() if v["name"] == d["tactic"]), None)
    if main:
        order.append(main)
    for item in d["items"]:
        for k in (ref["techniques"].get(item["id"]) or {}).get("tactics") or []:
            if k not in order:
                order.append(k)
    for k in (attack.get("tactics") or []):
        if k in ref["tactics"] and k not in order:
            order.append(k)
    parts = ["MITRE ATT&CK."]
    if order:
        parts.append("Тактики: " + ", ".join(ref["tactics"][k]["name"] for k in order) + ".")
    if d["items"]:
        parts.append("Техники: " + "; ".join(
            i["id"] + (" " + i["name"] if i["name"] else "") for i in d["items"]) + ".")
    return " ".join(parts)


def with_description(description: str, attack: dict | None) -> str:
    """Описание с добавленной строкой ATT&CK; повторный вызов строку не дублирует."""
    line = description_line(attack)
    base = re.sub(r"\s*MITRE ATT&CK\.[\s\S]*$", "", description or "").rstrip()
    if not line:
        return description or ""
    return (base + "\n" + line) if base else line


def field_spec(attack: dict | None) -> dict:
    """field_spec для определения события Graylog (template-v1 со статическим текстом)."""
    d = describe(attack)
    if not d:
        return {}
    out = {}
    for key in ("tactic", "technique", "techniques"):
        if not d[key]:
            continue
        out["mitre_" + key] = {
            "data_type": "string",
            "providers": [{"type": "template-v1", "template": d[key],
                           "require_values": False, "exclude_empty_fields": False}],
        }
    return out


def for_rule(rule) -> dict | None:
    """Данные ATT&CK правила для ответа конвертера; None, если у правила нет attack-тегов."""
    parsed = parse_tags(getattr(rule, "tags", None))
    d = describe(parsed)
    if not d:
        return None
    return {"tactics": parsed["tactics"], "techniques": parsed["techniques"],
            "renamed": parsed["renamed"], "tactic": d["tactic"], "technique": d["technique"],
            "items": d["items"]}
