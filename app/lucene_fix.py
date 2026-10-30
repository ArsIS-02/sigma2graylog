"""Приведение Lucene-запроса pySigma к синтаксису, который реально понимает Graylog.

Проверено на Graylog 7.2.1 / OpenSearch:
  * `field:*value*`   — ошибка разбора запроса (leading wildcard без кавычек);
  * `field:"*value*"` — разбирается, но не находит ничего;
  * `field:value*`    — работает (хвостовой wildcard);
  * `field:/.*value.*/` — работает (regex), счётчики совпадают с ожидаемыми.

Поэтому всё, что начинается с `*` (Sigma-модификаторы contains/endswith),
переводим в regex-запрос, экранируя метасимволы значения.
"""
from __future__ import annotations

import re

# Метасимволы, которые pySigma не экранирует, а в regex они значимы.
_REGEX_SPECIAL = set(".+?()[]{}^$|")

# field:*value* | field:"*value with spaces*" | field:*value
_FIELD_TERM = re.compile(r'(?P<pre>[A-Za-z0-9_.\-]+:)(?P<term>"\*[^"]*"|\*[^\s()"]*)')
# то же, но без префикса поля: (*value* ...)
_BARE_TERM = re.compile(r'(?P<pre>^|[\s(])(?P<term>\*[^\s()"]+)')


def _escape_for_regex(value: str) -> str:
    """Экранирует значение так, чтобы оно совпало буквально, сохраняя готовые \\X."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            out.append(value[i:i + 2])
            i += 2
            continue
        out.append("\\" + ch if ch in _REGEX_SPECIAL else ch)
        i += 1
    return "".join(out)


MAX_CASE_EXPAND = 48


def _expand_case(value: str) -> str:
    """powershell -> [Pp]ower[Ss]hell: Graylog-regex регистрозависим, Sigma — нет."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            out.append(value[i:i + 2])  # экранированная последовательность — как есть
            i += 2
            continue
        if ch.isalpha() and ord(ch) < 128:
            out.append(f"[{ch.upper()}{ch.lower()}]")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _term_to_regex(term: str, case_insensitive: bool = False) -> str:
    quoted = term.startswith('"') and term.endswith('"') and len(term) >= 2
    inner = term[1:-1] if quoted else term
    if not inner.startswith("*") or inner == "*":
        return term
    trailing = inner.endswith("*")
    body = inner[1:-1] if trailing else inner[1:]
    if not body:
        return term
    escaped = _escape_for_regex(body)
    if case_insensitive and len(body) <= MAX_CASE_EXPAND:
        escaped = _expand_case(escaped)
    return f"/.*{escaped}.*/" if trailing else f"/.*{escaped}/"


def fix_query(query: str, case_insensitive: bool = False) -> str:
    """Переписывает leading-wildcard термы в regex, не трогая остальное."""

    def repl(m: re.Match) -> str:
        return m.group("pre") + _term_to_regex(m.group("term"), case_insensitive)

    query = _FIELD_TERM.sub(repl, query)
    query = _BARE_TERM.sub(repl, query)
    return query


def describe_codes(query: str, case_insensitive: bool = False) -> list[str]:
    """Коды замечаний к запросу (текст подставляет слой i18n)."""
    notes = []
    if ":/" in query:
        notes.append("case_insensitive" if case_insensitive else "regex_rewrite")
    return notes


def describe(query: str, case_insensitive: bool = False) -> list[str]:
    """Человекочитаемые замечания к запросу (по умолчанию по-русски)."""
    from .i18n import tr
    return [tr("ru", code) for code in describe_codes(query, case_insensitive)]
