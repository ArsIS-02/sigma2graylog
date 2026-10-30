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

# Метасимволы, которые pySigma не экранирует, а в regex (Lucene/OpenSearch, флаги ALL) значимы.
_REGEX_SPECIAL = set(".+()[]{}^$|/#@&<>~\"")

_FIELD_RE = re.compile(r"[A-Za-z0-9_.\-]+:")


def _term_end(q: str, i: int) -> int:
    """Конец терма, начинающегося в позиции i: "..." с учётом \\X либо токен до пробела/скобки."""
    n = len(q)
    if i < n and q[i] == '"':
        j = i + 1
        while j < n:
            if q[j] == "\\":
                j += 2
                continue
            if q[j] == '"':
                return j + 1
            j += 1
        return n  # незакрытая кавычка — отдаём остаток как есть
    j = i
    while j < n:
        if q[j] == "\\":
            j += 2
            continue
        if q[j].isspace() or q[j] in "()":
            break
        j += 1
    return min(j, n)


def _escape_for_regex(value: str) -> str:
    """Значение Sigma/Lucene -> regex: \\X сохраняем, * -> .*, ? -> ., прочие метасимволы экранируем."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            out.append(value[i:i + 2])
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch in _REGEX_SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
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
    """Переписывает leading-wildcard термы в regex, не трогая остальное.

    Разбор посимвольный: кавычки и экранирование учитываются, поэтому `*` внутри
    фразы "..." и значения вида `\\ ` или `\\"` не ломают запрос.
    """
    out: list[str] = []
    i, n = 0, len(query)
    while i < n:
        ch = query[i]
        if ch == "\\":
            out.append(query[i:i + 2])
            i += 2
            continue
        if ch == '"':  # самостоятельная фраза — не трогаем целиком
            j = _term_end(query, i)
            out.append(query[i:j])
            i = j
            continue
        at_start = i == 0 or query[i - 1].isspace() or query[i - 1] == "("
        if at_start:
            m = _FIELD_RE.match(query, i)
            k = m.end() if m else i
            if (m or ch == "*") and k < n and query[k] in '*"':
                j = _term_end(query, k)
                out.append(query[i:k] + _term_to_regex(query[k:j], case_insensitive))
                i = j
                continue
        out.append(ch)
        i += 1
    return "".join(out)


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
