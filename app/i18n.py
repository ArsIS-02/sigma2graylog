"""Двуязычные сообщения сервера: предупреждения конвертации и ошибки.

Язык приходит заголовком X-Lang от интерфейса; по умолчанию — русский.
"""
from __future__ import annotations

MESSAGES: dict[str, dict[str, str]] = {
    "unknown_fields": {
        "ru": "Поля отсутствуют в индексах Graylog: {fields}",
        "en": "Fields missing in Graylog indexes: {fields}",
    },
    "foreign_product": {
        "ru": "Поле «{field}» найдено только в полях продукта {foreign}, а правило для {own} — в индексах такого поля нет",
        "en": "Field \"{field}\" exists only for product {foreign}, while the rule targets {own} — the index has no such field",
    },
    "auditd_path": {
        "ru": "В auditd путь разбит на два поля: cwd (каталог) и name (имя файла), поэтому startswith по полному пути может не сработать. Проверьте на истории и при необходимости ограничьте запрос вручную",
        "en": "In auditd the path is split into two fields: cwd (directory) and name (file name), so startswith on the full path may not match. Check it over history and narrow the query if needed",
    },
    "no_stream_for_product": {
        "ru": "Для продукта «{product}» не нашлось стрима с событиями — маппинг по общему списку полей индексов",
        "en": "No stream with events found for product \"{product}\" — mapping uses the global index field list",
    },
    "product_absent": {
        "ru": "В индексах не видно полей продукта «{product}» (есть: {available}). Возможно, источник логов не подключён",
        "en": "No fields for product \"{product}\" in the indexes (available: {available}). The log source may not be connected",
    },
    "weak_mapping": {
        "ru": "Сопоставление полей неуверенное, проверьте вручную: {fields}",
        "en": "Field mapping is uncertain, please check manually: {fields}",
    },
    "ambiguous_mapping": {
        "ru": "Несколько полей подходят одинаково хорошо, выберите вручную: {fields}",
        "en": "Several fields fit equally well, choose one manually: {fields}",
    },
    "leading_wildcard": {
        "ru": "Запрос содержит wildcard в начале значения (:*) — в Graylog это дорого на больших периодах.",
        "en": "The query has a leading wildcard (:*) — expensive in Graylog over long periods.",
    },
    "no_logsource_product": {
        "ru": "В правиле не указан logsource.product — маппинг полей будет менее точным.",
        "en": "The rule has no logsource.product — field mapping will be less accurate.",
    },
    "no_query": {
        "ru": "Бэкенд не выдал ни одного запроса.",
        "en": "The backend produced no query.",
    },
    "yaml_error": {
        "ru": "Не удалось разобрать YAML: {error}",
        "en": "Could not parse YAML: {error}",
    },
    "convert_error": {
        "ru": "Ошибка конвертации: {error}",
        "en": "Conversion error: {error}",
    },
    "regex_rewrite": {
        "ru": "contains/endswith переведены в regex: Graylog не принимает незакавыченный leading wildcard. Regex в Graylog регистрозависимый.",
        "en": "contains/endswith converted to regex: Graylog rejects an unquoted leading wildcard. Regex in Graylog is case-sensitive.",
    },
    "case_insensitive": {
        "ru": "contains/endswith переведены в regex без учёта регистра (символьные классы, как в Sigma) — запрос длиннее, но точнее.",
        "en": "contains/endswith converted to case-insensitive regex (character classes, as in Sigma) — longer query, but more precise.",
    },
}


def tr(lang: str, key: str, **params) -> str:
    """Сообщение на нужном языке; при отсутствии ключа возвращает сам ключ."""
    entry = MESSAGES.get(key)
    if not entry:
        return key
    template = entry.get(lang) or entry["ru"]
    try:
        return template.format(**params)
    except (KeyError, IndexError):
        return template


def lang_of(value: str | None) -> str:
    """Нормализует значение заголовка X-Lang."""
    return "en" if (value or "").lower().startswith("en") else "ru"
