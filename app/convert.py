"""Конвертация Sigma -> Lucene-запрос Graylog на pySigma + сбор диагностики."""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule import SigmaDetection, SigmaDetectionItem

from .i18n import tr
from .lucene_fix import describe_codes, fix_query


class ConversionError(RuntimeError):
    pass


def rule_fields(rule) -> set[str]:
    """Все поля, которые правило упоминает в detection."""
    found: set[str] = set()

    def walk(obj):
        if isinstance(obj, SigmaDetectionItem):
            if getattr(obj, "field", None):
                found.add(obj.field)
            for value in getattr(obj, "value", None) or []:
                walk(value)
        elif isinstance(obj, SigmaDetection):
            for item in obj.detection_items:
                walk(item)
        elif isinstance(obj, (list, tuple, set)):
            for item in obj:
                walk(item)

    for detection in rule.detection.detections.values():
        walk(detection)
    return found


def convert_rule(rule, mapping: dict[str, str], case_insensitive: bool = False) -> list[str]:
    """Конвертация одного правила с уже готовым маппингом полей."""
    pipeline = ProcessingPipeline(
        [ProcessingItem(FieldMappingTransformation(dict(mapping)))]
    )
    backend = LuceneBackend(processing_pipeline=pipeline)
    try:
        queries = backend.convert(SigmaCollection([rule]))
    except SigmaError as exc:
        raise ConversionError(str(exc)) from exc
    cleaned = [q.strip().replace("\n", " ") for q in queries if q and q.strip()]
    return [fix_query(q, case_insensitive) for q in cleaned]


def product_of(rule) -> str | None:
    return getattr(rule.logsource, "product", None)


# признаки продукта в именах полей правила
_PRODUCT_HINTS = {
    "windows": ("image", "commandline", "parentimage", "eventid", "targetfilename",
                "win_", "integritylevel", "hashes"),
    "linux": ("audit_type", "proctitle", "syscall", "exe", "cwd", "comm", "exe_path",
              "auditd_", "key", "syslog_hostname"),
    "macos": ("macos_", "es_event", "process_executable"),
}


def infer_product(fields: list[str]) -> str | None:
    """Продукт по полям правила — для правил без logsource.product.

    Linux-поля (proctitle, syscall, exe, cwd, audit_type) для Windows не встречаются,
    поэтому одного совпадения достаточно, чтобы отнести правило к Linux.
    """
    low = [f.lower() for f in fields]
    scores = {p: 0 for p in _PRODUCT_HINTS}
    for field in low:
        for product, hints in _PRODUCT_HINTS.items():
            if field in hints or any(field.startswith(h) for h in hints if h.endswith("_")):
                scores[product] += 1
    # exe/name/cwd в Windows тоже бывают, но в связке с syscall/proctitle/audit_type — только Linux
    linux_strong = any(f in ("proctitle", "syscall", "audit_type", "auditd_type") for f in low)
    if linux_strong:
        scores["linux"] += 3
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] >= 3 else None


def _warnings(rule, mapping: dict, queries: list[str], meta: dict | None = None,
              case_insensitive: bool = False, lang: str = "ru") -> list[dict]:
    out: list[dict] = []
    unknown = [f for f, m in mapping.items() if not m.get("graylog_field")]
    if unknown:
        out.append({
            "level": "error",
            "code": "unknown_fields",
            "message": tr(lang, "unknown_fields", fields=", ".join(sorted(unknown))),
            "fields": sorted(unknown),
        })
    cross = []
    for field, m in mapping.items():
        if m.get("graylog_field"):
            continue
        foreign = [c for c in (m.get("candidates") or []) if c.get("cross_product")]
        if foreign:
            cross.append((field, foreign[0]["product"]))
    for field, foreign_product in cross:
        out.append({
            "level": "error",
            "code": "cross_product_field",
            "message": tr(lang, "foreign_product", field=field, foreign=foreign_product,
                        own=(meta or {}).get("product") or "—"),
            "fields": [field],
        })

    meta = meta or {}
    stream = meta.get("stream") or {}
    if (stream.get("product") == "linux" and getattr(rule.logsource, "category", None) == "file_event"
            and any(f.lower() in ("targetfilename", "targetpath") for f in mapping)):
        out.append({
            "level": "warn",
            "code": "auditd_path_split",
            "message": tr(lang, "auditd_path"),
        })
    if meta.get("no_stream_for_product"):
        out.append({
            "level": "warn",
            "code": "no_stream_for_product",
            "message": tr(lang, "no_stream_for_product", product=meta.get("product")),
        })
    if meta.get("product") and meta.get("product_present") is False:
        out.append({
            "level": "warn",
            "code": "product_missing",
            "message": tr(lang, "product_absent", product=meta["product"],
                        available=", ".join(meta.get("products_available") or []) or "—"),
        })

    weak = [f for f, m in mapping.items()
            if m.get("graylog_field") and m.get("confidence", 0) < 85]
    if weak:
        out.append({
            "level": "warn",
            "code": "weak_mapping",
            "message": tr(lang, "weak_mapping", fields=", ".join(sorted(weak))),
            "fields": sorted(weak),
        })
    for q in queries:
        for code in describe_codes(q, case_insensitive):
            out.append({"level": "info", "code": "query_rewrite", "message": tr(lang, code)})
    ambiguous = [f for f, m in mapping.items() if m.get("ambiguous")]
    if ambiguous:
        out.append({
            "level": "warn",
            "code": "ambiguous_mapping",
            "message": tr(lang, "ambiguous_mapping", fields=", ".join(sorted(ambiguous))),
            "fields": sorted(ambiguous),
        })
    if any(re.search(r":\*", q) for q in queries):
        out.append({
            "level": "warn",
            "code": "leading_wildcard",
            "message": tr(lang, "leading_wildcard"),
        })
    if getattr(rule.logsource, "product", None) is None:
        out.append({
            "level": "info",
            "code": "no_product",
            "message": tr(lang, "no_logsource_product"),
        })
    if not queries:
        out.append({
            "level": "error",
            "code": "empty_result",
            "message": tr(lang, "no_query"),
        })
    return out


@dataclass
class ConvertedRule:
    index: int
    title: str
    rule_id: str | None
    level: str | None
    product: str | None
    category: str | None
    queries: list[str]
    fields: list[str]
    stream: dict | None = None
    warnings: list[dict] = dc_field(default_factory=list)


def convert(sigma_text: str, mapping_for, overrides: dict[str, str] | None = None,
            max_rules: int = 60, case_insensitive: bool = False, lang: str = "ru",
            default_product: str | None = None) -> dict:
    """mapping_for(product, fields) -> dict (см. mapping.build_mapping)."""
    try:
        collection = SigmaCollection.from_yaml(sigma_text)
    except Exception as exc:  # noqa: BLE001 - показываем текст ошибки пользователю
        raise ConversionError(tr(lang, "yaml_error", error=exc)) from exc

    rules_out: list[ConvertedRule] = []
    all_fields: dict[str, dict] = {}

    truncated_rules = len(collection.rules) > max_rules
    for idx, rule in enumerate(collection.rules[:max_rules]):
        fields = sorted(rule_fields(rule))
        # продукт: из правила -> из фильтра источника -> из полей правила
        product = product_of(rule) or (default_product or None) or infer_product(fields)
        product_source = "rule" if product_of(rule) else ("filter" if default_product else "inferred")
        mapping = mapping_for(product, fields, overrides or {})
        meta = mapping.pop("__meta__", {})
        enabled = {
            f: m["graylog_field"]
            for f, m in mapping.items()
            if m.get("graylog_field")
        }
        try:
            queries = convert_rule(rule, enabled, case_insensitive)
        except ConversionError as exc:
            queries = []
            err = str(exc)
        else:
            err = None

        for f in fields:
            all_fields[f] = mapping[f]

        warnings = _warnings(rule, mapping, queries, meta, case_insensitive, lang)
        if not product_of(rule) and product:
            warnings.append({"level": "info", "code": "product_from_hint",
                             "message": tr(lang, "product_from_hint", product=product,
                                           source=product_source)})
        if err:
            warnings.insert(0, {"level": "error", "code": "backend_error",
                                "message": tr(lang, "convert_error", error=err)})
        rules_out.append(ConvertedRule(
            index=idx,
            title=getattr(rule, "title", "") or f"rule-{idx}",
            rule_id=str(rule.id) if getattr(rule, "id", None) else None,
            level=str(rule.level) if getattr(rule, "level", None) else None,
            product=product,
            category=getattr(rule.logsource, "category", None),
            queries=queries,
            fields=fields,
            stream=meta.get("stream"),
            warnings=warnings,
        ))

    return {
        "rules": [
            {
                "index": r.index,
                "title": r.title,
                "rule_id": r.rule_id,
                "level": r.level,
                "product": r.product,
                "category": r.category,
                "queries": r.queries,
                "fields": r.fields,
                "stream": r.stream,
                "warnings": r.warnings,
            }
            for r in rules_out
        ],
        "fields": all_fields,
        "rule_count": len(rules_out),
        "total_in_input": len(collection.rules),
        "truncated_rules": truncated_rules,
        "max_rules": max_rules,
    }
