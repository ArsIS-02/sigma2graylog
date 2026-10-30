"""Каталог публичных источников Sigma-правил и загрузка с фильтрами."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import httpx
import yaml

from .loader import _iter_archive, MAX_TOTAL_BYTES

CACHE_TTL = 24 * 3600
URL_TIMEOUT = 60.0

SOURCES: list[dict] = [
    {
        "id": "sigmahq-all",
        "name": "SigmaHQ — все правила",
        "url": "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip",
        "homepage": "https://github.com/SigmaHQ/sigma",
        "description": "Официальный репозиторий SigmaHQ, релизный архив (~3000 правил, 3 МБ)",
    },
    {
        "id": "sigmahq-core",
        "name": "SigmaHQ — core",
        "url": "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip",
        "homepage": "https://github.com/SigmaHQ/sigma",
        "description": "Только курируемое ядро правил SigmaHQ (1.4 МБ)",
    },
    {
        "id": "sigmahq-master",
        "name": "SigmaHQ — master (tar.gz)",
        "url": "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz",
        "homepage": "https://github.com/SigmaHQ/sigma",
        "description": "Текущее состояние репозитория, включая правила вне релиза",
    },
    {
        "id": "threat-hunting-keywords",
        "name": "ThreatHunting Keywords (mthcht)",
        "url": "https://github.com/mthcht/ThreatHunting-Keywords-sigma-rules/archive/refs/heads/main.tar.gz",
        "homepage": "https://github.com/mthcht/ThreatHunting-Keywords-sigma-rules",
        "description": "Коллекция правил для threat hunting по ключевым словам",
    },
    {
        "id": "sigmadetectionrules",
        "name": "SIGMA detection rules (mdecrevoisier)",
        "url": "https://github.com/mdecrevoisier/SIGMA-detection-rules/archive/refs/heads/main.tar.gz",
        "homepage": "https://github.com/mdecrevoisier/SIGMA-detection-rules",
        "description": "Практические правила под Windows/AD-атаки и пентест",
    },
]

_SPECIAL = re.compile(r"[^a-z0-9]")


def _field(text: str, name: str) -> str | None:
    m = re.search(rf"(?mi)^\s*{name}:\s*['\"]?([\w\-\. ]+)['\"]?\s*$", text)
    return m.group(1).strip() if m else None


def _rule_meta(text: str) -> dict:
    return {
        "title": (_field(text, "title") or "untitled").strip(),
        "product": (_field(text, "product") or "").lower() or None,
        "category": (_field(text, "category") or "").lower() or None,
        "service": (_field(text, "service") or "").lower() or None,
        "level": (_field(text, "level") or "").lower() or None,
        "id": _field(text, "id"),
    }


CACHE_VERSION = 2


def _split_rules(text: str) -> list[str]:
    """Разбирает файл на правила через YAML, а не регуляркой.

    Регулярка по строке '---' рвала документы, если такая строка встречалась
    внутри блочного описания (description: |) — получались обрывки правил.
    """
    out: list[str] = []
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return out
    for doc in documents:
        if not isinstance(doc, dict) or not doc.get("title"):
            continue
        # pySigma принимает category/service/product только строкой
        logsource = doc.get("logsource") or {}
        if isinstance(logsource, dict):
            if any(isinstance(logsource.get(key), (list, dict))
                   for key in ("category", "service", "product")):
                continue
        try:
            out.append(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=1000))
        except yaml.YAMLError:
            continue
    return out


class SourceCache:
    def __init__(self, directory: Path, ttl: int = CACHE_TTL):
        self.dir = directory
        self.ttl = ttl

    def path(self, source_id: str) -> Path:
        return self.dir / f"{source_id}.json"

    def load(self, source_id: str) -> dict | None:
        try:
            return json.loads(self.path(source_id).read_text("utf-8"))
        except (OSError, ValueError):
            return None

    def save(self, source_id: str, payload: dict) -> None:
        payload = {**payload, "version": CACHE_VERSION}
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path(source_id).with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), "utf-8")
        tmp.replace(self.path(source_id))

    def fresh(self, source_id: str) -> dict | None:
        data = self.load(source_id)
        if data and (time.time() - data.get("fetched_at", 0)) < self.ttl:
            return data
        return None

    def listing(self) -> list[dict]:
        """Скачанные наборы, доступные в библиотеке (независимо от TTL)."""
        out = []
        names = {src["id"]: src["name"] for src in SOURCES}
        for path in sorted(self.dir.glob("*.json")):
            data = self.load(path.stem)
            if not data or not data.get("rules"):
                continue
            products: dict[str, int] = {}
            levels: dict[str, int] = {}
            for rule in data["rules"]:
                prod = rule.get("product") or "—"
                products[prod] = products.get(prod, 0) + 1
                lvl = rule.get("level") or "—"
                levels[lvl] = levels.get(lvl, 0) + 1
            out.append({
                "id": path.stem,
                "name": names.get(path.stem, path.stem),
                "count": len(data["rules"]),
                "fetched_at": data.get("fetched_at", 0),
                "products": dict(sorted(products.items(), key=lambda kv: -kv[1])),
                "levels": dict(sorted(levels.items(), key=lambda kv: -kv[1])),
            })
        return out

    def delete(self, source_id: str) -> bool:
        try:
            self.path(source_id).unlink()
            return True
        except OSError:
            return False

    def rules(self, source_id: str) -> list[dict]:
        """Правила набора; пусто, если набор скачан старой версией парсера."""
        data = self.load(source_id)
        if not data or data.get("version") != CACHE_VERSION:
            return []
        return data.get("rules", [])

    def stale(self, source_id: str) -> bool:
        data = self.load(source_id)
        return bool(data) and data.get("version") != CACHE_VERSION

    def info(self) -> dict[str, dict]:
        out = {}
        for src in SOURCES:
            data = self.load(src["id"])
            if data:
                out[src["id"]] = {
                    "count": len(data.get("rules") or []),
                    "fetched_at": data.get("fetched_at"),
                }
        return out


def download(url: str) -> bytes:
    with httpx.Client(follow_redirects=True, timeout=URL_TIMEOUT,
                      headers={"User-Agent": "sigma2graylog/1.0"}) as client:
        response = client.get(url)
        response.raise_for_status()
        data = response.content
    if len(data) > MAX_TOTAL_BYTES:
        raise ValueError("Источник слишком большой")
    if len(data) < 100:
        raise ValueError("Источник вернул пустой ответ")
    return data


def build_rules(source: dict) -> list[dict]:
    """Скачивает источник и разбирает его в список правил с метаданными."""
    data = download(source["url"])
    name = source["url"].split("/")[-1]
    files = _iter_archive(name, data)
    if not files:
        raise ValueError("Не удалось распаковать архив источника")
    rules: list[dict] = []
    seen: set[str] = set()
    for path, raw in files.items():
        if not path.lower().endswith((".yml", ".yaml")):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for doc in _split_rules(text):
            meta = _rule_meta(doc)
            key = meta["id"] or meta["title"]
            if key in seen:
                continue
            seen.add(key)
            rules.append({"text": doc, "path": path, **meta})
    if not rules:
        raise ValueError("В источнике не найдено Sigma-правил")
    return rules


def filter_rules(rules: list[dict], product: str | None = None,
                 category: str | None = None, level: str | None = None,
                 query: str | None = None, limit: int = 50) -> list[dict]:
    def norm(value: str | None) -> str:
        return _SPECIAL.sub("", (value or "").lower())

    out = []
    levels = {l.strip().lower() for l in (level or "").split(",") if l.strip()}
    q = (query or "").strip().lower()
    for rule in rules:
        if product and (rule.get("product") or "") != product.lower():
            continue
        if category and (rule.get("category") or "") != category.lower():
            continue
        if levels and (rule.get("level") or "") not in levels:
            continue
        if q and q not in (rule.get("title") or "").lower():
            continue
        out.append(rule)
    out.sort(key=lambda r: (r.get("title") or "").lower())
    return out[: max(1, min(limit, 300))]
