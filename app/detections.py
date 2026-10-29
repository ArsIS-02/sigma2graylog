"""Работа с существующими Event Definition в Graylog и поиск дубликатов."""
from __future__ import annotations

import re
import time
from difflib import SequenceMatcher

_STOP = {"and", "or", "not", "field", "true", "false"}


def normalize_query(query: str) -> set[str]:
    """Набор токенов запроса для сравнения: без регистра и пунктуации."""
    low = (query or "").lower()
    low = re.sub(r"[()\[\]{}\"']", " ", low)
    tokens = {t for t in re.split(r"\s+", low) if t}
    return {t for t in tokens if t not in _STOP}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def title_ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, (a or "").lower().strip(), (b or "").lower().strip()).ratio()


def similarity(new_query: str, new_title: str, existing: dict) -> dict:
    query_n = normalize_query(new_query)
    query_e = normalize_query(existing.get("query", ""))
    q_score = jaccard(query_n, query_e)
    t_score = title_ratio(new_title, existing.get("title", ""))
    score = max(q_score, 0.65 * q_score + 0.35 * t_score)
    return {
        "score": round(score, 3),
        "query_score": round(q_score, 3),
        "title_score": round(t_score, 3),
        "same_query": query_n == query_e and bool(query_n),
    }


def find_duplicates(new_query: str, new_title: str, existing: list[dict],
                    threshold: float = 0.55, limit: int = 3) -> list[dict]:
    scored = []
    for item in existing:
        sim = similarity(new_query, new_title, item)
        if sim["score"] >= threshold:
            scored.append({**item, **sim})
    scored.sort(key=lambda x: -x["score"])
    return scored[:limit]


class DefinitionCache:
    """Кэш списка определений, чтобы не дёргать Graylog на каждую конвертацию."""

    def __init__(self, ttl: int = 120):
        self.ttl = ttl
        self.items: list[dict] | None = None
        self.loaded_at = 0.0

    def get(self, fetch, force: bool = False) -> list[dict]:
        if force or self.items is None or (time.time() - self.loaded_at) > self.ttl:
            self.items = fetch()
            self.loaded_at = time.time()
        return self.items

    def invalidate(self) -> None:
        self.items = None
        self.loaded_at = 0.0
