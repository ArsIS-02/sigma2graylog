"""Клиент Graylog REST API: поля, стримы, пробный поиск, создание Event Definition."""
from __future__ import annotations

import httpx

from .attack import definition_techniques as attack_definition_techniques
from .attack import field_spec as attack_field_spec
from .attack import with_description as attack_description


class GraylogError(RuntimeError):
    pass


_AGG_OPS = {">=", ">", "<=", "<", "==", "!="}


def aggregation_config(aggregation: dict | None) -> dict | None:
    """Описание агрегации из конвертера -> куски config события Graylog (aggregation-v1)."""
    if not aggregation:
        return None
    op = aggregation.get("operator") or ">="
    if op not in _AGG_OPS:
        raise GraylogError(f"Неподдерживаемый оператор порога: {op}")
    if aggregation.get("type") == "value_count":
        field = aggregation.get("value_field")
        if not field:
            raise GraylogError("Для value_count нужно поле, по которому считаются значения")
        series = {"id": f"card({field})", "type": "card", "field": field}
    else:
        series = {"id": "count()", "type": "count", "field": None}
    span_ms = max(1, int(aggregation.get("timespan_seconds") or 60)) * 1000
    threshold = aggregation.get("threshold") or 0
    return {
        "group_by": list(aggregation.get("group_by") or []),
        "series": [series],
        "conditions": {"expression": {
            "expr": op,
            "left": {"expr": "number-ref", "ref": series["id"]},
            "right": {"expr": "number", "value": threshold},
        }},
        "search_within_ms": span_ms,
        # проверка раз в минуту, но не реже, чем окно
        "execute_every_ms": min(60_000, span_ms),
    }


class Graylog:
    def __init__(self, base_url: str, user: str | None = None, password: str | None = None,
                 token: str | None = None, timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        headers = {"Accept": "application/json", "X-Requested-By": "sigma2graylog"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
            auth = None
        else:
            auth = (user or "", password or "")
        self._client = httpx.Client(base_url=self.base_url, auth=auth, headers=headers,
                                    timeout=timeout)

    # --- служебное ---------------------------------------------------------
    def _get(self, path: str, **params):
        r = self._client.get(path, params=params or None)
        if r.status_code >= 400:
            raise GraylogError(f"GET {path} -> {r.status_code}: {r.text[:300]}")
        return r.json()

    def _post(self, path: str, payload: dict):
        r = self._client.post(path, json=payload)
        if r.status_code >= 400:
            raise GraylogError(f"POST {path} -> {r.status_code}: {r.text[:600]}")
        return r.json() if r.content else {}

    def close(self):
        self._client.close()

    # --- данные ------------------------------------------------------------
    def system(self) -> dict:
        d = self._get("/api/system")
        return {
            "version": d.get("version"),
            "codename": d.get("codename"),
            "cluster_id": d.get("cluster_id"),
            "is_leader": d.get("is_leader"),
        }

    def fields(self) -> list[dict]:
        data = self._get("/api/system/fields")
        raw = data.get("fields", data) if isinstance(data, dict) else data
        out = []
        for item in raw:
            if isinstance(item, str):
                out.append({"name": item, "type": None})
            elif isinstance(item, dict):
                name = item.get("name")
                if name:
                    out.append({"name": name, "type": item.get("type")})
        out.sort(key=lambda f: f["name"].lower())
        return out

    def streams(self) -> list[dict]:
        data = self._get("/api/streams")
        out = []
        for s in data.get("streams", []):
            out.append({
                "id": s.get("id"),
                "title": s.get("title"),
                "description": s.get("description"),
                "index_set_id": s.get("index_set_id"),
                "disabled": s.get("disabled"),
            })
        out.sort(key=lambda s: (s["title"] or "").lower())
        return out

    def index_sets(self) -> list[dict]:
        data = self._get("/api/system/indices/index_sets", stats="false")
        return [{
            "id": s.get("id"),
            "title": s.get("title"),
            "index_prefix": s.get("index_prefix"),
        } for s in data.get("index_sets", [])]

    def count(self, query: str, range_seconds: int = 86400, stream_id: str | None = None) -> dict:
        """Сколько событий за период отдаёт запрос. Заодно валидация синтаксиса."""
        q = query
        if stream_id:
            q = f"({query}) AND streams:{stream_id}"
        data = self._get("/api/search/universal/relative",
                         query=q, range=range_seconds, limit=1)
        return {
            "total_results": data.get("total_results"),
            "built_query": data.get("built_query"),
            "errors": data.get("errors"),
            "duration_ms": data.get("duration"),
            "effective_query": q,
        }

    def stream_fields(self, stream_id: str, limit: int = 200, days: int = 7) -> dict:
        """Реальные поля событий стрима (по выборке) — а не глобальный список индексов."""
        data = self._get("/api/search/universal/relative", query=f"streams:{stream_id}",
                         range=days * 86400, limit=limit)
        counter: dict[str, int] = {}
        messages = data.get("messages") or []
        for msg in messages:
            for key in (msg.get("message") or {}):
                counter[key] = counter.get(key, 0) + 1
        fields = [{"name": k, "count": v} for k, v in counter.items()
                  if not k.startswith("gl2_") and k != "_id"]
        fields.sort(key=lambda f: (-f["count"], f["name"]))
        return {
            "stream_id": stream_id,
            "sampled": len(messages),
            "total_in_stream": data.get("total_results"),
            "fields": fields,
        }

    def history(self, query: str, days: int = 30, stream_id: str | None = None,
                samples: int = 3) -> dict:
        """Совпадения по дням за период + примеры событий."""
        days = max(1, min(int(days), 90))
        q = query
        if stream_id:
            q = f"({query}) AND streams:{stream_id}"
        payload = {
            "queries": [{
                "id": "q1",
                "query": {"type": "elasticsearch", "query_string": q},
                "timerange": {"type": "relative", "range": days * 86400},
                "search_types": [{
                    "id": "hist",
                    "type": "pivot",
                    "row_groups": [{"type": "time", "field": "timestamp", "interval": "1d"}],
                    "column_groups": [],
                    "series": [{"id": "count()", "type": "count"}],
                    "rollup": True,
                }],
            }]
        }
        r = self._client.post("/api/views/search/sync", json=payload)
        if r.status_code >= 400:
            raise GraylogError(f"POST /api/views/search/sync -> {r.status_code}: {r.text[:300]}")
        data = r.json()
        result = (data.get("results") or {}).get("q1") or {}
        hist = (result.get("search_types") or {}).get("hist") or {}
        buckets = []
        total = 0
        for row in hist.get("rows") or []:
            key = (row.get("key") or [None])[0]
            value = 0
            for item in row.get("values") or []:
                value = item.get("value") or 0
            if key:
                buckets.append({"date": str(key)[:10], "count": value})
                total += value
        buckets.sort(key=lambda b: b["date"])

        sample_events = []
        if samples:
            try:
                found = self._get("/api/search/universal/relative", query=q,
                                  range=days * 86400, limit=samples)
                for msg in (found.get("messages") or [])[:samples]:
                    body = msg.get("message") or {}
                    sample_events.append({
                        "timestamp": body.get("timestamp"),
                        "source": body.get("source"),
                        "message": (body.get("message") or "")[:300],
                    })
            except GraylogError:
                pass

        avg = round(total / days, 1) if days else 0
        if total == 0:
            verdict = {"level": "warn", "text": "На исторических данных не срабатывает ни разу"}
        elif avg >= 1000:
            verdict = {"level": "error", "text": f"Очень шумно: в среднем {avg:g} срабатываний в сутки"}
        elif avg >= 100:
            verdict = {"level": "warn", "text": f"Шумновато: в среднем {avg:g} срабатываний в сутки"}
        else:
            verdict = {"level": "ok", "text": f"Умеренно: в среднем {avg:g} срабатываний в сутки"}
        return {
            "days": days,
            "buckets": buckets,
            "total": total,
            "average_per_day": avg,
            "max_per_day": max([b["count"] for b in buckets], default=0),
            "verdict": verdict,
            "samples": sample_events,
            "errors": result.get("errors") or [],
        }

    def create_event_definition(self, *, title: str, query: str, description: str = "",
                                priority: int = 2, stream_ids: list[str] | None = None,
                                search_within_ms: int = 300_000,
                                execute_every_ms: int = 60_000,
                                attack: dict | None = None,
                                aggregation: dict | None = None) -> dict:
        """Создаёт Event Definition (Graylog 7.x: тело обязано быть обёрнуто в entity).

        aggregation (из корреляционного правила Sigma): группировка, функция и порог.
        """
        agg = aggregation_config(aggregation)
        if agg:
            search_within_ms = agg["search_within_ms"]
            execute_every_ms = agg["execute_every_ms"]
        config = {
            "type": "aggregation-v1",
            "query": query,
            "query_parameters": [],
            "filters": [],
            "streams": stream_ids or [],
            "stream_categories": [],
            # без агрегации серия не задана — детект срабатывает на каждое совпадение
            "group_by": agg["group_by"] if agg else [],
            "series": agg["series"] if agg else [],
            "conditions": agg["conditions"] if agg else {"expression": None},
            "search_within_ms": int(search_within_ms),
            "execute_every_ms": int(execute_every_ms),
            "use_cron_scheduling": False,
            "cron_expression": None,
            "cron_timezone": None,
            "event_limit": 100,
        }
        entity = {
            "title": title,
            "description": attack_description(description, attack),
            "priority": int(priority),
            "alert": False,
            "config": config,
            # поля mitre_tactic / mitre_technique / mitre_techniques из тегов attack.* правила
            "field_spec": attack_field_spec(attack),
            "key_spec": list(agg["group_by"]) if agg else [],
            "notification_settings": {"grace_period_ms": 0, "backlog_size": 5},
            "notifications": [],
            "storage": [],
            "tags": [],
        }
        created = self._post("/api/events/definitions", {"entity": entity})
        return {"id": created.get("id"), "title": created.get("title")}

    def delete_event_definition(self, definition_id: str) -> None:
        r = self._client.delete(f"/api/events/definitions/{definition_id}")
        if r.status_code >= 400:
            raise GraylogError(f"DELETE -> {r.status_code}: {r.text[:200]}")

    def list_event_definitions(self, per_page: int = 1) -> dict:
        d = self._get("/api/events/definitions", page=1, per_page=per_page)
        return {"total": d.get("total")}

    # --- определения как объекты -------------------------------------------
    @staticmethod
    def _slim_definition(entry: dict) -> dict:
        config = entry.get("config") or {}
        return {
            "id": entry.get("id"),
            "title": entry.get("title") or "(без названия)",
            "description": entry.get("description") or "",
            "priority": entry.get("priority"),
            "alert": bool(entry.get("alert")),
            "matched_at": entry.get("matched_at"),
            "updated_at": entry.get("updated_at"),
            "query": (config.get("query") or "").strip(),
            "streams": config.get("streams") or [],
            "execute_every_ms": config.get("execute_every_ms"),
            "search_within_ms": config.get("search_within_ms"),
            "scope": entry.get("_scope"),
        }

    def definitions(self, query: str | None = None, page: int = 1,
                    per_page: int = 50) -> dict:
        params: dict = {"page": page, "per_page": per_page}
        if query:
            params["query"] = query
        data = self._get("/api/events/definitions", **params)
        items = [self._slim_definition(e) for e in data.get("event_definitions", [])]
        return {"total": data.get("total", len(items)), "page": page,
                "per_page": per_page, "items": items}

    def all_definitions(self, max_items: int = 600) -> list[dict]:
        """Все определения (для поиска дубликатов), с ограничением."""
        out: list[dict] = []
        page = 1
        while len(out) < max_items:
            chunk = self.definitions(page=page, per_page=100)
            items = chunk["items"]
            if not items:
                break
            out.extend(items)
            if len(out) >= chunk["total"]:
                break
            page += 1
        return out[:max_items]

    def attack_definitions(self, max_items: int = 1000) -> list[dict]:
        """Все определения с техниками ATT&CK из полей mitre_* (для карты покрытия)."""
        out: list[dict] = []
        page = 1
        while len(out) < max_items:
            data = self._get("/api/events/definitions", page=page, per_page=100)
            chunk = data.get("event_definitions", [])
            if not chunk:
                break
            for e in chunk:
                ids, primary = attack_definition_techniques(e.get("field_spec"))
                out.append({"id": e.get("id"), "title": e.get("title") or "(без названия)",
                            "state": e.get("state"), "techniques": ids, "primary": primary})
            if len(out) >= data.get("total", len(out)):
                break
            page += 1
        return out[:max_items]

    def definition(self, definition_id: str) -> dict:
        raw = self._get(f"/api/events/definitions/{definition_id}")
        return self._slim_definition(raw)
