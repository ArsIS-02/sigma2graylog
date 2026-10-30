"""Демо-режим: синтетический Graylog, чтобы приложение запускалось без реального сервера.

Нужен для скриншотов и для того, чтобы любой мог пощупать инструмент:
`podman run -e DEMO_MODE=1 -p 8080:8080 sigma2graylog`.
"""
from __future__ import annotations

from contextvars import ContextVar

import hashlib
import random
from datetime import datetime, timedelta, timezone

DEMO_VERSION = "7.2.1-demo"

# --- поля: Windows (winlogbeat), Linux (auditd), macOS -------------------
_FIELDS_WINDOWS = [
    "win_image", "win_parent_image", "win_command_line", "win_user", "win_event_id",
    "winlogbeat_winlog_event_data_Image", "winlogbeat_winlog_event_data_ParentImage",
    "winlogbeat_winlog_event_data_CommandLine", "winlogbeat_winlog_event_data_User",
    "winlogbeat_winlog_event_data_TargetFilename", "winlogbeat_winlog_event_data_Hashes",
    "winlogbeat_winlog_event_data_GrantedAccess", "winlogbeat_winlog_event_data_TargetImage",
    "winlogbeat_host_hostname", "winlogbeat_host_os_platform", "winlogbeat_event_code",
    "winlogbeat_agent_name", "winlogbeat_agent_id", "winlogbeat_event_created",
    "winlogbeat_winlog_channel", "winlogbeat_winlog_provider_name",
]
_FIELDS_LINUX = [
    "audit_type", "type", "exe", "proctitle", "name", "cwd", "comm", "pid", "ppid",
    "uid", "auid", "euid", "syscall", "key", "nametype", "inode", "mode", "dev",
    "success", "terminal", "hostname", "syslog_hostname", "msg",
]
_FIELDS_MACOS = [
    "macos_processImagePath", "macos_processCommandLine", "macos_personaID",
    "macos_activityIdentifier", "macos_eventMessage", "process_path", "process_name",
    "user_name", "session_id",
]
_COMMON = ["timestamp", "source", "message", "streams", "raw_message", "level"]

# язык демо-данных берётся из контекста запроса (ставится middleware в main.py)
LANG: ContextVar[str] = ContextVar("demo_lang", default="ru")


def _t(ru: str, en: str) -> str:
    """Строка на языке текущего запроса."""
    return en if LANG.get() == "en" else ru


DEMO_STREAMS = [
    {"id": "demo-windows", "title": ("Windows — Sysmon и Security", "Windows — Sysmon and Security"),
     "product": "windows", "events": 958_431, "fields": _FIELDS_WINDOWS + _COMMON,
     "index_set_id": "demo-index-default"},
    {"id": "demo-linux", "title": ("Linux — auditd", "Linux — auditd"),
     "product": "linux", "events": 1_920_109, "fields": _FIELDS_LINUX + _COMMON,
     "index_set_id": "demo-index-linux"},
    {"id": "demo-macos", "title": ("macOS — endpoint", "macOS — endpoint"),
     "product": "macos", "events": 30_521_718, "fields": _FIELDS_MACOS + _COMMON,
     "index_set_id": "demo-index-macos"},
    {"id": "demo-proxy", "title": ("Web proxy", "Web proxy"),
     "product": None, "events": 5_390_562,
     "fields": ["cs-method", "cs-host", "cs-uri", "sc-status", "c-useragent", "source"] + _COMMON,
     "index_set_id": "demo-index-default"},
    {"id": "demo-container", "title": ("Containers", "Containers"),
     "product": None, "events": 466,
     "fields": ["CMDLINE", "COMM", "SYSTEMD_UNIT", "log_c", "source"] + _COMMON,
     "index_set_id": "demo-index-default"},
]

DEMO_DEFINITIONS = [
    (("PowerShell с закодированной командой", "PowerShell with an encoded command"), 2, "demo-windows",
     'win_image:/.*\\[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]\\.exe/ AND '
     'winlogbeat_winlog_event_data_CommandLine:/.*\\-[Ee][Nn][Cc].*/', "2026-10-27T09:14:00Z"),
    (("Mimikatz в командной строке", "Mimikatz on the command line"), 1, "demo-windows",
     'winlogbeat_winlog_event_data_CommandLine:/.*sekurlsa::logonpasswords.*/', "2026-10-26T22:03:00Z"),
    (("Загрузка через certutil", "Download via certutil"), 2, "demo-windows",
     'win_image:/.*certutil\\.exe/ AND winlogbeat_winlog_event_data_CommandLine:/.*urlcache.*/', None),
    (("Выгрузка NTDS через ntdsutil", "NTDS dump via ntdsutil"), 1, "demo-windows",
     'win_image:/.*ntdsutil\\.exe/ AND winlogbeat_winlog_event_data_CommandLine:/.*ntds.*/', None),
    (("Подозрительный rundll32", "Suspicious rundll32"), 3, "demo-windows",
     'win_image:/.*rundll32\\.exe/ AND winlogbeat_winlog_event_data_CommandLine:/.*javascript:.*/', "2026-10-24T11:41:00Z"),
    (("Изменение sudoers", "sudoers modification"), 2, "demo-linux",
     'name:(/etc/sudoers* OR /etc/sudoers.d/*)', "2026-10-25T18:20:00Z"),
    (("Обратный шелл через bash", "Reverse shell via bash"), 1, "demo-linux",
     'proctitle:/.*bash -i >& /dev/tcp/.*/', None),
    (("Запуск шелла из нестандартного каталога", "Shell started from an unusual directory"), 3, "demo-linux",
     'audit_type:EXECVE AND exe:/.*\\/tmp\\/.*/', "2026-10-23T07:55:00Z"),
    (("Подбор пароля FreeIPA", "FreeIPA password spraying"), 3, "demo-proxy",
     'application_name:freeipa_389_audit AND message:PREAUTH_FAILED', None),
    (("Обращение к редкому домену", "Request to a rare domain"), 2, "demo-proxy",
     'cs-host:/.*\\.(top|xyz)/ AND sc-status:200', "2026-10-22T13:12:00Z"),
]

DEMO_SAMPLES = [
    ("demo-windows", "Process Create: RuleName: - UtcTime: 2026-10-29 07:17:25.450 "
                     "ProcessGuid: {a1b2} Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    ("demo-linux", 'type=PATH msg=audit(1761700000.123:456): item=0 name="sudoers" '
                   'nametype=NORMAL cwd="/etc"'),
    ("demo-proxy", 'GET https://cdn.example.net/update.js 200 "Mozilla/5.0 (Windows NT 10.0)"'),
]


class FakeGraylog:
    """Тот же интерфейс, что у настоящего клиента, но на синтетических данных."""

    def __init__(self):
        self._created: list[dict] = []
        self._deleted: set[str] = set()

    # --- служебное ---------------------------------------------------------
    def close(self):  # noqa: D401 - интерфейс клиента
        return None

    def system(self) -> dict:
        return {"version": DEMO_VERSION, "codename": "Demo", "cluster_id": "demo",
                "is_leader": True}

    def fields(self) -> list[dict]:
        names = sorted({f for s in DEMO_STREAMS for f in s["fields"]})
        return [{"name": n, "type": None} for n in names]

    def _stream_title(self, stream: dict) -> str:
        title = stream.get("title")
        return _t(*title) if isinstance(title, tuple) else title

    def streams(self) -> list[dict]:
        return [
            {"id": s["id"], "title": self._stream_title(s), "description": "",
             "index_set_id": s["index_set_id"], "disabled": False}
            for s in DEMO_STREAMS
        ]

    def index_sets(self) -> list[dict]:
        return [{"id": "demo-index-default", "title": "Default", "index_prefix": "graylog"},
                {"id": "demo-index-linux", "title": "Linux", "index_prefix": "linux"}]

    def stream_fields(self, stream_id: str, limit: int = 200, days: int = 7) -> dict:
        stream = next((s for s in DEMO_STREAMS if s["id"] == stream_id), None)
        if not stream:
            return {"stream_id": stream_id, "sampled": 0, "total_in_stream": 0, "fields": []}
        sampled = 100
        fields = []
        for i, name in enumerate(stream["fields"]):
            coverage = 100 if i < 6 else max(10, 95 - i * 4)
            fields.append({"name": name, "count": int(sampled * coverage / 100)})
        return {"stream_id": stream_id, "sampled": sampled,
                "total_in_stream": stream["events"], "fields": fields}

    # --- детекты -----------------------------------------------------------
    def _definition_payload(self, title, priority, stream_id, query, matched_at) -> dict:
        ru_title = title[0] if isinstance(title, tuple) else title
        shown = _t(*title) if isinstance(title, tuple) else title
        return {
            "id": "demo-" + hashlib.sha1(ru_title.encode()).hexdigest()[:12],
            "title": shown, "description": _t("Демонстрационный детект", "Demo detection"),
            "priority": priority, "alert": False, "matched_at": matched_at,
            "updated_at": "2026-10-28T10:00:00Z", "query": query,
            "streams": [stream_id], "execute_every_ms": 60_000,
            "search_within_ms": 300_000, "scope": "DEFAULT",
        }

    def _all(self) -> list[dict]:
        items = [self._definition_payload(*row) for row in DEMO_DEFINITIONS]
        items = [i for i in items if i["id"] not in self._deleted]
        items.extend(i for i in self._created if i["id"] not in self._deleted)
        return items

    def definitions(self, query: str | None = None, page: int = 1,
                    per_page: int = 50) -> dict:
        items = self._all()
        if query:
            q = query.lower()
            items = [i for i in items if q in i["title"].lower() or q in i["description"].lower()]
        total = len(items)
        start = (page - 1) * per_page
        return {"total": total, "page": page, "per_page": per_page,
                "items": items[start:start + per_page]}

    def all_definitions(self, max_items: int = 600) -> list[dict]:
        return self._all()[:max_items]

    def definition(self, definition_id: str) -> dict:
        for item in self._all():
            if item["id"] == definition_id:
                return item
        raise RuntimeError("детект не найден")

    def create_event_definition(self, *, title: str, query: str, description: str = "",
                                priority: int = 2, stream_ids: list[str] | None = None,
                                search_within_ms: int = 300_000,
                                execute_every_ms: int = 60_000) -> dict:
        payload = self._definition_payload(title, priority,
                                           (stream_ids or ["demo-windows"])[0],
                                           query, None)
        self._created.append(payload)
        return {"id": payload["id"], "title": title}

    def delete_event_definition(self, definition_id: str) -> None:
        self._deleted.add(definition_id)

    def list_event_definitions(self, per_page: int = 1) -> dict:
        return {"total": len(self._all())}

    # --- поиск и история ----------------------------------------------------
    @staticmethod
    def _seed(query: str) -> int:
        return int(hashlib.sha1(query.encode()).hexdigest()[:8], 16)

    def count(self, query: str, range_seconds: int = 86400,
              stream_id: str | None = None) -> dict:
        base = self._seed(query)
        per_day = 0 if "ntdsutil" in query or "sudoers" in query else base % 40
        return {
            "total_results": per_day * max(1, range_seconds // 86400),
            "built_query": query,
            "errors": None,
            "effective_query": query,
        }

    def history(self, query: str, days: int = 30, stream_id: str | None = None,
                samples: int = 3) -> dict:
        rnd = random.Random(self._seed(query))
        quiet = "ntdsutil" in query or "sudoers" in query
        per_day = 0 if quiet else max(1, rnd.randint(2, 60))
        today = datetime.now(timezone.utc).date()
        buckets = []
        for i in range(min(days, 21)):
            day = today - timedelta(days=min(days, 21) - i)
            value = 0 if quiet else max(0, int(rnd.gauss(per_day, per_day * 0.4)))
            buckets.append({"date": day.isoformat(), "count": value})
        total = sum(b["count"] for b in buckets)
        avg = round(total / max(len(buckets), 1), 1)
        if total == 0:
            verdict = {"level": "warn", "text": _t("На исторических данных не срабатывает ни разу",
                                          "Never matched against historical data")}
        elif avg >= 1000:
            verdict = {"level": "error", "text": _t(f"Очень шумно: в среднем {avg:g} срабатываний в сутки",
                                           f"Very noisy: {avg:g} matches per day on average")}
        elif avg >= 100:
            verdict = {"level": "warn", "text": _t(f"Шумновато: в среднем {avg:g} срабатываний в сутки",
                                          f"Rather noisy: {avg:g} matches per day on average")}
        else:
            verdict = {"level": "ok", "text": _t(f"Умеренно: в среднем {avg:g} срабатываний в сутки",
                                        f"Moderate: {avg:g} matches per day on average")}
        picked = [{"timestamp": (today - timedelta(days=1)).isoformat() + "T08:15:00Z",
                   "source": src, "message": msg} for src, msg in DEMO_SAMPLES[:max(0, samples)]]
        return {
            "days": days, "buckets": buckets, "total": total,
            "average_per_day": avg,
            "max_per_day": max((b["count"] for b in buckets), default=0),
            "verdict": verdict, "samples": picked, "errors": [],
        }
