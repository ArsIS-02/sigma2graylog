"""Сопоставление полей Sigma с полями, реально существующими в Graylog.

Sigma-правила написаны в терминах Windows-полей (Image, CommandLine, EventID),
а в индексах Graylog поля лежат как winlogbeat_winlog_event_data_Image и т.п.
Здесь считается «похожесть» и выдаются кандидаты для ручного выбора.
"""
from __future__ import annotations

import re
from collections import Counter
from difflib import SequenceMatcher

# Префиксы, характерные для источника логов: дают бонус кандидату.
PRODUCT_PREFIXES = {
    "windows": ("winlogbeat_", "win_", "wineventlog_"),
    "linux": ("proc_", "file_", "auditd_", "unix_", "syslog_"),
    "macos": ("mac_", "macos_", "osquery_"),
    "aws": ("aws_",),
    "azure": ("azure_",),
}
DEFAULT_PREFIXES = tuple(p for prefs in PRODUCT_PREFIXES.values() for p in prefs)

MIN_ACCEPT_SCORE = 70

# Префикс поля -> продукт. Нужно, чтобы правило для linux не маппилось на winlogbeat-поля.
PREFIX_PRODUCT = {
    "winlogbeat": "windows", "win": "windows", "wineventlog": "windows",
    "proc": "linux", "file": "linux", "auditd": "linux", "unix": "linux", "syslog": "linux",
    "mac": "macos", "macos": "macos", "osquery": "macos",
    "aws": "aws", "azure": "azure",
}

# Семантические соответствия: Sigma-поле -> как оно называется в Graylog для продукта.
# Это не догадки по буквам, а знание предметной области: TargetFilename в linux-файловых
# событиях лежит в file_path, а Image в linux-процессах — в proc_exe.
SEMANTIC_HINTS: dict[str, dict[str, list[str]]] = {
    "linux": {
        # auditd: путь разбит на cwd + name, команда в proctitle, бинарь в exe
        "targetfilename": ["name", "name_decoded", "file_path", "proc_file_path"],
        "image": ["exe", "exe_decoded", "proc_exe", "process_path"],
        "commandline": ["proctitle", "proctitle_decoded", "proc_cmdline"],
        "parentcommandline": ["proc_p_cmdline"],
        "originalfilename": ["comm", "comm_decoded", "file_name"],
        "processid": ["pid", "pid_decoded"],
        "parentprocessid": ["ppid", "ppid_decoded"],
        "currentdirectory": ["cwd", "cwd_decoded"],
        "parentimage": ["proc_p_exe"],
    },
    "macos": {
        "targetfilename": ["macos_file_path", "file_path"],
        "image": ["macos_processImagePath", "process_path"],
        "commandline": ["macos_processCommandLine", "process_commandline"],
    },
    "*": {
        "eventid": ["event_code", "event_id"],
        "user": ["user", "user_name"],
        "destinationip": ["net_conn_dst", "dst_ip", "destination_ip"],
        "sourceip": ["net_conn_src", "src_ip", "source_ip"],
        "destinationport": ["net_conn_dport", "dst_port", "destination_port"],
        "sourceport": ["net_conn_sport", "src_port", "source_port"],
    },
}

# Насколько штрафуем поле из чужого продукта, чтобы оно не выбиралось автоматически.
CROSS_PRODUCT_PENALTY = 60.0
HINT_SCORE = 97.0


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def segments(s: str) -> list[str]:
    return [p for p in re.split(r"[._\-\s]+", s.lower()) if p]


def _last_name(sigma_field: str) -> str:
    """winlog.event_data.Image -> Image"""
    parts = [p for p in re.split(r"[.]", sigma_field) if p]
    return parts[-1] if parts else sigma_field


class FieldIndex:
    """Предпосчитанные структуры по списку полей Graylog."""

    def __init__(self, fields: list[dict]):
        self.names = [f["name"] for f in fields]
        self.types = {f["name"]: f.get("type") for f in fields}
        # доля событий стрима, где поле вообще присутствует (0..1)
        self.coverage = {f["name"]: float(f.get("coverage") or 0.0) for f in fields}
        self.norms = {n: norm(n) for n in self.names}
        self._cache: dict[tuple, list[dict]] = {}
        # предвычисления: по ним идёт быстрый поиск без перебора строк
        self._lower: dict[str, str] = {}
        self._by_norm: dict[str, str] = {}
        self._by_last: dict[str, list[str]] = {}
        self._rows: list[tuple[str, str, str, str]] = []
        for name in self.names:
            low = name.lower()
            normed = self.norms[name]
            segs = segments(name)
            last = segs[-1] if segs else normed
            self._lower.setdefault(low, name)
            self._by_norm.setdefault(normed, name)
            self._by_last.setdefault(last, []).append(name)
            self._rows.append((name, low, normed, last))
        prefixes = Counter()
        for n in self.names:
            head = n.split("_")[0] if "_" in n else n
            prefixes[head] += 1
        total = max(len(self.names), 1)
        # 0..3 балла в зависимости от того, насколько часто префикс встречается
        self.prefix_bonus = {
            p: min(3.0, 3.0 * cnt / total * 10) for p, cnt in prefixes.items()
        }
        # какие продукты вообще представлены в индексах
        self.products = {PREFIX_PRODUCT[p] for p in prefixes if p in PREFIX_PRODUCT}
        self._names_set = set(self.names)

    def has_product(self, product: str | None) -> bool:
        return (product or "").lower() in self.products

    @staticmethod
    def field_product(name: str) -> str | None:
        head = name.split("_")[0] if "_" in name else name
        return PREFIX_PRODUCT.get(head)

    def _hint_names(self, sigma_field: str, product: str | None) -> list[str]:
        target = _last_name(sigma_field).lower()
        names = []
        for scope in ((product or "").lower(), "*"):
            names.extend(SEMANTIC_HINTS.get(scope, {}).get(target, []))
        return [n for n in names if n in self._names_set]

    def suggest(self, sigma_field: str, product: str | None = None,
                limit: int = 6) -> list[dict]:
        key = (sigma_field, (product or "").lower(), limit)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        result = self._suggest(sigma_field, product, limit)
        self._cache[key] = result
        return result

    def _suggest(self, sigma_field: str, product: str | None = None,
                 limit: int = 6) -> list[dict]:
        target = _last_name(sigma_field)
        tl, tn, tseg = target.lower(), norm(target), segments(target)
        prefs = PRODUCT_PREFIXES.get((product or "").lower(), ())
        full = sigma_field.lower()

        scored: list[tuple[float, str]] = []
        fuzzy_budget = 150  # нечёткое сравнение — самое дорогое, ограничиваем
        for name, ln, nn, last in self._rows:
            score = 0.0

            if ln == full or ln == tl:
                score = 100.0
            elif nn == norm(full) or nn == tn:
                score = 96.0
            elif ln.endswith("_" + tl) or ln.endswith("." + tl):
                score = 92.0
            elif last == tn:
                score = 88.0
            elif nn.endswith(tn):
                score = 80.0
            elif tn and tn in nn and len(tn) >= 4:
                score = 55.0
            elif fuzzy_budget > 0 and len(tn) >= 4 and len(last) <= 2 * len(tn):
                fuzzy_budget -= 1
                ratio = SequenceMatcher(None, tn, last).ratio()
                if ratio >= 0.92:
                    score = 45.0 * ratio
            if score == 0:
                continue

            head = name.split("_")[0] if "_" in name else name
            if prefs and ln.startswith(prefs):
                score += 6.0
            score += self.prefix_bonus.get(head, 0.0)
            score += 3.0 * self.coverage.get(name, 0.0)  # чаще встречается — правдоподобнее
            score -= min(len(name) / 60.0, 2.0)  # короткие имена правдоподобнее

            # поле из чужого продукта не должно выигрывать у «своего»
            field_prod = PREFIX_PRODUCT.get(head)
            cross = bool(product and field_prod and field_prod != product.lower())
            if cross:
                score = min(score, 40.0) - CROSS_PRODUCT_PENALTY
            scored.append((score, name))

        scored.sort(key=lambda x: (-x[0], len(x[1])))
        if prefs:
            preferred = [s for s in scored if s[1].lower().startswith(prefs)]
            # если есть кандидаты с «правильным» префиксом — остальные только как запасные
            if preferred:
                scored = preferred + [s for s in scored if s not in preferred]

        hints = self._hint_names(sigma_field, product)
        if hints:
            boosted = []
            for name in hints:
                base = next((sc for sc, nm in scored if nm == name), 0.0)
                boosted.append((HINT_SCORE if base < HINT_SCORE else base, name))
            # подсказки — в начало, остальные следом
            hint_set = set(hints)
            scored = boosted + [item for item in scored if item[1] not in hint_set]

        out, seen = [], set()
        for score, name in scored:
            if name in seen:
                continue
            seen.add(name)
            head = name.split("_")[0] if "_" in name else name
            field_prod = PREFIX_PRODUCT.get(head)
            out.append({
                "name": name,
                "type": self.types.get(name),
                "score": round(min(max(score, 0.0), 100.0), 1),
                "accepted": score >= MIN_ACCEPT_SCORE,
                "product": field_prod,
                "cross_product": bool(product and field_prod and field_prod != product.lower()),
            })
            if len(out) >= limit:
                break
        return out


def detect_product(field_names: list[str]) -> str | None:
    """Определяет продукт стрима по «подписи» его полей (по большинству признаков)."""
    scores = {"windows": 0, "linux": 0, "macos": 0}
    for name in field_names:
        low = name.lower()
        if low.startswith("winlogbeat_"):
            scores["windows"] += 3
        elif low in ("eventid", "winlog_event_data"):
            scores["windows"] += 2
        elif low.startswith(("macos_", "mac_")):
            scores["macos"] += 3
        elif low in ("audit_type", "proctitle", "syslog_hostname"):
            scores["linux"] += 3
        elif low.startswith(("auditd_",)):
            scores["linux"] += 2
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] >= 3 else None


def build_mapping(sigma_fields: list[str], index: FieldIndex, product: str | None,
                  overrides: dict[str, str] | None = None) -> dict:
    """Возвращает {sigma_field: {graylog_field, confidence, candidates, accepted}}."""
    overrides = overrides or {}
    result = {}
    for field in sorted(set(sigma_fields)):
        if field in overrides and overrides[field]:
            result[field] = {
                "sigma_field": field,
                "graylog_field": overrides[field],
                "confidence": 100.0,
                "accepted": True,
                "source": "manual",
                "ambiguous": False,
                "candidates": index.suggest(field, product),
            }
            continue
        candidates = index.suggest(field, product)
        best = candidates[0] if candidates else None
        ambiguous = bool(len(candidates) > 1 and best
                         and (best["score"] - candidates[1]["score"]) < 6
                         and best["score"] < 96)
        result[field] = {
            "sigma_field": field,
            "graylog_field": best["name"] if best and best["accepted"] else None,
            "confidence": best["score"] if best else 0.0,
            "accepted": bool(best and best["accepted"]),
            "source": "auto",
            "ambiguous": ambiguous,
            "candidates": candidates,
        }
    result["__meta__"] = {
        "product": product,
        "product_present": index.has_product(product),
        "products_available": sorted(index.products),
    }
    return result


# Частые поля Sigma по продуктам — по ним считается «покрытие» стрима.
COMMON_SIGMA_FIELDS: dict[str, list[str]] = {
    "windows": ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "User",
                "EventID", "TargetFilename", "Hashes", "DestinationIp", "DestinationPort",
                "SourceIp", "SourcePort", "ProcessId", "ParentProcessId", "CurrentDirectory"],
    "linux": ["Image", "CommandLine", "ParentCommandLine", "TargetFilename", "User",
              "ProcessId", "ParentProcessId", "CurrentDirectory", "Type", "Syscall", "Key"],
    "macos": ["Image", "CommandLine", "ParentImage", "User", "ProcessId"],
}

# Что делать, если поля нет — подсказка по существу, а не «поле не найдено».
FIELD_ADVICE: dict[str, str] = {
    "TargetFilename": "в auditd путь разбит на cwd + name — для полного пути нужен экстрактор",
    "Image": "в auditd бинарь лежит в exe; если пусто — проверьте, включён ли лог execve",
    "CommandLine": "в auditd это proctitle; включается флагом log_format в auditd.conf",
    "User": "в auditd есть числовые uid/auid — сопоставление с именем требует обогащения",
    "Hashes": "хэши не извлекаются из памяти событий — нужен расчёт по файлу",
    "ParentImage": "родительский процесс виден только при включённом proctitle/ppid",
}


def analyze_stream(index, product: str | None) -> list[dict]:
    """Покрытие типовых Sigma-полей конкретным набором полей стрима."""
    product = (product or "").lower()
    names = COMMON_SIGMA_FIELDS.get(product) or COMMON_SIGMA_FIELDS["windows"]
    rows = []
    for field in names:
        candidates = index.suggest(field, product or None, limit=4)
        best = candidates[0] if candidates else None
        accepted = bool(best and best.get("accepted"))
        rows.append({
            "sigma_field": field,
            "graylog_field": best["name"] if accepted else None,
            "score": best["score"] if best else 0.0,
            "accepted": accepted,
            "candidates": candidates,
            "advice": None if accepted else FIELD_ADVICE.get(field),
        })
    return rows
