"""sigma2graylog — конвертер Sigma-правил в детекты Graylog с проверкой по реальным полям индексов."""
from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path

from fastapi import (Depends, FastAPI, File, HTTPException, Query, Request,
                     Response, UploadFile)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import convert as converter
from . import detections as detections_mod
from . import demo as demo_mod
from . import loader, samples, sources as sources_mod
from . import mapping as mapping_mod
from .i18n import lang_of
from .settings import SettingsStore
from .auth import (COOKIE_NAME, MIN_PASSWORD_LEN, SESSION_TTL, Sessions,
                   Throttle, UserStore)
from .graylog import Graylog, GraylogError
from .mapping import FieldIndex, build_mapping

LOG = logging.getLogger("sigma2graylog")
logging.basicConfig(level=logging.INFO)

ENV_GRAYLOG_URL = os.getenv("GRAYLOG_URL", "http://127.0.0.1:9000")
ENV_GRAYLOG_USER = os.getenv("GRAYLOG_USER") or ""
ENV_GRAYLOG_PASSWORD = os.getenv("GRAYLOG_PASSWORD") or ""
ENV_GRAYLOG_TOKEN = os.getenv("GRAYLOG_TOKEN") or ""
ENV_GRAYLOG_PUBLIC_URL = os.getenv("GRAYLOG_PUBLIC_URL", "").rstrip("/")
ENV_FIELDS_TTL = int(os.getenv("FIELDS_TTL", "600"))
DEMO_MODE = os.getenv("DEMO_MODE", "").strip().lower() in ("1", "true", "yes", "on")
APP_USER = os.getenv("APP_USER", "sigma")
APP_PASSWORD = os.getenv("APP_PASSWORD", "")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
OVERRIDES_FILE = DATA_DIR / "overrides.json"
STREAM_OVERRIDES_FILE = DATA_DIR / "stream_overrides.json"
SOURCES_DIR = DATA_DIR / "sources"
USERS_FILE = DATA_DIR / "users.json"
SECRET_FILE = DATA_DIR / "secret.key"
SETTINGS_FILE = DATA_DIR / "settings.json"

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="sigma2graylog", docs_url=None, redoc_url=None)

MEDIA_DIR = STATIC / "media"
app.mount("/static", StaticFiles(directory=MEDIA_DIR), name="static")
app.mount("/js", StaticFiles(directory=STATIC / "js"), name="js")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(MEDIA_DIR / "favicon.ico", media_type="image/x-icon")

users = UserStore(USERS_FILE)
sessions = Sessions(SECRET_FILE)
settings = SettingsStore(SETTINGS_FILE, SECRET_FILE)
definitions_cache = detections_mod.DefinitionCache(ttl=120)
throttle = Throttle()
if not DEMO_MODE and users.bootstrap(APP_USER, APP_PASSWORD):
    LOG.info("создан пользователь %s из переменных окружения", APP_USER)


def _cookie(request: Request) -> str | None:
    return request.cookies.get(COOKIE_NAME)


def current_user(request: Request) -> str:
    """Зависимость для API: возвращает имя пользователя или 401."""
    if DEMO_MODE:
        return "demo"
    token = _cookie(request)
    user = sessions.verify(token, users) if token else None
    if not user:
        raise HTTPException(status_code=401, detail="Требуется вход")
    return user


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


class FieldCache:
    def __init__(self):
        self.names: list[dict] = []
        self.index: FieldIndex | None = None
        self.loaded_at: float = 0.0
        self.system: dict = {}

    def ensure(self, client: Graylog, force: bool = False, ttl: int | None = None):
        ttl = ENV_FIELDS_TTL if ttl is None else ttl
        if force or not self.names or (time.time() - self.loaded_at) > ttl:
            self.names = client.fields()
            self.index = FieldIndex(self.names)
            self.loaded_at = time.time()
        return self.index


cache = FieldCache()


stream_index_cache: dict[str, FieldIndex] = {}


class StreamRegistry:
    """Профили стримов: какие поля реально встречаются в событиях и какой это продукт."""

    def __init__(self, ttl: int = 600):
        self.ttl = ttl
        self.profiles: dict[str, dict] = {}
        self.loaded_at = 0.0
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self.profiles = {}
            self.loaded_at = 0.0
            stream_index_cache.clear()

    def ensure(self, g: Graylog, streams: list[dict], force: bool = False) -> dict[str, dict]:
        if not force and self.profiles and (time.time() - self.loaded_at) < self.ttl:
            return self.profiles
        with self._lock:
            if not force and self.profiles and (time.time() - self.loaded_at) < self.ttl:
                return self.profiles
            from concurrent.futures import ThreadPoolExecutor

            def probe(stream: dict) -> tuple[str, dict]:
                try:
                    data = g.stream_fields(stream["id"], limit=100, days=7)
                except Exception:  # noqa: BLE001 - стрим может быть пустым/недоступным
                    data = {"fields": [], "sampled": 0, "total_in_stream": 0}
                names = [f["name"] for f in data.get("fields", [])]
                return stream["id"], {
                    "id": stream["id"],
                    "title": stream.get("title"),
                    "product": mapping_mod.detect_product(names),
                    "fields": data.get("fields", []),
                    "sampled": data.get("sampled", 0),
                    "total": data.get("total_in_stream") or 0,
                }

            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(probe, streams))
            self.profiles = dict(results)
            self.loaded_at = time.time()
            return self.profiles

    def for_product(self, product: str | None) -> dict | None:
        if not product:
            return None
        candidates = [p for p in self.profiles.values()
                      if p.get("product") == product.lower() and p.get("fields")]
        return max(candidates, key=lambda p: p.get("total", 0)) if candidates else None

    def by_id(self, stream_id: str | None) -> dict | None:
        return self.profiles.get(stream_id) if stream_id else None


stream_registry = StreamRegistry()
source_cache = sources_mod.SourceCache(SOURCES_DIR)


def effective_config() -> dict:
    """Настройки из UI поверх переменных окружения."""
    st = settings.get()
    url = (st.get("graylog_url") or ENV_GRAYLOG_URL).rstrip("/")
    public = (st.get("graylog_public_url") or ENV_GRAYLOG_PUBLIC_URL or url).rstrip("/")
    mode = st.get("auth_mode") or ("token" if ENV_GRAYLOG_TOKEN else "basic")
    token = st.get("graylog_token") or (ENV_GRAYLOG_TOKEN if mode == "token" else "")
    user = st.get("graylog_user") or ENV_GRAYLOG_USER
    password = st.get("graylog_password") or ENV_GRAYLOG_PASSWORD
    if mode != "token":
        token = ""
    return {
        "url": url,
        "public_url": public,
        "auth_mode": mode,
        "user": user,
        "password": password,
        "token": token,
        "fields_ttl": int(st.get("fields_ttl") or ENV_FIELDS_TTL),
        "default_stream_id": st.get("default_stream_id") or "",
        "default_range": int(st.get("default_range") or 86400),
        "check_duplicates": bool(st.get("check_duplicates", True)),
        "case_insensitive_regex": bool(st.get("case_insensitive_regex", True)),
    }


def client(cfg: dict | None = None) -> Graylog:
    if DEMO_MODE:
        return demo_mod.FakeGraylog()
    cfg = cfg or effective_config()
    if cfg["auth_mode"] == "token" and cfg["token"]:
        return Graylog(cfg["url"], token=cfg["token"])
    return Graylog(cfg["url"], cfg["user"], cfg["password"])


def load_overrides() -> dict[str, str]:
    try:
        return json.loads(OVERRIDES_FILE.read_text("utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def load_stream_overrides() -> dict[str, dict[str, str]]:
    try:
        return json.loads(STREAM_OVERRIDES_FILE.read_text("utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def save_stream_overrides(data: dict) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STREAM_OVERRIDES_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
        tmp.replace(STREAM_OVERRIDES_FILE)
    except OSError as exc:
        LOG.warning("не смог сохранить stream_overrides: %s", exc)


def stream_index(profile: dict) -> FieldIndex:
    """FieldIndex по реальным полям стрима, с учётом их распространённости."""
    cached = stream_index_cache.get(profile["id"])
    if cached is not None:
        return cached
    sampled = max(profile.get("sampled") or 1, 1)
    index = FieldIndex([
        {"name": f["name"], "type": None, "coverage": (f.get("count") or 0) / sampled}
        for f in profile.get("fields") or []
    ])
    stream_index_cache[profile["id"]] = index
    return index


def save_overrides(data: dict[str, str]) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = OVERRIDES_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
        tmp.replace(OVERRIDES_FILE)
    except OSError as exc:
        LOG.warning("не смог сохранить overrides: %s", exc)


class ConvertRequest(BaseModel):
    sigma: str = Field(min_length=3, max_length=8_000_000)
    overrides: dict[str, str] = Field(default_factory=dict)
    use_saved_overrides: bool = True
    stream_id: str | None = None
    probe: bool = False
    probe_range_seconds: int = 86400
    check_duplicates: bool | None = None


class SettingsPatch(BaseModel):
    graylog_url: str | None = None
    graylog_public_url: str | None = None
    auth_mode: str | None = None
    graylog_user: str | None = None
    graylog_password: str | None = None
    graylog_token: str | None = None
    fields_ttl: int | None = None
    default_stream_id: str | None = None
    default_range: int | None = None
    check_duplicates: bool | None = None
    case_insensitive_regex: bool | None = None


class SettingsTest(BaseModel):
    graylog_url: str | None = None
    auth_mode: str | None = None
    graylog_user: str | None = None
    graylog_password: str | None = None
    graylog_token: str | None = None


class BulkItem(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    query: str = Field(min_length=1)
    description: str = ""
    priority: int = 2
    stream_id: str | None = None


class BulkRequest(BaseModel):
    items: list[BulkItem] = Field(min_length=1)
    confirm: bool = False
    dry_run: bool = False
    skip_duplicates: bool = True


class SimilarRequest(BaseModel):
    query: str = Field(min_length=1)
    title: str = ""


class ProbeRequest(BaseModel):
    query: str = Field(min_length=1)
    range_seconds: int = 86400
    stream_id: str | None = None


class EventDefinitionRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    query: str = Field(min_length=1)
    description: str = ""
    priority: int = 2
    stream_id: str | None = None
    confirm: bool = False


@app.get("/api/status", dependencies=[Depends(current_user)])
def status(refresh: bool = False):
    cfg = effective_config()
    try:
        g = client(cfg)
        try:
            system = g.system()
            index = cache.ensure(g, force=refresh, ttl=cfg["fields_ttl"])
        finally:
            g.close()
    except GraylogError as exc:
        return JSONResponse(status_code=502, content={
            "ok": False, "error": str(exc), "graylog_url": cfg["url"],
        })
    return {
        "ok": True,
        "demo": DEMO_MODE,
        "graylog_url": cfg["url"],
        "graylog_public_url": cfg["public_url"],
        "graylog": system,
        "fields": len(index.names),
        "fields_loaded_at": int(cache.loaded_at),
        "auth_mode": cfg["auth_mode"],
        "auth_enabled": bool(APP_PASSWORD),
        "default_stream_id": cfg["default_stream_id"],
        "default_range": cfg["default_range"],
        "check_duplicates": cfg["check_duplicates"],
        "case_insensitive_regex": cfg["case_insensitive_regex"],
    }


@app.get("/api/fields", dependencies=[Depends(current_user)])
def fields(q: str = "", limit: int = Query(default=200, le=2000)):
    cfg = effective_config()
    g = client(cfg)
    try:
        cache.ensure(g, ttl=cfg["fields_ttl"])
        names = cache.names
    finally:
        g.close()
    if q:
        ql = q.lower()
        names = [f for f in names if ql in f["name"].lower()]
    return {"total": len(names), "fields": names[:limit]}


@app.post("/api/fields/refresh", dependencies=[Depends(current_user)])
def refresh_fields():
    cfg = effective_config()
    g = client(cfg)
    try:
        index = cache.ensure(g, force=True, ttl=cfg["fields_ttl"])
    finally:
        g.close()
    return {"ok": True, "fields": len(index.names), "loaded_at": int(cache.loaded_at)}


@app.get("/api/streams", dependencies=[Depends(current_user)])
def streams(profiles: bool = False):
    cfg = effective_config()
    g = client(cfg)
    try:
        items = g.streams()
        if profiles:
            registry = stream_registry.ensure(g, items)
            for item in items:
                prof = registry.get(item["id"]) or {}
                item["product"] = prof.get("product")
                item["fields"] = len(prof.get("fields") or [])
                item["events"] = prof.get("total")
        return {"streams": items}
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()


@app.post("/api/convert", dependencies=[Depends(current_user)])
def convert(req: ConvertRequest, request: Request):
    cfg = effective_config()
    g = client(cfg)
    try:
        global_index = cache.ensure(g, ttl=cfg["fields_ttl"])
        try:
            profiles = stream_registry.ensure(g, g.streams())
        except GraylogError:
            profiles = {}
        overrides = load_overrides() if req.use_saved_overrides else {}
        overrides.update({k: v for k, v in req.overrides.items() if v})

        def resolve(product: str | None):
            """Стрим и набор полей: по продукту правила либо явно выбранный."""
            profile = None
            if req.stream_id:
                profile = stream_registry.by_id(req.stream_id)
            else:
                profile = stream_registry.for_product(product)
            if not profile or not profile.get("fields"):
                return global_index, None
            return stream_index(profile), {
                "id": profile["id"], "title": profile.get("title"),
                "product": profile.get("product"), "fields": len(profile["fields"]),
            }

        stream_overrides = load_stream_overrides()

        def mapping_for(product, fields, ovr):
            index, stream = resolve(product)
            merged = dict(ovr)
            if stream:
                merged.update(stream_overrides.get(stream["id"], {}))
            result = build_mapping(fields, index, product, merged)
            result["__meta__"]["stream"] = stream
            if product and not stream:
                result["__meta__"]["no_stream_for_product"] = True
            return result

        result = converter.convert(req.sigma, mapping_for, overrides,
                                   case_insensitive=cfg["case_insensitive_regex"],
                                   lang=request_lang(request))
        want_dupes = req.check_duplicates
        if want_dupes is None:
            want_dupes = cfg["check_duplicates"]
        if want_dupes and result["rules"]:
            try:
                defs = definitions_cache.get(lambda: g.all_definitions())
                for rule in result["rules"]:
                    query = rule["queries"][0] if rule["queries"] else ""
                    rule["similar"] = detections_mod.find_duplicates(
                        query, rule["title"], defs) if query else []
            except GraylogError:
                for rule in result["rules"]:
                    rule["similar"] = []
        if req.probe and result["rules"]:
            probes = []
            for rule in result["rules"]:
                for q in rule["queries"]:
                    try:
                        cnt = g.count(q, req.probe_range_seconds, req.stream_id)
                        probes.append({"rule_index": rule["index"], "query": q, **cnt})
                    except GraylogError as exc:
                        probes.append({"rule_index": rule["index"], "query": q,
                                       "errors": [str(exc)]})
            result["probes"] = probes
    except converter.ConversionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()
    return result


@app.post("/api/probe", dependencies=[Depends(current_user)])
def probe(req: ProbeRequest):
    g = client()
    try:
        return g.count(req.query, req.range_seconds, req.stream_id)
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()


@app.post("/api/overrides", dependencies=[Depends(current_user)])
def set_overrides(payload: dict[str, str]):
    current = load_overrides()
    for k, v in payload.items():
        if v:
            current[k] = v
        else:
            current.pop(k, None)
    save_overrides(current)
    return {"ok": True, "overrides": current}


@app.post("/api/event-definition", dependencies=[Depends(current_user)])
def event_definition(req: EventDefinitionRequest):
    if not req.confirm:
        raise HTTPException(status_code=400,
                            detail="Нужно подтверждение: передайте confirm=true")
    g = client()
    try:
        created = g.create_event_definition(
            title=req.title,
            query=req.query,
            description=req.description,
            priority=req.priority,
            stream_ids=[req.stream_id] if req.stream_id else [],
        )
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()
    definitions_cache.invalidate()
    base = effective_config()["public_url"]
    return {"ok": True, **created,
            "url": f"{base}/events/definitions/{created.get('id')}"}


@app.get("/api/event-definitions/count", dependencies=[Depends(current_user)])
def event_definitions_count():
    g = client()
    try:
        return g.list_event_definitions(per_page=1)
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordRequest(BaseModel):
    current: str = Field(min_length=1, max_length=256)
    new: str = Field(min_length=1, max_length=256)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if DEMO_MODE or sessions.verify(_cookie(request) or "", users):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse((STATIC / "login.html").read_text("utf-8"), headers=NO_CACHE)


@app.post("/login")
def login(req: LoginRequest, request: Request, response: Response):
    ip = _client_ip(request)
    if throttle.blocked(ip):
        raise HTTPException(status_code=429,
                            detail="Слишком много попыток входа. Подождите несколько минут.")
    if not users.verify(req.username, req.password):
        throttle.fail(ip)
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    throttle.reset(ip)
    token = sessions.issue(req.username, users.version(req.username))
    response.set_cookie(
        COOKIE_NAME, token,
        max_age=SESSION_TTL, httponly=True, samesite="lax", path="/",
    )
    return {"ok": True, "user": req.username}


@app.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


class UrlRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


@app.get("/api/samples/random", dependencies=[Depends(current_user)])
def sample(exclude: str = ""):
    """Случайное правило из встроенной коллекции."""
    exclude_titles = [t for t in exclude.split("|") if t.strip()] if exclude else []
    return samples.random_sample(exclude_titles)


@app.get("/api/samples", dependencies=[Depends(current_user)])
def sample_list():
    return {
        "total": len(samples.SAMPLES),
        "items": [
            {"title": samples._title(s), "source": s["source"]}
            for s in samples.SAMPLES
        ],
    }


@app.get("/api/streams/{stream_id}/analysis", dependencies=[Depends(current_user)])
def stream_analysis(stream_id: str, refresh: bool = False):
    """Что за стрим, какие в нём поля и насколько они покрывают типовые поля Sigma."""
    cfg = effective_config()
    g = client(cfg)
    try:
        items = g.streams()
        registry = stream_registry.ensure(g, items, force=refresh)
        profile = registry.get(stream_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Стрим не найден")
        if not profile.get("fields"):
            raise HTTPException(status_code=409, detail="В стриме нет событий — анализировать нечего")
        index = stream_index(profile)
        coverage = mapping_mod.analyze_stream(index, profile.get("product"))
        saved = load_stream_overrides().get(stream_id, {})
        for row in coverage:
            if row["sigma_field"] in saved:
                row["graylog_field"] = saved[row["sigma_field"]]
                row["accepted"] = True
                row["source"] = "manual"
        covered = sum(1 for r in coverage if r["accepted"])
        sampled = max(profile.get("sampled") or 1, 1)
        fields = [
            {"name": f["name"], "count": f.get("count", 0),
             "coverage": round(100 * (f.get("count") or 0) / sampled, 1)}
            for f in profile.get("fields") or []
        ]
        return {
            "stream": {"id": profile["id"], "title": profile.get("title"),
                       "product": profile.get("product"), "events": profile.get("total")},
            "sampled": profile.get("sampled"),
            "fields": fields,
            "coverage": coverage,
            "covered": covered,
            "total_checked": len(coverage),
            "overrides": saved,
        }
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()


@app.post("/api/streams/{stream_id}/overrides", dependencies=[Depends(current_user)])
def set_stream_overrides(stream_id: str, payload: dict[str, str]):
    data = load_stream_overrides()
    current = data.get(stream_id, {})
    for key, value in payload.items():
        if value:
            current[key] = value
        else:
            current.pop(key, None)
    if current:
        data[stream_id] = current
    else:
        data.pop(stream_id, None)
    save_stream_overrides(data)
    return {"ok": True, "overrides": current}


class SourceFetch(BaseModel):
    product: str | None = None
    category: str | None = None
    level: str | None = None
    query: str | None = None
    limit: int = 50
    refresh: bool = False


@app.get("/api/sources", dependencies=[Depends(current_user)])
def list_sources():
    info = source_cache.info()
    return {
        "sources": [
            {**{k: v for k, v in src.items() if k != "url"},
             "cached": info.get(src["id"], {})}
            for src in sources_mod.SOURCES
        ]
    }


@app.post("/api/sources/{source_id}/fetch", dependencies=[Depends(current_user)])
def fetch_source(source_id: str, req: SourceFetch):
    """Скачивает известный набор правил и отдаёт выборку по фильтрам."""
    source = next((s for s in sources_mod.SOURCES if s["id"] == source_id), None)
    if not source:
        raise HTTPException(status_code=404, detail="Источник не найден")
    cached = None if req.refresh else source_cache.fresh(source_id)
    if cached:
        rules = cached.get("rules") or []
    else:
        try:
            rules = sources_mod.build_rules(source)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - сеть/архив
            raise HTTPException(status_code=502, detail=f"Не удалось скачать: {exc}") from exc
        source_cache.save(source_id, {"fetched_at": time.time(), "rules": rules})
    total = len(rules)
    picked = sources_mod.filter_rules(rules, req.product, req.category,
                                      req.level, req.query, req.limit)
    if not picked:
        raise HTTPException(status_code=404,
                            detail="Под указанные фильтры правил не нашлось")
    facets = {
        "products": sorted({r["product"] for r in rules if r.get("product")}),
        "levels": sorted({r["level"] for r in rules if r.get("level")}),
    }
    return {
        "source": {"id": source["id"], "name": source["name"], "homepage": source["homepage"]},
        "sigma": "\n---\n".join(r["text"] for r in picked),
        "rule_count": len(picked),
        "total_available": total,
        "matched": sum(1 for r in rules
                       if (not req.product or r.get("product") == req.product.lower())
                       and (not req.category or r.get("category") == req.category.lower())
                       and (not req.level or r.get("level") in
                            {x.strip().lower() for x in req.level.split(",") if x.strip()})),
        "titles": [r["title"] for r in picked[:30]],
        "facets": facets,
        "cached": bool(cached),
    }


@app.post("/api/load/files", dependencies=[Depends(current_user)])
async def load_files(files: list[UploadFile] = File(...)):
    """Загрузка набора правил: yaml-файлы, zip или tar.gz."""
    from .loader import from_upload

    if len(files) > 3000:
        raise HTTPException(status_code=400,
                            detail="Слишком много файлов за раз (макс. 3000). "
                                   "Загрузите архивом или выберите один каталог правил")
    merged: dict = {"sigma": "", "rule_count": 0, "file_count": 0,
                    "files": [], "skipped": [], "errors": [], "truncated": False}
    chunks: list[str] = []
    for upload in files:
        data = await upload.read()
        try:
            part = from_upload(upload.filename or "rules.yaml", data)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"{upload.filename}: {exc}") from exc
        if part["rule_count"]:
            chunks.append(part["sigma"])
        for key in ("files", "skipped", "errors"):
            merged[key].extend(part[key])
        merged["rule_count"] += part["rule_count"]
        merged["truncated"] = merged["truncated"] or part["truncated"]
    merged["sigma"] = "\n---\n".join(c for c in chunks if c)
    merged["file_count"] = len(merged["files"])
    if not merged["rule_count"]:
        raise HTTPException(status_code=400,
                            detail="В загруженных файлах не найдено ни одного Sigma-правила")
    return merged


@app.post("/api/load/url", dependencies=[Depends(current_user)])
def load_url(req: UrlRequest):
    """Загрузка правил по ссылке: одиночный YAML, zip или tar.gz."""
    try:
        return loader.from_url(req.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------- настройки
@app.get("/api/settings", dependencies=[Depends(current_user)])
def get_settings():
    cfg = effective_config()
    return {
        "settings": settings.masked(),
        "effective": {k: v for k, v in cfg.items() if k not in ("password", "token")},
        "env": {
            "GRAYLOG_URL": ENV_GRAYLOG_URL,
            "GRAYLOG_PUBLIC_URL": ENV_GRAYLOG_PUBLIC_URL,
            "FIELDS_TTL": ENV_FIELDS_TTL,
            "has_env_password": bool(ENV_GRAYLOG_PASSWORD),
            "has_env_token": bool(ENV_GRAYLOG_TOKEN),
        },
    }


@app.put("/api/settings", dependencies=[Depends(current_user)])
def update_settings(patch: SettingsPatch):
    data = {k: v for k, v in patch.model_dump().items() if v is not None}
    if "auth_mode" in data and data["auth_mode"] not in ("basic", "token"):
        raise HTTPException(status_code=400, detail="auth_mode: basic или token")
    for url_key in ("graylog_url", "graylog_public_url"):
        if url_key in data and data[url_key] and not data[url_key].startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail=f"{url_key} должен начинаться с http:// или https://")
    settings.update(data)
    # конфиг мог измениться — сбрасываем кэши
    cache.names = []
    cache.index = None
    cache.loaded_at = 0.0
    definitions_cache.invalidate()
    return {"ok": True, "settings": settings.masked()}


@app.post("/api/settings/test", dependencies=[Depends(current_user)])
def test_settings(req: SettingsTest):
    """Проверка соединения — можно до сохранения, передав поля явно."""
    merged = dict(effective_config())
    if req.graylog_url:
        merged["url"] = req.graylog_url.rstrip("/")
    if req.auth_mode:
        merged["auth_mode"] = req.auth_mode
    if req.graylog_user:
        merged["user"] = req.graylog_user
    if req.graylog_password:
        merged["password"] = req.graylog_password
    if req.graylog_token:
        merged["token"] = req.graylog_token
    try:
        g = client(merged)
        try:
            system = g.system()
            fields = g.fields()
        finally:
            g.close()
    except Exception as exc:  # noqa: BLE001 - текст ошибки показываем пользователю
        return {"ok": False, "error": str(exc)[:300], "url": merged["url"]}
    return {
        "ok": True,
        "url": merged["url"],
        "version": system.get("version"),
        "is_leader": system.get("is_leader"),
        "fields": len(fields),
    }


# ---------------------------------------------------------------- детекты
@app.get("/api/detections", dependencies=[Depends(current_user)])
def list_detections(query: str = "", page: int = 1, per_page: int = 50,
                    filter: str = "all", refresh: bool = False):
    cfg = effective_config()
    g = client(cfg)
    try:
        if filter in ("never", "matched") and not query:
            data = g.definitions(page=1, per_page=500)
            items = data["items"]
            if filter == "never":
                items = [i for i in items if not i.get("matched_at")]
            else:
                items = [i for i in items if i.get("matched_at")]
            total = len(items)
            start = (page - 1) * per_page
            items = items[start:start + per_page]
        else:
            data = g.definitions(query=query or None, page=page, per_page=per_page)
            items, total = data["items"], data["total"]
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()
    stats = {
        "total": total,
        "never_matched": sum(1 for i in items if not i.get("matched_at")),
        "with_alerts": sum(1 for i in items if i.get("alert")),
    }
    return {"total": total, "page": page, "per_page": per_page,
            "items": items, "stats": stats}


@app.post("/api/event-definitions/bulk", dependencies=[Depends(current_user)])
def bulk_create(req: BulkRequest):
    """Массовое создание детектов: с проверкой дублей, предпросмотром и отчётом по каждому."""
    if len(req.items) > 50:
        raise HTTPException(status_code=400, detail="За один раз не больше 50 детектов")
    if not req.confirm and not req.dry_run:
        raise HTTPException(status_code=400, detail="Нужно подтверждение: confirm=true (или dry_run=true)")

    cfg = effective_config()
    g = client(cfg)
    results: list[dict] = []
    try:
        existing = definitions_cache.get(lambda: g.all_definitions())
        for item in req.items:
            row = {"title": item.title, "ok": False, "status": "pending"}
            dupes = detections_mod.find_duplicates(item.query, item.title, existing,
                                                   threshold=0.8, limit=1)
            if dupes:
                row["duplicate"] = dupes[0]["title"]
                row["score"] = dupes[0]["score"]
                if req.skip_duplicates:
                    row["status"] = "skipped"
                    row["reason"] = f"уже есть похожий: «{dupes[0]['title']}» ({int(dupes[0]['score']*100)}%)"
                    results.append(row)
                    continue
            if req.dry_run:
                row["status"] = "ready"
                row["ok"] = True
                results.append(row)
                continue
            try:
                created = g.create_event_definition(
                    title=item.title, query=item.query, description=item.description,
                    priority=item.priority,
                    stream_ids=[item.stream_id] if item.stream_id else [],
                )
                row.update({"ok": True, "status": "created", "id": created.get("id")})
            except GraylogError as exc:
                row.update({"status": "failed", "error": str(exc)[:200]})
            results.append(row)
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()

    if not req.dry_run:
        definitions_cache.invalidate()
    summary = {
        "total": len(results),
        "created": sum(1 for r in results if r["status"] == "created"),
        "ready": sum(1 for r in results if r["status"] == "ready"),
        "skipped": sum(1 for r in results if r["status"] == "skipped"),
        "failed": sum(1 for r in results if r["status"] == "failed"),
    }
    base = cfg["public_url"]
    for row in results:
        if row.get("id"):
            row["url"] = f"{base}/events/definitions/{row['id']}"
    return {"summary": summary, "results": results, "dry_run": req.dry_run}


@app.get("/api/detections/{definition_id}", dependencies=[Depends(current_user)])
def get_detection(definition_id: str):
    g = client(effective_config())
    try:
        return g.definition(definition_id)
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()


def delete_detection(definition_id: str):
    g = client(effective_config())
    try:
        g.delete_event_definition(definition_id)
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()
    definitions_cache.invalidate()
    return {"ok": True, "deleted": definition_id}


app.add_api_route("/api/detections/{definition_id}", delete_detection, methods=["DELETE"],
                  dependencies=[Depends(current_user)])


class HistoryRequest(BaseModel):
    query: str = Field(min_length=1)
    days: int = 30
    stream_id: str | None = None
    samples: int = 3


@app.post("/api/history", dependencies=[Depends(current_user)])
def run_history(req: HistoryRequest):
    """Прогон запроса по историческим данным: срабатывания по дням и примеры событий."""
    g = client(effective_config())
    try:
        return g.history(req.query, req.days, req.stream_id, req.samples)
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()


@app.post("/api/detections/similar", dependencies=[Depends(current_user)])
def similar_detections(req: SimilarRequest):
    cfg = effective_config()
    g = client(cfg)
    try:
        defs = definitions_cache.get(lambda: g.all_definitions())
    except GraylogError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        g.close()
    return {"items": detections_mod.find_duplicates(req.query, req.title, defs)}


@app.get("/api/me", dependencies=[Depends(current_user)])
def me(request: Request, user: str = Depends(current_user)):
    return {
        "user": user,
        "password_updated_at": users.updated_at(user),
        "min_password_length": MIN_PASSWORD_LEN,
    }


@app.post("/api/password", dependencies=[Depends(current_user)])
def change_password(req: PasswordRequest, response: Response,
                    user: str = Depends(current_user)):
    if not users.verify(user, req.current):
        raise HTTPException(status_code=400, detail="Текущий пароль указан неверно")
    if req.current == req.new:
        raise HTTPException(status_code=400, detail="Новый пароль совпадает с текущим")
    try:
        users.set_password(user, req.new)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # старая сессия инвалидирована сменой версии — выдаём новую этому же клиенту
    token = sessions.issue(user, users.version(user))
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL,
                        httponly=True, samesite="lax", path="/")
    return {"ok": True, "message": "Пароль изменён"}


NO_CACHE = {"Cache-Control": "no-store, must-revalidate"}


def request_lang(request: Request) -> str:
    """Язык ответа: заголовок X-Lang от интерфейса, иначе Accept-Language, иначе русский."""
    return lang_of(request.headers.get("x-lang") or request.headers.get("accept-language"))


@app.middleware("http")
async def _demo_lang(request: Request, call_next):
    """Язык демо-данных: из заголовка X-Lang текущего запроса."""
    demo_mod.LANG.set(request_lang(request))
    return await call_next(request)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not DEMO_MODE and not sessions.verify(_cookie(request) or "", users):
        return RedirectResponse("/login", status_code=302)
    # no-store: после обновления контейнера браузер не должен показывать старый интерфейс
    return HTMLResponse((STATIC / "index.html").read_text("utf-8"), headers=NO_CACHE)


@app.get("/healthz")
def healthz():
    return {"ok": True}
