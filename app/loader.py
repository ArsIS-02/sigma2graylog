"""Загрузка Sigma-правил: из файлов, архивов (zip/tar.gz) и по ссылке."""
from __future__ import annotations

import io
import re
import tarfile
import zipfile
from dataclasses import dataclass, field

import httpx
from sigma.collection import SigmaCollection

MAX_FILE_BYTES = 8 * 1024 * 1024        # один файл
MAX_TOTAL_BYTES = 64 * 1024 * 1024      # распакованный архив целиком
MAX_FILES = 3000                        # файлов внутри архива/папки
MAX_RULES = 300                         # правил отдаём в редактор
URL_TIMEOUT = 25.0

YAML_SUFFIXES = (".yml", ".yaml")
ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")
_SKIP_DIRS = re.compile(r"(^|/)(\.git|\.github|tests?|deprecated|unsupported)(/|$)", re.I)


@dataclass
class LoadResult:
    rules: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "sigma": "\n---\n".join(self.rules),
            "rule_count": len(self.rules),
            "file_count": len(self.files),
            "files": self.files[:40],
            "skipped": self.skipped[:20],
            "errors": self.errors[:10],
            "truncated": self.truncated,
        }


def _looks_like_archive(name: str, data: bytes) -> bool:
    low = name.lower()
    if low.endswith(ARCHIVE_SUFFIXES):
        return True
    return data[:2] == b"PK" or data[:2] == b"\x1f\x8b"


def _iter_archive(name: str, data: bytes) -> dict[str, bytes]:
    """Возвращает {путь: содержимое} для zip/tar архивов."""
    out: dict[str, bytes] = {}
    low = name.lower()
    if low.endswith(".zip") or data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > MAX_FILE_BYTES:
                    continue
                if len(out) >= MAX_FILES:
                    break
                out[info.filename] = zf.read(info)
        return out
    if low.endswith((".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")) or data[:2] == b"\x1f\x8b":
        total = 0
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for member in tf:
                if not member.isfile() or member.name.startswith(("/", "..")):
                    continue
                if member.size > MAX_FILE_BYTES:
                    continue
                total += member.size
                if total > MAX_TOTAL_BYTES or len(out) >= MAX_FILES:
                    break
                handle = tf.extractfile(member)
                if handle:
                    out[member.name] = handle.read()
        return out
    return out


def _valid_rules(text: str) -> list[str]:
    """Оставляет только те документы YAML, которые pySigma принимает."""
    try:
        collection = SigmaCollection.from_yaml(text)
    except Exception:
        return []
    if not collection.rules:
        return []
    # сохраняем исходный текст по правилам, чтобы не терять комментарии
    docs = [d.strip() for d in re.split(r"(?m)^---\s*$", text) if d.strip()]
    if len(docs) == len(collection.rules):
        return docs
    return [text.strip()]


def _collect(files: dict[str, bytes], result: LoadResult) -> None:
    seen_ids: set[str] = set()
    total_bytes = 0
    for path, raw in files.items():
        if len(result.rules) >= MAX_RULES:
            result.truncated = True
            break
        if _SKIP_DIRS.search(path):
            result.skipped.append(f"{path} (служебный каталог)")
            continue
        if not path.lower().endswith(YAML_SUFFIXES):
            continue
        total_bytes += len(raw)
        if total_bytes > MAX_TOTAL_BYTES:
            result.truncated = True
            break
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("cp1251")
            except UnicodeDecodeError:
                result.skipped.append(f"{path} (кодировка)")
                continue
        rules = _valid_rules(text)
        if not rules:
            result.skipped.append(f"{path} (не Sigma или ошибка YAML)")
            continue
        added = 0
        for rule in rules:
            if len(result.rules) >= MAX_RULES:
                result.truncated = True
                break
            rule_id = _rule_id(rule)
            if rule_id and rule_id in seen_ids:
                continue
            if rule_id:
                seen_ids.add(rule_id)
            result.rules.append(rule)
            added += 1
        if added:
            result.files.append(path)


def _rule_id(rule: str) -> str | None:
    match = re.search(r"(?m)^id:\s*['\"]?([\w\-\.]+)", rule)
    return match.group(1) if match else None


def from_upload(filename: str, data: bytes) -> dict:
    result = LoadResult()
    if len(data) > MAX_FILE_BYTES and not _looks_like_archive(filename, data):
        raise ValueError(f"Файл больше {MAX_FILE_BYTES // 1024 // 1024} МБ")
    if _looks_like_archive(filename, data):
        files = _iter_archive(filename, data)
        if not files:
            raise ValueError("Архив пуст или формат не поддерживается")
        _collect(files, result)
    else:
        _collect({filename: data}, result)
    return result.to_dict()


def from_url(url: str) -> dict:
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        raise ValueError("Нужна ссылка http(s)://")
    result = LoadResult()
    try:
        with httpx.Client(follow_redirects=True, timeout=URL_TIMEOUT,
                          headers={"User-Agent": "sigma2graylog/1.0"}) as client:
            response = client.get(url)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise ValueError(f"Не удалось скачать: {exc}") from exc
    data = response.content
    if len(data) > MAX_TOTAL_BYTES:
        raise ValueError("Файл по ссылке слишком большой")
    name = url.split("?")[0].rstrip("/").split("/")[-1] or "rules.yaml"
    if _looks_like_archive(name, data):
        files = _iter_archive(name, data)
        if not files:
            raise ValueError("Архив пуст или формат не поддерживается")
        _collect(files, result)
    else:
        _collect({name: data}, result)
    return result.to_dict()
