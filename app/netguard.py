"""Защита загрузки по ссылке от SSRF.

Сервис скачивает файлы по ссылке, введённой пользователем. Без проверки так
можно достучаться до внутренних адресов (Graylog, метаданные облака, localhost).
Здесь адрес проверяется до запроса и заново на каждом редиректе, а размер
ответа ограничивается в процессе чтения.

`ALLOW_PRIVATE_URLS=1` разрешает частные адреса (например, свой внутренний git).
"""
from __future__ import annotations

import ipaddress
import os
import socket
from typing import Callable
from urllib.parse import urljoin, urlsplit

MAX_REDIRECTS = 5
USER_AGENT = "sigma2graylog/1.0"

Resolver = Callable[[str], list[str]]


class UnsafeURL(ValueError):
    """Ссылка ведёт на запрещённый адрес или имеет недопустимый вид."""


def private_allowed() -> bool:
    return os.environ.get("ALLOW_PRIVATE_URLS", "").strip().lower() in ("1", "true", "yes")


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURL(f"Не удалось определить адрес «{host}»") from exc
    return sorted({info[4][0] for info in infos})


def _is_public(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%")[0])
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def check_url(url: str, resolver: Resolver | None = None) -> str:
    """Возвращает url, если он безопасен; иначе поднимает UnsafeURL."""
    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in ("http", "https"):
        raise UnsafeURL("Нужна ссылка http(s)://")
    if parts.username or parts.password:
        raise UnsafeURL("Логин и пароль в ссылке не поддерживаются")
    host = parts.hostname
    if not host:
        raise UnsafeURL("В ссылке нет адреса сервера")
    if private_allowed():
        return url
    try:
        addrs = [str(ipaddress.ip_address(host))]
    except ValueError:
        addrs = (resolver or _resolve)(host)
    if not addrs:
        raise UnsafeURL(f"Не удалось определить адрес «{host}»")
    for addr in addrs:
        if not _is_public(addr):
            raise UnsafeURL("Ссылка ведёт на внутренний адрес — загрузка запрещена")
    return url


def fetch(url: str, max_bytes: int, timeout: float = 25.0,
          resolver: Resolver | None = None) -> bytes:
    """Скачивает url с проверкой адреса на каждом редиректе и лимитом размера."""
    import httpx  # локально: чистые проверки выше не требуют httpx

    current = check_url(url, resolver)
    with httpx.Client(follow_redirects=False, timeout=timeout,
                      headers={"User-Agent": USER_AGENT}) as client:
        for _ in range(MAX_REDIRECTS + 1):
            with client.stream("GET", current) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise ValueError("Редирект без адреса")
                    current = check_url(urljoin(current, location), resolver)
                    continue
                response.raise_for_status()
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise ValueError("Файл по ссылке слишком большой")
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("Файл по ссылке слишком большой")
                    chunks.append(chunk)
                return b"".join(chunks)
    raise ValueError("Слишком много перенаправлений")
