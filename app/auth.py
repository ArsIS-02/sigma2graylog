"""Аутентификация: пользователи в JSON, пароли на scrypt, сессия в подписанной cookie."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = 32

COOKIE_NAME = "s2g_session"
SESSION_TTL = 12 * 3600  # 12 часов
MIN_PASSWORD_LEN = 8


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def hash_password(password: str) -> dict:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N,
                        r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_LEN)
    return {
        "algo": "scrypt",
        "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "salt": _b64(salt),
        "hash": _b64(dk),
        "updated_at": int(time.time()),
    }


def check_password(password: str, record: dict) -> bool:
    try:
        dk = hashlib.scrypt(password.encode("utf-8"), salt=_unb64(record["salt"]),
                            n=record["n"], r=record["r"], p=record["p"],
                            dklen=SCRYPT_LEN)
        return hmac.compare_digest(dk, _unb64(record["hash"]))
    except (KeyError, ValueError):
        return False


class UserStore:
    def __init__(self, path: Path):
        self.path = path
        self.users: dict[str, dict] = {}
        self._mtime = 0.0
        self.load()

    def load(self) -> None:
        try:
            self.users = json.loads(self.path.read_text("utf-8"))
            self._mtime = self.path.stat().st_mtime
        except (OSError, ValueError):
            self.users = {}
            self._mtime = 0.0

    def _sync(self) -> None:
        """Перечитывает файл, если его изменили извне (сброс пароля через podman exec)."""
        try:
            if self.path.stat().st_mtime != self._mtime:
                self.load()
        except OSError:
            pass

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.users, ensure_ascii=False, indent=2), "utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        self._mtime = self.path.stat().st_mtime

    def bootstrap(self, username: str, password: str) -> bool:
        """Первый запуск: заводим пользователя из переменных окружения."""
        if self.users or not password:
            return False
        self.set_password(username, password)
        return True

    def set_password(self, username: str, password: str) -> None:
        if len(password) < MIN_PASSWORD_LEN:
            raise ValueError(f"Пароль короче {MIN_PASSWORD_LEN} символов")
        self.users[username] = hash_password(password)
        self.save()

    def verify(self, username: str, password: str) -> bool:
        self._sync()
        record = self.users.get(username)
        if record is None:
            # выравниваем время ответа, чтобы нельзя было перебирать имена
            hashlib.scrypt(b"x", salt=b"0" * 16, n=SCRYPT_N, r=SCRYPT_R,
                           p=SCRYPT_P, dklen=SCRYPT_LEN)
            return False
        return check_password(password, record)

    def exists(self, username: str) -> bool:
        self._sync()
        return username in self.users

    def version(self, username: str) -> str:
        self._sync()
        """Отпечаток текущего пароля: смена пароля инвалидирует старые сессии."""
        record = self.users.get(username) or {}
        return hashlib.sha256(str(record.get("hash", "")).encode()).hexdigest()[:16]

    def updated_at(self, username: str) -> int:
        self._sync()
        return int(self.users.get(username, {}).get("updated_at", 0))


class Sessions:
    """Подписанные сессионные токены (без внешних зависимостей)."""

    def __init__(self, secret_path: Path):
        self.secret = self._load_or_create(secret_path)

    @staticmethod
    def _load_or_create(path: Path) -> bytes:
        try:
            data = path.read_bytes().strip()
            if len(data) >= 32:
                return data
        except OSError:
            pass
        secret = secrets.token_bytes(48)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(secret)
        os.chmod(path, 0o600)
        return secret

    def issue(self, username: str, version: str) -> str:
        payload = {"u": username, "exp": int(time.time()) + SESSION_TTL, "v": version}
        body = _b64(json.dumps(payload, separators=(",", ":")).encode())
        sig = _b64(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str, users: UserStore) -> str | None:
        try:
            body, sig = token.split(".", 1)
        except (ValueError, AttributeError):
            return None
        expected = _b64(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            payload = json.loads(_unb64(body))
        except (ValueError, TypeError):
            return None
        if int(payload.get("exp", 0)) < time.time():
            return None
        user = payload.get("u")
        if not user or not users.exists(user):
            return None
        # смена пароля инвалидирует старые сессии
        if payload.get("v") != users.version(user):
            return None
        return user


class Throttle:
    """Примитивный лимит попыток входа по IP."""

    def __init__(self, attempts: int = 8, window: int = 300):
        self.attempts = attempts
        self.window = window
        self.buckets: dict[str, tuple[int, float]] = {}

    def blocked(self, key: str) -> bool:
        count, reset = self.buckets.get(key, (0, 0.0))
        return count >= self.attempts and reset > time.time()

    def fail(self, key: str) -> None:
        now = time.time()
        count, reset = self.buckets.get(key, (0, 0.0))
        if reset <= now:
            count, reset = 0, now + self.window
        self.buckets[key] = (count + 1, reset)

    def reset(self, key: str) -> None:
        self.buckets.pop(key, None)
