"""Настройки приложения: хранятся в /data/settings.json, секреты шифруются Fernet."""
from __future__ import annotations

import base64
import json
import os
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

SECRET_FIELDS = ("graylog_password", "graylog_token")

DEFAULTS: dict = {
    "graylog_url": "",
    "graylog_public_url": "",
    "auth_mode": "basic",          # basic | token
    "graylog_user": "admin",
    "graylog_password": "",
    "graylog_token": "",
    "fields_ttl": 600,
    "default_stream_id": "",
    "default_range": 86400,
    "check_duplicates": True,
    "case_insensitive_regex": True,
}

INT_FIELDS = {"fields_ttl", "default_range"}


class SettingsStore:
    def __init__(self, path: Path, secret_path: Path):
        self.path = path
        self._lock = threading.Lock()
        key = secret_path.read_bytes().strip()[:32]
        self._fernet = Fernet(base64.urlsafe_b64encode(key))
        self._data: dict = dict(DEFAULTS)
        self.load()

    # --- шифрование ---------------------------------------------------------
    def _enc(self, value: str) -> str:
        if not value:
            return ""
        return "enc:" + self._fernet.encrypt(value.encode("utf-8")).decode()

    def _dec(self, value: str) -> str:
        if not value:
            return ""
        if not value.startswith("enc:"):
            return value
        try:
            return self._fernet.decrypt(value[4:].encode()).decode("utf-8")
        except (InvalidToken, ValueError):
            return ""

    # --- чтение/запись ------------------------------------------------------
    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            raw = {}
        data = dict(DEFAULTS)
        for key, value in raw.items():
            if key not in DEFAULTS:
                continue
            data[key] = self._dec(value) if key in SECRET_FIELDS else value
        self._data = data

    def save(self) -> None:
        with self._lock:
            out = {}
            for key, value in self._data.items():
                out[key] = self._enc(value) if key in SECRET_FIELDS else value
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2), "utf-8")
            os.chmod(tmp, 0o600)
            tmp.replace(self.path)

    def get(self) -> dict:
        return dict(self._data)

    def update(self, patch: dict) -> dict:
        for key, value in patch.items():
            if key not in DEFAULTS:
                continue
            if key in INT_FIELDS:
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    continue
            if isinstance(value, str):
                value = value.strip()
            self._data[key] = value
        self.save()
        return self.get()

    def masked(self) -> dict:
        """Версия для отдачи в браузер: секреты не раскрываются."""
        data = self.get()
        return {
            **{k: v for k, v in data.items() if k not in SECRET_FIELDS},
            "has_password": bool(data.get("graylog_password")),
            "has_token": bool(data.get("graylog_token")),
        }
