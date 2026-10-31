"""Номер версии: формат и наличие заглушки на страницах."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.version import __version__  # noqa: E402


def test_version_format():
    assert re.fullmatch(r"\d+\.\d+(\.\d+)?", __version__)


def test_pages_have_version_placeholder():
    for name in ("index.html", "login.html"):
        assert "__VERSION__" in (ROOT / "app" / "static" / name).read_text("utf-8")
