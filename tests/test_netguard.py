"""Защита загрузки по ссылке (SSRF). Сеть не нужна: DNS подменяется."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import netguard  # noqa: E402
from app.netguard import UnsafeURL, check_url  # noqa: E402


def fake(mapping):
    return lambda host: mapping[host]


@pytest.fixture(autouse=True)
def _no_override(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_URLS", raising=False)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/x", "http://localhost/x", "http://10.0.0.5:9000/api",
    "http://192.168.1.10/", "http://172.16.0.1/", "http://169.254.169.254/latest/meta-data",
    "http://[::1]/", "http://[fd00::1]/", "http://0.0.0.0/", "http://[::ffff:127.0.0.1]/",
])
def test_private_literals_rejected(url):
    with pytest.raises(UnsafeURL):
        check_url(url, fake({"localhost": ["127.0.0.1"]}))


def test_hostname_resolving_to_private_rejected():
    with pytest.raises(UnsafeURL):
        check_url("https://evil.example/x", fake({"evil.example": ["93.184.216.34", "10.1.1.1"]}))


def test_public_host_allowed():
    url = "https://github.com/SigmaHQ/sigma.zip"
    assert check_url(url, fake({"github.com": ["140.82.121.4"]})) == url


def test_public_literal_allowed():
    assert check_url("http://93.184.216.34/a.yml") == "http://93.184.216.34/a.yml"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "gopher://x/",
                                 "http:///nohost", "http://user:pw@example.com/"])
def test_bad_scheme_or_shape_rejected(url):
    with pytest.raises(UnsafeURL):
        check_url(url, fake({"example.com": ["93.184.216.34"]}))


def test_override_allows_private(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_URLS", "1")
    assert check_url("http://10.0.0.5/x") == "http://10.0.0.5/x"
