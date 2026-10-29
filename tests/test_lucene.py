"""Приведение запроса pySigma к синтаксису Graylog."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.lucene_fix import fix_query  # noqa: E402

# pySigma экранирует обратный слэш: в запросе приходит '\\cmd.exe'
INPUT = "Image:*\\\\cmd.exe"


def test_leading_wildcard_becomes_regex():
    assert fix_query(INPUT) == "Image:/.*\\\\cmd\\.exe/"


def test_contains_becomes_regex():
    assert fix_query("CommandLine:*\\\\-enc*") == "CommandLine:/.*\\\\-enc.*/"


def test_trailing_wildcard_is_kept():
    assert fix_query("Image:cmd*") == "Image:cmd*"


def test_bare_wildcard_untouched():
    assert fix_query("field:*") == "field:*"


def test_case_insensitive_expands_letters():
    out = fix_query(INPUT, case_insensitive=True)
    assert "[Cc]" in out and "[Dd]" in out


def test_case_expansion_keeps_escapes():
    out = fix_query(INPUT, case_insensitive=True)
    assert "\\\\" in out          # экранированный слэш сохранён
    assert "\\." in out           # точка по-прежнему экранирована
    assert out.count("[") == 6    # cmd + exe: 6 букв


def test_already_regex_is_untouched():
    q = "Image:/.*foo.*/"
    assert fix_query(q) == q
