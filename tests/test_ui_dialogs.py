"""В интерфейсе не должно быть нативных alert/confirm/prompt — только диалоги в стиле инструмента."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "app" / "static"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_no_native_dialogs():
    pattern = re.compile(r"(?<![\w.])(alert|confirm|prompt)\s*\(")
    bad = []
    for path in [*ROOT.glob("*.html"), *ROOT.glob("js/*.js")]:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("//")[0]
            if pattern.search(code) and "uiConfirm" not in code and "uiAlert" not in code:
                bad.append(f"{path.name}:{n}: {line.strip()[:80]}")
    assert not bad, "нативные диалоги: " + "; ".join(bad)
