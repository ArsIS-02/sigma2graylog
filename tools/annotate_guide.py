"""Готовит иллюстрации для руководства: полоса-указатель + номер в левом поле.

Скрипт не входит в рантайм: запускается вручную при обновлении скриншотов.
Положение элементов определяется по цвету фона, а не жёсткими координатами,
поэтому мелкие правки интерфейса не ломают разметку.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ACCENT = (255, 181, 71)
BADGE_TEXT = (36, 26, 5)
SRC = Path("docs/screenshots")
SRC_EN = Path("docs/screenshots/en")
OUT = Path("app/static/media/guide")
GUTTER = 58
FONTS = ["/System/Library/Fonts/Supplemental/Arial Bold.ttf",
         "/System/Library/Fonts/Helvetica.ttc"]

INPUT_BG = (28, 36, 56)     # поля ввода и строки таблиц
QUERY_BG = (11, 16, 24)     # блок запроса и история
CARD_BG = (17, 24, 40)      # карточки

# target: (что ищем, x-проба, y-от, y-до, цвет) ; band: (x1, x2) в координатах кропа
STEPS = {
    "g1-connection": {
        "source": "04-settings.png", "crop": (10, 70, 900, 700),
        "marks": [
            {"label": "1", "band_y": (121, 162), "band": (250, 880)},
            {"label": "2", "band_y": (588, 632), "band": (18, 350)},
        ],
    },
    "g2-sources": {
        "source": "06-library.png", "crop": (20, 250, 780, 578),
        "en": {"source": "07-library.png"},
        "marks": [
            {"label": "1", "band_y": (250, 520), "band": (4, 756)},
        ],
    },
    "g3-result": {
        "source": "01-converter.png", "crop": (700, 92, 1660, 545),
        "marks": [
            {"label": "1", "band_y": (300, 466), "band": (24, 950)},
            {"label": "2", "band_y": (466, 516), "band": (24, 580)},
        ],
    },
    "g4-mapping": {
        "source": "01-converter.png", "crop": (700, 545, 1660, 800),
        "marks": [{"label": "1", "band_y": (600, 792), "band": (180, 940)}],
    },
    "g5-history": {
        "source": "05-history.png", "crop": (700, 425, 1660, 770),
        "marks": [{"label": "1", "band_y": (466, 586), "band": (20, 950)}],
    },
    "g6-streams": {
        "source": "02-streams.png", "crop": (10, 60, 1670, 880),
        "marks": [
            {"label": "1", "probe": (1500, 200, 260, INPUT_BG), "band": (18, 1650)},
            {"label": "2", "probe": (1200, 620, 700, INPUT_BG), "band": (18, 1650)},
        ],
    },
    "g7-detect": {
        "source": "03-detections.png", "crop": (10, 60, 1400, 520),
        "marks": [
            {"label": "1", "probe": (700, 180, 300, (17, 24, 40)), "band": (18, 1380)},
        ],
    },
}


def font(size: int):
    for path in FONTS:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def find_band(im: Image.Image, probe, tol: int = 8, min_h: int = 16) -> tuple[int, int] | None:
    """Ищет вертикальную полосу цвета probe[3] в столбце probe[0] между probe[1] и probe[2]."""
    x, y0, y1, colour = probe
    run = None
    for y in range(y0, min(y1, im.height)):
        p = im.getpixel((x, y))[:3]
        hit = all(abs(p[i] - colour[i]) <= tol for i in range(3))
        if hit and run is None:
            run = y
        elif not hit and run is not None:
            if y - run >= min_h:
                return run, y
            run = None
    if run is not None and min(y1, im.height) - run >= min_h:
        return run, min(y1, im.height)
    return None


def annotate(name: str, spec: dict, src_dir: Path = SRC, out_name: str | None = None) -> dict:
    im = Image.open(src_dir / spec["source"]).convert("RGB")
    x1, y1, x2, y2 = spec["crop"]
    shot = im.crop(spec["crop"])
    canvas = Image.new("RGB", (shot.width + GUTTER, shot.height), (11, 16, 24))
    canvas.paste(shot, (GUTTER, 0))
    ImageDraw.Draw(canvas).line([(GUTTER - 1, 0), (GUTTER - 1, shot.height)], fill=(38, 48, 72))

    overlay = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    badge_layer = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    bdraw = ImageDraw.Draw(badge_layer)
    centers = []

    for mark in spec["marks"]:
        if "band_y" in mark:
            band = mark["band_y"]
        else:
            band = find_band(im, mark["probe"])
        if band is None:
            print(f"  ! {name}: не найдена полоса для метки {mark['label']}")
            continue
        top = band[0] - y1
        bottom = band[1] - y1
        if "band_y" not in mark:
            top -= 3
            bottom += 3
        bx1, bx2 = mark["band"][0] + GUTTER, mark["band"][1] + GUTTER
        # подсветка полосы + акцентная линия снизу
        draw.rounded_rectangle([bx1, top, bx2, bottom], radius=8, outline=ACCENT, width=3)
        cy = (top + bottom) // 2

        r = 15
        cx = GUTTER // 2
        # длинный пунктир только если полоса начинается рядом с полем;
        # иначе — короткая стрелка у края, чтобы не перечёркивать подписи
        if bx1 - (cx + r) <= 70:
            for xx in range(cx + r + 4, bx1 - 16, 9):
                bdraw.line([(xx, cy), (xx + 5, cy)], fill=(150, 118, 48, 255), width=2)
            arrow_x = bx1 - 16
        else:
            arrow_x = bx1 - 2
        bdraw.polygon([(bx1 - 1, cy), (arrow_x - 13, cy - 6), (arrow_x - 13, cy + 6)],
                      fill=(255, 181, 71, 255))
        bdraw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=ACCENT)
        bdraw.text((cx, cy), mark["label"], font=font(19), fill=BADGE_TEXT, anchor="mm")
        centers.append({"label": mark["label"],
                        "x": round(cx / canvas.width * 100, 1),
                        "y": round(cy / canvas.height * 100, 1)})

    canvas = Image.alpha_composite(canvas.convert("RGBA"), overlay)
    canvas = Image.alpha_composite(canvas, badge_layer).convert("RGB")
    OUT.mkdir(parents=True, exist_ok=True)
    canvas.save(OUT / f"{out_name or name}.png")
    return {"size": canvas.size, "centers": centers}


def main() -> None:
    only = sys.argv[1] if len(sys.argv) > 1 else None
    lang = sys.argv[2] if len(sys.argv) > 2 else "ru"
    src_dir = SRC_EN if lang == "en" else SRC
    suffix = ".en" if lang == "en" else ""
    result = {}
    for name, spec in STEPS.items():
        if only and only != name:
            continue
        if lang == "en" and "en" in spec:
            spec = {**spec, **spec["en"]}
        data = annotate(name, spec, src_dir=src_dir, out_name=f"{name}{suffix}")
        result[name] = data
        print(f"{name}{suffix}: {data['size']} {data['centers']}")
    if not suffix:
        Path("tools/guide-points.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
