"""Готовит иллюстрации для руководства: обводит элементы, рисует номера и стрелки.

Скрипт не входит в рантайм — запускается вручную при обновлении скриншотов.
На выходе: PNG с аннотациями + JSON с центрами обводок для CSS-анимации.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ACCENT = (255, 181, 71)
BADGE_TEXT = (36, 26, 5)
SRC = Path("docs/screenshots")
OUT = Path("app/static/media/guide")
FONT_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
]

# прямоугольники в координатах исходных скриншотов: (x1, y1, x2, y2)
STEPS = {
    "g1-connection": {
        "source": "04-settings.png", "crop": (10, 70, 900, 660),
        "marks": [
            ("1", (270, 138, 850, 172), "above-left"),
            ("2", (30, 606, 228, 644), "above-right"),
        ],
    },
    "g2-sources": {
        "source": "01-converter.png", "crop": (18, 88, 715, 345),
        "marks": [
            ("1", (25, 170, 300, 202), "above-left"),
            ("2", (598, 170, 697, 202), "above-left"),
        ],
    },
    "g3-result": {
        "source": "01-converter.png", "crop": (700, 88, 1660, 560),
        "marks": [
            ("1", (796, 265, 1632, 392), "above-right"),
            ("2", (1104, 436, 1248, 470), "above-right"),
        ],
    },
    "g4-mapping": {
        "source": "01-converter.png", "crop": (700, 560, 1660, 845),
        "marks": [("1", (886, 612, 1472, 652), "above-right")],
    },
    "g6-streams": {
        "source": "02-streams.png", "crop": (10, 60, 1670, 790),
        "marks": [
            ("1", (30, 258, 1650, 312), "above-left"),
            ("2", (378, 696, 1372, 736), "above-left"),
        ],
    },
    "g7-detect": {
        "source": "03-detections.png", "crop": (10, 60, 1400, 700),
        "marks": [("1", (34, 244, 292, 272), "above-left")],
    },
    "g5-history": {
        "source": "05-history.png", "crop": (700, 320, 1660, 790),
        "marks": [("1", (742, 462, 1628, 552), "above-left")],
    },
}


def font(size: int):
    for path in FONT_CANDIDATES:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def arrow(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int]) -> None:
    draw.line([start, end], fill=ACCENT, width=3)
    # наконечник
    dx, dy = end[0] - start[0], end[1] - start[1]
    length = max((dx * dx + dy * dy) ** 0.5, 1)
    ux, uy = dx / length, dy / length
    px, py = -uy, ux
    size = 11
    p1 = (end[0] - ux * size + px * size * 0.55, end[1] - uy * size + py * size * 0.55)
    p2 = (end[0] - ux * size - px * size * 0.55, end[1] - uy * size - py * size * 0.55)
    draw.polygon([end, p1, p2], fill=ACCENT)


def annotate(name: str, spec: dict) -> dict:
    """Кадр + левое поле с номерами: стрелки идут из поля в картинку, пересечений нет."""
    src_path = (SRC / spec["source"]).resolve()
    im = Image.open(src_path).convert("RGB")
    x1, y1, x2, y2 = spec["crop"]
    shot = im.crop(spec["crop"])

    GUTTER = 58
    canvas = Image.new("RGB", (shot.width + GUTTER, shot.height), (11, 16, 24))
    canvas.paste(shot, (GUTTER, 0))
    # тонкая граница между полем и кадром
    ImageDraw.Draw(canvas).line([(GUTTER - 1, 0), (GUTTER - 1, shot.height)], fill=(38, 48, 72))
    draw = ImageDraw.Draw(canvas)
    centers = []

    for index, (label, box, _side) in enumerate(spec["marks"]):
        bx1, by1, bx2, by2 = (box[0] - x1 + GUTTER, box[1] - y1,
                              box[2] - x1 + GUTTER, box[3] - y1)
        draw.rounded_rectangle([bx1, by1, bx2, by2], radius=9, outline=ACCENT, width=3)

        r = 15
        cx = GUTTER // 2
        cy = int((by1 + by2) / 2)
        cy = max(r + 4, min(cy, canvas.height - r - 4))
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=ACCENT)
        draw.text((cx, cy), label, font=font(19), fill=BADGE_TEXT, anchor="mm")
        # пунктирная линия по полю + стрелка в кадр
        for xx in range(cx + r + 4, bx1 - 18, 10):
            draw.line([(xx, cy), (xx + 5, cy)], fill=(120, 96, 40), width=2)
        arrow(draw, (bx1 - 18, cy), (bx1 - 3, cy))
        centers.append({
            "label": label,
            "x": round(cx / canvas.width * 100, 1),
            "y": round(cy / canvas.height * 100, 1),
        })

    OUT.mkdir(parents=True, exist_ok=True)
    canvas.save(OUT / f"{name}.png")
    return {"size": canvas.size, "centers": centers}


def main() -> None:
    only = sys.argv[1] if len(sys.argv) > 1 else None
    result = {}
    for name, spec in STEPS.items():
        if only and only != name:
            continue
        result[name] = annotate(name, spec)
        print(f"{name}: {result[name]['size']} центры={result[name]['centers']}")
    Path("tools/guide-points.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
