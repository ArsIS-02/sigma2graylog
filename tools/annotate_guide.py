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
    # marks: (номер, прямоугольник в координатах исходника, смещение бейджа или (x, y) бейджа)
    "g1-connection": {
        "source": "04-settings.png", "crop": (10, 70, 900, 670),
        "marks": [
            ("1", (270, 138, 850, 172)),
            ("2", (30, 606, 228, 644)),
        ],
    },
    "g2-sources": {
        "source": "01-converter.png", "crop": (10, 100, 706, 275),
        "marks": [
            ("1", (25, 183, 300, 215)),
            ("2", (598, 183, 697, 215), (688, 152)),
        ],
    },
    "g3-result": {
        "source": "01-converter.png", "crop": (700, 92, 1660, 530),
        "marks": [
            ("1", (745, 273, 1630, 458)),
            ("2", (1105, 476, 1250, 508), (1350, 492)),
        ],
    },
    "g4-mapping": {
        "source": "01-converter.png", "crop": (700, 548, 1660, 742),
        "marks": [("1", (735, 610, 1648, 736))],
    },
    "g6-streams": {
        "source": "02-streams.png", "crop": (10, 60, 1670, 872),
        "marks": [
            ("1", (30, 230, 1650, 276)),
            ("2", (30, 600, 706, 634)),
        ],
    },
    "g7-detect": {
        "source": "03-detections.png", "crop": (10, 60, 1400, 520),
        "marks": [("1", (34, 244, 292, 272))],
    },
    "g5-history": {
        "source": "05-history.png", "crop": (700, 425, 1660, 740),
        "marks": [("1", (742, 433, 1628, 550))],
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

    # проход 1: рамки вокруг элементов
    for label, box, *rest in spec["marks"]:
        bx1, by1, bx2, by2 = (box[0]-x1+GUTTER, box[1]-y1, box[2]-x1+GUTTER, box[3]-y1)
        draw.rounded_rectangle([bx1, by1, bx2, by2], radius=9, outline=ACCENT, width=3)

    # проход 2: бейджи и стрелки
    for label, box, *rest in spec["marks"]:
        option = rest[0] if rest else 0
        dy = option if isinstance(option, int) else 0
        badge_pos = option if isinstance(option, tuple) else None
        bx1, by1, bx2, by2 = (box[0] - x1 + GUTTER, box[1] - y1,
                              box[2] - x1 + GUTTER, box[3] - y1)

        r = 15
        if badge_pos:
            cx = badge_pos[0] - x1
            cy = badge_pos[1] - y1
            right_side = cx > (bx1 + bx2) / 2
            below = cy < by1 - 4
        else:
            cx = GUTTER // 2
            cy = int((by1 + by2) / 2) + dy
            right_side = False
        cy = max(r + 4, min(cy, canvas.height - r - 4))
        cx = max(r + 2, min(cx, canvas.width - r - 2))
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=ACCENT)
        draw.text((cx, cy), label, font=font(19), fill=BADGE_TEXT, anchor="mm")
        if badge_pos and cy < by1 - 4:
            # бейдж над элементом: короткая стрелка вниз
            for yy in range(cy + r + 4, by1 - 14, 8):
                draw.line([(cx, yy), (cx, yy + 4)], fill=(120, 96, 40), width=2)
            arrow(draw, (cx, by1 - 14), (cx, by1 - 3))
        elif right_side:
            # бейдж справа: пунктир от него влево к элементу
            for xx in range(bx2 + 18, cx - r - 6, 10):
                draw.line([(xx, cy), (xx + 5, cy)], fill=(120, 96, 40), width=2)
            arrow(draw, (bx2 + 18, cy), (bx2 + 3, cy))
        else:
            for xx in range(cx + r + 4, bx1 - 18, 10):
                draw.line([(xx, cy), (xx + 5, cy)], fill=(120, 96, 40), width=2)
            target_y = by2 - 8 if dy > 0 else (by1 + 8 if dy < 0 else cy)
            arrow(draw, (bx1 - 18, cy), (bx1 - 3, target_y))
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
