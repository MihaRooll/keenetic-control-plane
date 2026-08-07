#!/usr/bin/env python3
"""Генерация PNG-иконок LOCAL HUB (единственный источник байтов иконок).

Запуск из корня репозитория:
    py -3.11 scripts/generate-hub-icons.py

Перезаписывает PNG в router_control_host/web/hub/icons/.
Повторный запуск детерминирован: те же байты, без tIME-чанков в PNG.
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ICONS_DIR = REPO_ROOT / "router_control_host" / "web" / "hub" / "icons"

BG = (0x0B, 0x0F, 0x1A, 0xFF)
ACCENT = (0x4F, 0x5B, 0xF0, 0xFF)
ACCENT_LIGHT = (0x6B, 0x75, 0xF5, 0xFF)


def _hexagon_vertices(cx: float, cy: float, radius: float) -> list[tuple[float, float]]:
    return [
        (
            cx + radius * math.cos(math.radians(60 * i - 30)),
            cy + radius * math.sin(math.radians(60 * i - 30)),
        )
        for i in range(6)
    ]


def _point_in_polygon(x: float, y: float, poly: list[tuple[float, float]]) -> bool:
    inside = False
    j = len(poly) - 1
    for i in range(len(poly)):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if ((yi > y) != (yj > y)) and (
            x < (xj - xi) * (y - yi) / (yj - yi + 1e-12) + xi
        ):
            inside = not inside
        j = i
    return inside


def _render_emblem(
    size: int,
    *,
    maskable: bool = False,
    opaque: bool = False,
) -> list[list[tuple[int, int, int, int]]]:
    """Рисует эмблему: тёмный фон и сине-фиолетовый скруглённый шестиугольник-куб."""
    rows: list[list[tuple[int, int, int, int]]] = []
    cx = cy = (size - 1) / 2.0
    if maskable:
        radius = size * 0.32
    else:
        radius = size * 0.38

    outer = _hexagon_vertices(cx, cy, radius)
    inner = _hexagon_vertices(cx, cy - radius * 0.08, radius * 0.55)
    highlight = _hexagon_vertices(cx, cy - radius * 0.22, radius * 0.28)

    for y in range(size):
        row: list[tuple[int, int, int, int]] = []
        for x in range(size):
            if _point_in_polygon(x + 0.5, y + 0.5, outer):
                if _point_in_polygon(x + 0.5, y + 0.5, highlight):
                    pixel = ACCENT_LIGHT
                elif _point_in_polygon(x + 0.5, y + 0.5, inner):
                    pixel = ACCENT
                else:
                    pixel = ACCENT
            else:
                pixel = BG
            if opaque and pixel[3] < 255:
                pixel = (*pixel[:3], 255)
            row.append(pixel)
        rows.append(row)
    return rows


def _encode_png(width: int, height: int, rows: list[list[tuple[int, int, int, int]]]) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    raw = bytearray()
    for row in rows:
        raw.append(0)
        for r, g, b, a in row:
            raw.extend((r, g, b, a))

    compressed = zlib.compress(bytes(raw), 9)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", compressed)
        + chunk(b"IEND", b"")
    )


def generate_icon_bytes(
    size: int,
    *,
    maskable: bool = False,
    opaque: bool = False,
) -> bytes:
    rows = _render_emblem(size, maskable=maskable, opaque=opaque)
    return _encode_png(size, size, rows)


def generate_all_icons() -> dict[str, bytes]:
    """Возвращает отображение имя файла → PNG-байты (для тестов и CLI)."""
    return {
        "icon-192.png": generate_icon_bytes(192),
        "icon-512.png": generate_icon_bytes(512),
        "icon-maskable-512.png": generate_icon_bytes(512, maskable=True),
        "apple-touch-icon-180.png": generate_icon_bytes(180, opaque=True),
    }


def main() -> None:
    ICONS_DIR.mkdir(parents=True, exist_ok=True)
    icons = generate_all_icons()
    for name, data in icons.items():
        (ICONS_DIR / name).write_bytes(data)
    print(f"Wrote {len(icons)} PNG icons to {ICONS_DIR}")


if __name__ == "__main__":
    main()
