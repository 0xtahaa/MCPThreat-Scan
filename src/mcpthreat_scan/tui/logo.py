"""The Autorea mark for the TUI header, drawn with braille characters.

A terminal cannot show an SVG, so the three polygons of the brand kit's app icon
(Autorea_Brand_Kit/01_Logos/SVG/autorea-app-icon-dark.svg, polygon points in the icon's own
coordinates) are rasterized at run time: each braille character holds 2x4 square dots, so five
lines are 16x20 dots. The real gaps between the planes are thinner than one dot at that size, so a
dot only belongs to the mark where a single plane covers most of it and no other plane touches it;
that keeps the three planes visibly apart. Nothing here is a pasted text picture."""

from __future__ import annotations

from functools import lru_cache

from rich.text import Text

from mcpthreat_scan.tui.theme import ACCENT

# The three planes of the mark (autorea-app-icon-dark.svg).
_PLANES = (
    ((43, 56), (156, 12), (156, 87)),
    ((32, 63), (214, 114), (32, 172)),
    ((57, 179), (227, 121), (227, 258)),
)
_X0 = min(x for plane in _PLANES for x, _ in plane)
_Y0 = min(y for plane in _PLANES for _, y in plane)
_WIDTH = max(x for plane in _PLANES for x, _ in plane) - _X0
_HEIGHT = max(y for plane in _PLANES for _, y in plane) - _Y0

_MIN_COVERAGE = 0.7  # a dot must be mostly inside one plane ...
_MAX_OTHER_COVERAGE = 0.05  # ... and barely touched by any other
_SUBSAMPLES = 8
# Braille dot bit for (column, row) inside one character cell.
_DOT_BITS = {(0, 0): 1, (0, 1): 2, (0, 2): 4, (1, 0): 8, (1, 1): 16, (1, 2): 32, (0, 3): 64, (1, 3): 128}


def _inside(plane: tuple, x: float, y: float) -> bool:
    """Even-odd point-in-polygon test."""
    inside = False
    for index, (x1, y1) in enumerate(plane):
        x2, y2 = plane[(index + 1) % len(plane)]
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
            inside = not inside
    return inside


def _coverage(plane: tuple, column: int, row: int, columns: int, rows: int) -> float:
    """Share of the dot (column, row) that lies inside the plane, by supersampling."""
    hits = 0
    for a in range(_SUBSAMPLES):
        for b in range(_SUBSAMPLES):
            x = _X0 + (column + (a + 0.5) / _SUBSAMPLES) * _WIDTH / columns
            y = _Y0 + (row + (b + 0.5) / _SUBSAMPLES) * _HEIGHT / rows
            hits += _inside(plane, x, y)
    return hits / (_SUBSAMPLES * _SUBSAMPLES)


@lru_cache(maxsize=None)
def logo_dots(lines: int = 5) -> tuple[tuple[bool, ...], ...]:
    """The mark as a grid of dots (True = part of the mark), `lines` terminal lines high."""
    rows = lines * 4
    columns = 2 * round(rows * _WIDTH / _HEIGHT / 2)  # an even number: two dots per character
    grid = []
    for row in range(rows):
        line = []
        for column in range(columns):
            coverage = sorted(_coverage(plane, column, row, columns, rows) for plane in _PLANES)
            line.append(coverage[-1] > _MIN_COVERAGE and coverage[-2] <= _MAX_OTHER_COVERAGE)
        grid.append(tuple(line))
    return tuple(grid)


def render_logo(lines: int = 5) -> Text:
    """The mark as braille text in the brand's light green (ACCENT)."""
    grid = logo_dots(lines)
    text_lines = []
    for top in range(0, len(grid), 4):
        characters = []
        for left in range(0, len(grid[0]), 2):
            code = sum(
                bit for (dx, dy), bit in _DOT_BITS.items() if grid[top + dy][left + dx]
            )
            characters.append(chr(0x2800 + code))
        text_lines.append("".join(characters))
    return Text("\n".join(text_lines), style=ACCENT, no_wrap=True)
