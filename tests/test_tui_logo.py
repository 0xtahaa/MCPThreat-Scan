"""The Autorea mark in the TUI header: drawn from the brand polygons, not a pasted picture."""

import pytest

from mcpthreat_scan.tui import logo
from mcpthreat_scan.tui.logo import logo_dots, render_logo
from mcpthreat_scan.tui.theme import ACCENT


def _components(grid, diagonal):
    """Connected groups of dots (4- or 8-neighbourhood), each as a list of (row, column)."""
    neighbours = [(1, 0), (-1, 0), (0, 1), (0, -1)]
    if diagonal:
        neighbours += [(1, 1), (1, -1), (-1, 1), (-1, -1)]
    seen, groups = set(), []
    for row, line in enumerate(grid):
        for column, dot in enumerate(line):
            if not dot or (row, column) in seen:
                continue
            group, stack = [], [(row, column)]
            seen.add((row, column))
            while stack:
                y, x = stack.pop()
                group.append((y, x))
                for dy, dx in neighbours:
                    ny, nx = y + dy, x + dx
                    if 0 <= ny < len(grid) and 0 <= nx < len(grid[0]) and grid[ny][nx] and (ny, nx) not in seen:
                        seen.add((ny, nx))
                        stack.append((ny, nx))
            groups.append(group)
    return groups


def test_the_mark_is_five_lines_of_braille_in_the_brand_green():
    mark = render_logo()

    lines = mark.plain.split("\n")
    assert len(lines) == 5 and {len(line) for line in lines} == {8}
    assert all(0x2800 <= ord(character) <= 0x28FF for line in lines for character in line)
    assert str(mark.style) == ACCENT == "#CFE9C8"
    assert any(character != "⠀" for line in lines for character in line)


def test_the_three_planes_of_the_mark_stay_visibly_apart():
    grid = logo_dots(5)

    for diagonal in (False, True):
        groups = _components(grid, diagonal)
        assert len(groups) == 3
    top_to_bottom = sorted(_components(grid, True), key=lambda group: sum(y for y, _ in group) / len(group))
    centres = [sum(y for y, _ in group) / len(group) for group in top_to_bottom]
    assert centres[0] < centres[1] < centres[2]
    # the smallest plane is the top one, the largest the bottom one (as in the logo)
    assert [len(group) for group in top_to_bottom][0] < [len(group) for group in top_to_bottom][2]


def test_the_mark_scales_with_the_requested_height():
    assert len(render_logo(6).plain.split("\n")) == 6
    assert len(render_logo(7).plain.split("\n")) == 7
    assert logo_dots(5) is logo_dots(5)  # computed once, then cached


def test_the_planes_are_the_polygons_of_the_brand_kit_app_icon():
    # autorea-app-icon-dark.svg, <polygon points="..."> in the icon's own coordinates
    assert logo._PLANES == (
        ((43, 56), (156, 12), (156, 87)),
        ((32, 63), (214, 114), (32, 172)),
        ((57, 179), (227, 121), (227, 258)),
    )


@pytest.mark.parametrize("lines", [0, -1])
def test_a_non_positive_height_draws_nothing_instead_of_crashing(lines):
    assert render_logo(lines).plain == ""
