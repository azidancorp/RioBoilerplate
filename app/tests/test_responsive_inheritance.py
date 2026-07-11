from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.components.responsive import ResponsiveComponent


APP_ROOT = Path(__file__).resolve().parents[1] / "app"


def _base_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _calls_is_mobile(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if isinstance(func, ast.Name) and func.id == "is_mobile":
            return True
        if isinstance(func, ast.Attribute) and func.attr == "is_mobile":
            return True
    return False


def test_classes_using_is_mobile_inherit_responsive_component():
    offenders: list[str] = []

    for py_file in APP_ROOT.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name == "ResponsiveComponent":
                continue
            if not _calls_is_mobile(node):
                continue

            base_names = {_base_name(base) for base in node.bases}
            if "ResponsiveComponent" not in base_names:
                relative = py_file.relative_to(APP_ROOT.parent)
                offenders.append(f"{relative}:{node.name}")

    assert not offenders, (
        "Classes that call is_mobile() must inherit ResponsiveComponent: "
        + ", ".join(sorted(offenders))
    )


@pytest.mark.parametrize(
    ("initial_width", "crossed_width"),
    [(80, 30), (30, 80), (40, 39)],
)
def test_first_breakpoint_crossing_refreshes(
    initial_width: float,
    crossed_width: float,
):
    session = SimpleNamespace(window_width=initial_width)
    refresh_count = 0

    def force_refresh() -> None:
        nonlocal refresh_count
        refresh_count += 1

    component = SimpleNamespace(
        session=session,
        force_refresh=force_refresh,
    )
    ResponsiveComponent._rio_post_init(component)

    session.window_width = crossed_width
    ResponsiveComponent.on_window_size_change(component)
    ResponsiveComponent.on_window_size_change(component)

    assert refresh_count == 1


@pytest.mark.parametrize(
    ("initial_width", "resized_width"),
    [(80, 60), (30, 20), (40, 60)],
)
def test_same_side_resize_does_not_refresh(
    initial_width: float,
    resized_width: float,
):
    session = SimpleNamespace(window_width=initial_width)
    refresh_count = 0

    def force_refresh() -> None:
        nonlocal refresh_count
        refresh_count += 1

    component = SimpleNamespace(
        session=session,
        force_refresh=force_refresh,
    )
    ResponsiveComponent._rio_post_init(component)

    session.window_width = resized_width
    ResponsiveComponent.on_window_size_change(component)

    assert refresh_count == 0
