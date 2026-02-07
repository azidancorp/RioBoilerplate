from __future__ import annotations

import ast
from pathlib import Path


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
