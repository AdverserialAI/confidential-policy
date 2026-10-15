#!/usr/bin/env python3
"""Regression tests for fail-closed policy/release validation."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_registry.py"


def run(root: Path, expected: int) -> None:
    result = subprocess.run(
        [sys.executable, str(root / "tools" / "validate_registry.py")],
        cwd=root,
        text=True,
        capture_output=True,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"validator returned {result.returncode}, expected {expected}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def copy_registry(tempdir: Path) -> Path:
    target = tempdir / "registry"
    shutil.copytree(
        ROOT,
        target,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
    )
    return target


def mutate_json(path: Path, callback) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    callback(value)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def expect_rejected(name: str, callback) -> None:
    with tempfile.TemporaryDirectory(prefix="policy-validator-") as raw:
        root = copy_registry(Path(raw))
        callback(root)
        result = subprocess.run(
            [sys.executable, str(root / "tools" / "validate_registry.py")],
            cwd=root,
            text=True,
            capture_output=True,
        )
        if result.returncode == 0:
            raise AssertionError(f"{name}: validator accepted malformed trust material")


def main() -> int:
    run(ROOT, 0)

    expect_rejected(
        "abbreviated source commit",
        lambda root: mutate_json(
            root / "releases" / "attest-proxy-v0.1.0-rc.24.json",
            lambda value: value["source"].__setitem__("commit", "5e44f5a"),
        ),
    )
    expect_rejected(
        "mutable image reference",
        lambda root: mutate_json(
            root / "releases" / "attest-proxy-v0.1.0-rc.24.json",
            lambda value: value["artifacts"][0].__setitem__("image", "ghcr.io/adverserialai/attest-proxy:latest"),
        ),
    )
    expect_rejected(
        "path traversal policy reference",
        lambda root: mutate_json(
            root / "registry" / "models.json",
            lambda value: value["models"][0].__setitem__("policy_ref", "policies/../releases/attest-proxy-v0.1.0-rc.24.json"),
        ),
    )
    expect_rejected(
        "unverified active policy",
        lambda root: mutate_json(
            root / "policies" / "production.json",
            lambda value: value.__setitem__("status", "active"),
        ),
    )
    print("policy validator regression tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
