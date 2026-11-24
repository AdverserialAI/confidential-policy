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

    production = lambda root: root / "policies" / "production.json"
    current_manifest = lambda root: root / json.loads(production(root).read_text())["release_manifest"].lstrip("/")
    cases = {
        "abbreviated source commit in the current release": lambda root: mutate_json(current_manifest(root), lambda v: v["source"].__setitem__("commit", "5e44f5a")),
        "mutable image reference": lambda root: mutate_json(current_manifest(root), lambda v: v["artifacts"][0].__setitem__("image", "ghcr.io/adverserialai/attest-proxy:latest")),
        "release from another source repository": lambda root: mutate_json(current_manifest(root), lambda v: v["source"].__setitem__("repository", "https://github.com/someone/attest-proxy")),
        "current release not active": lambda root: mutate_json(current_manifest(root), lambda v: v.__setitem__("status", "retired")),
        "path traversal policy reference": lambda root: mutate_json(root / "registry" / "models.json", lambda v: v["models"][0].__setitem__("policy_ref", "policies/../releases/index.json")),
        "registry selects another model's policy": lambda root: mutate_json(root / "registry" / "models.json", lambda v: v["models"][0].__setitem__("policy_ref", "/policies/lordx64-cyberglm.json")),
        "production policy not active": lambda root: mutate_json(production(root), lambda v: v.__setitem__("status", "template-not-production")),
        "production policy without receipt keys": lambda root: mutate_json(production(root), lambda v: v.__setitem__("receipt_keys", {})),
        "private receipt key published": lambda root: mutate_json(production(root), lambda v: next(iter(v["receipt_keys"].values())).__setitem__("d", "c2VjcmV0")),
        "truncated measurement": lambda root: mutate_json(production(root), lambda v: v["tdx"].__setitem__("mrtd", v["tdx"]["mrtd"][:-2])),
        "malformed TLS pin": lambda root: mutate_json(production(root), lambda v: v.__setitem__("tls_spki_sha256", "sha256:short")),
        "missing hardware binding": lambda root: mutate_json(production(root), lambda v: v["required_bindings"].remove("tdx_quote")),
        "policy and manifest name different proxy versions": lambda root: mutate_json(production(root), lambda v: v.__setitem__("proxy_version", "v0.1.0-rc.1")),
        "credential in a release manifest": lambda root: mutate_json(current_manifest(root), lambda v: v.__setitem__("note", "-----BEGIN EC PRIVATE KEY-----")),
        "production policy deleted": lambda root: production(root).unlink(),
    }
    for name, mutate in cases.items():
        expect_rejected(name, mutate)
    print(f"policy validator regression tests passed ({len(cases)} rejections)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
