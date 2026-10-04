#!/usr/bin/env python3
"""Dependency-free registry guard used by CI and release reviewers."""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}/[a-z0-9][a-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

def load(path: Path):
    return json.loads(path.read_text())

def require(condition: bool, message: str):
    if not condition:
        raise ValueError(message)

def main() -> int:
    models = load(ROOT / "registry/models.json").get("models", [])
    require(isinstance(models, list) and models, "registry must contain models")
    ids = set()
    for model in models:
        ident = model.get("id")
        require(isinstance(ident, str) and MODEL_ID.fullmatch(ident), f"invalid canonical model ID: {ident!r}")
        require(ident not in ids, f"duplicate model ID: {ident}")
        ids.add(ident)
        policy_ref = model.get("policy_ref")
        require(isinstance(policy_ref, str) and policy_ref.startswith("policies/"), f"invalid policy ref for {ident}")
        policy = load(ROOT / policy_ref)
        require(policy.get("model_id") == ident, f"policy/model mismatch for {ident}")
        status = policy.get("status")
        require(status in {"template-not-production", "active", "retired"}, f"invalid policy status: {status!r}")
        if status == "active":
            for field in ("policy_id", "endpoint", "tls_spki_sha256", "receipt_keys", "evidence", "release_manifest"):
                require(field in policy, f"active policy {ident} missing {field}")
            require(DIGEST.fullmatch(policy["model_artifact_digest"] or "") is not None, f"active policy {ident} lacks model digest")
            require(DIGEST.fullmatch(policy["runtime_digest"] or "") is not None, f"active policy {ident} lacks runtime digest")
            require(DIGEST.fullmatch(policy["deployment_configuration_digest"] or "") is not None, f"active policy {ident} lacks compose digest")
            require(policy["tls_spki_sha256"].startswith("sha256:"), f"active policy {ident} lacks TLS SPKI")
            manifest = load(ROOT / policy["release_manifest"])
            require(manifest.get("status") == "active", f"active policy {ident} references non-active release")
    for manifest_path in (ROOT / "releases").glob("*.json"):
        manifest = load(manifest_path)
        require(manifest.get("status") in {"pre-activation", "active", "retired"}, f"invalid release state: {manifest_path}")
        for artifact in manifest.get("artifacts", []):
            image = artifact.get("image")
            require(isinstance(image, str) and "@sha256:" in image, f"un-pinned release artifact: {manifest_path}")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"registry validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
