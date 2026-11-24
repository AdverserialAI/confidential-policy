#!/usr/bin/env python3
"""Fail-closed validation of the published policy documents.

This repository is the source of what https://verify.adverserial.ai serves
under /policies, /releases, /registry and /schema, and every change to those
files on main is signed. This check runs before anything is signed. It does
not decide whether a policy is *right* (that needs the deployment's attestation
evidence); it refuses documents that are malformed, inconsistent with each
other, or that would publish private key material.

Standard library only.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SOURCE_REPOSITORY = "https://github.com/AdverserialAI/attest-proxy"
MODEL_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}/[a-z0-9][a-z0-9._-]{0,127}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHORT_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
RELEASE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$")
IMAGE = re.compile(r"^ghcr\.io/adverserialai/[a-z0-9-]+@sha256:[0-9a-f]{64}$")
SPKI = re.compile(r"^sha256:[A-Za-z0-9_-]{43}$")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{3})?Z$")
TDX_FIELDS = {"mrtd": 96, "rtmr0": 96, "rtmr1": 96, "rtmr2": 96, "app_id": 40, "compose_hash": 64, "os_image_hash": 64}
POLICY_STATES = {"template-not-production", "active", "retired"}
RELEASE_STATES = {"pre-activation", "active", "retired"}
REQUIRED_BINDINGS = {
    "fresh_client_nonce", "tdx_quote", "tdx_event_log", "tls_spki_der", "gpu_evidence", "report_data",
    "runtime_image_digest", "model_artifact_digest", "deployment_configuration_digest",
}
PRIVATE_JWK_MEMBERS = {"d", "k", "p", "q", "dp", "dq", "qi", "oth"}
SECRET_TEXT = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}|\bsk-[A-Za-z0-9_-]{24,}|\bAKIA[0-9A-Z]{16}\b")


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, message: str):
    if not condition:
        raise ValueError(message)


def repo_path(reference: object, *, directory: str, label: str) -> Path:
    """Resolve a document reference to a JSON file directly under ``directory``.

    The site refers to its documents from the web root ("/policies/x.json");
    the repository root is that web root.
    """
    require(isinstance(reference, str) and reference, f"{label} must be a string")
    candidate = (ROOT / reference.lstrip("/")).resolve()
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository: {reference!r}") from exc
    require(candidate.parent == (ROOT / directory).resolve() and candidate.suffix == ".json", f"invalid {label}: {reference!r}")
    require(candidate.is_file(), f"missing {label}: {reference!r}")
    return candidate


def no_private_material(value, where: str) -> None:
    """No private JWK members and nothing that looks like a credential, anywhere."""
    if isinstance(value, dict):
        if "kty" in value:
            exposed = PRIVATE_JWK_MEMBERS.intersection(value)
            require(not exposed, f"{where} exposes private key material ({', '.join(sorted(exposed))})")
        for key, child in value.items():
            no_private_material(child, f"{where}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            no_private_material(child, f"{where}[{index}]")
    elif isinstance(value, str):
        require(not SECRET_TEXT.search(value), f"{where} looks like a credential")


def validate_receipt_keys(policy: dict, name: str) -> None:
    keys = policy.get("receipt_keys")
    require(isinstance(keys, dict) and keys, f"active policy {name} has no receipt keys")
    for kid, key in keys.items():
        require(isinstance(kid, str) and kid and isinstance(key, dict), f"active policy {name} has an invalid receipt key")
        require(key.get("kid") == kid, f"active policy {name} receipt key id mismatch")
        require(key.get("use") == "sig", f"active policy {name} receipt key {kid!r} is not signing-only")
        require(key.get("kty") == "EC" and key.get("crv") == "P-256" and key.get("alg") == "ES256", f"active policy {name} receipt key {kid!r} is not P-256/ES256")
        require(all(isinstance(key.get(part), str) and key[part] for part in ("x", "y")), f"active policy {name} receipt key {kid!r} lacks coordinates")


def validate_manifest(path: Path, *, current: bool = False) -> dict:
    """``current``: the manifest the enforced policy points to; historical ones predate the full-SHA rule."""
    manifest = load(path)
    status = manifest.get("status")
    require(status in RELEASE_STATES, f"invalid release state: {path.name}")
    release = manifest.get("release")
    require(isinstance(release, str) and RELEASE.fullmatch(release), f"invalid release name: {path.name}")
    require(path.name == f"attest-proxy-{release}.json", f"release file/name mismatch: {path.name}")
    source = manifest.get("source")
    require(isinstance(source, dict), f"missing source metadata: {path.name}")
    require(source.get("repository") == EXPECTED_SOURCE_REPOSITORY, f"unexpected source repository: {path.name}")
    require(source.get("tag") == release, f"release/source tag mismatch: {path.name}")
    require(isinstance(source.get("commit"), str) and (COMMIT if current else SHORT_COMMIT).fullmatch(source["commit"]), f"source commit must be a {'full ' if current else ''}SHA: {path.name}")
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, f"release has no artifacts: {path.name}")
    for artifact in artifacts:
        require(isinstance(artifact, dict), f"invalid artifact record: {path.name}")
        require(isinstance(artifact.get("image"), str) and IMAGE.fullmatch(artifact["image"]), f"un-pinned or unexpected artifact image: {path.name}")
    return manifest


def validate_runtime_policy(path: Path, registered: set[str]) -> None:
    """A policy for a confidential-inference model (it has a model_id)."""
    policy = load(path)
    name = path.relative_to(ROOT).as_posix()
    require(MODEL_ID.fullmatch(policy["model_id"]) is not None, f"invalid canonical model ID in {name}")
    require(policy.get("status") in POLICY_STATES, f"invalid policy status in {name}: {policy.get('status')!r}")
    release = policy.get("release")
    require(isinstance(release, dict) and release.get("source_repository") == EXPECTED_SOURCE_REPOSITORY, f"unexpected policy source in {name}")
    manifest = None
    if policy.get("release_manifest") is not None:
        manifest = validate_manifest(repo_path(policy["release_manifest"], directory="releases", label=f"release manifest in {name}"), current=name in registered)
    if name not in registered:
        return
    # The policy the model registry selects is the one clients enforce.
    require(policy.get("status") == "active", f"the registry selects a policy that is not active: {name}")
    require(isinstance(policy.get("policy_id"), str) and policy["policy_id"], f"active policy {name} has no policy_id")
    require(isinstance(policy.get("published_at"), str) and STAMP.fullmatch(policy["published_at"]), f"active policy {name} has no valid published_at")
    bindings = policy.get("required_bindings")
    require(isinstance(bindings, list) and REQUIRED_BINDINGS.issubset(bindings), f"active policy {name} omits a required hardware binding")
    for field in ("runtime_image_digest", "model_artifact_digest", "deployment_configuration_digest"):
        require(isinstance(policy.get(field), str) and SHA256.fullmatch(policy[field]), f"active policy {name} has invalid {field}")
    require(isinstance(policy.get("tls_spki_sha256"), str) and SPKI.fullmatch(policy["tls_spki_sha256"]), f"active policy {name} has invalid TLS SPKI")
    tdx = policy.get("tdx")
    require(isinstance(tdx, dict), f"active policy {name} has no TDX measurements")
    for field, length in TDX_FIELDS.items():
        require(isinstance(tdx.get(field), str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", tdx[field]), f"active policy {name} has invalid tdx.{field}")
    runtime = policy.get("allowed_runtime")
    require(isinstance(runtime, dict) and "intel-tdx" in (runtime.get("tee") or []) and isinstance(runtime.get("minimum_gpu_count"), int) and runtime["minimum_gpu_count"] >= 1,
            f"active policy {name} has invalid hardware requirements")
    validate_receipt_keys(policy, name)
    require(manifest is not None and manifest.get("status") == "active", f"active policy {name} does not reference an active release")
    require(manifest.get("release") == policy.get("proxy_version"), f"active policy {name} and its release manifest name different proxy versions")


def main() -> int:
    documents = {}
    for folder in ("policies", "releases", "registry", "schema"):
        for path in sorted((ROOT / folder).glob("*.json")):
            if path.name.endswith(".sigstore.json"):
                continue
            documents[path] = load(path)
            no_private_material(documents[path], path.relative_to(ROOT).as_posix())

    models = documents.get(ROOT / "registry/models.json", {}).get("models", [])
    require(isinstance(models, list) and models, "registry must contain models")
    ids: set[str] = set()
    registered: set[str] = set()
    for model in models:
        require(isinstance(model, dict), "invalid registry model record")
        ident = model.get("id")
        require(isinstance(ident, str) and MODEL_ID.fullmatch(ident), f"invalid canonical model ID: {ident!r}")
        require(ident not in ids, f"duplicate model ID: {ident}")
        ids.add(ident)
        policy_path = repo_path(model.get("policy_ref"), directory="policies", label=f"policy ref for {ident}")
        require(load(policy_path).get("model_id") == ident, f"policy/model mismatch for {ident}")
        registered.add(policy_path.relative_to(ROOT).as_posix())

    require((ROOT / "policies/production.json").is_file(), "policies/production.json is missing")
    require("policies/production.json" in registered, "the model registry does not select policies/production.json")
    for path in sorted((ROOT / "policies").glob("*.json")):
        if not path.name.endswith(".sigstore.json") and isinstance(documents[path], dict) and "model_id" in documents[path]:
            validate_runtime_policy(path, registered)
    for path in sorted((ROOT / "releases").glob("attest-proxy-v*.json")):
        if not path.name.endswith(".sigstore.json"):
            validate_manifest(path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        print(f"registry validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
