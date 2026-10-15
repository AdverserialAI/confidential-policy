#!/usr/bin/env python3
"""Fail-closed validation for public confidential-policy materials.

This guard intentionally validates every policy and every release manifest in
the repository, not just the files currently selected by the model registry.
An unreferenced document can still be copied by an SDK or a reviewer, so it
must not be allowed to make an unsupported active-runtime claim.
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
RELEASE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$")
IMAGE = re.compile(
    r"^ghcr\.io/adverserialai/"
    r"(?:attest-proxy|gpu-evidence-collector|model-measurer)@sha256:[0-9a-f]{64}$"
)
GITHUB_RUN = re.compile(
    r"^https://github\.com/AdverserialAI/attest-proxy/actions/runs/[1-9][0-9]*$"
)
SPKI = re.compile(r"^sha256:[A-Za-z0-9_-]{43}$")
REQUIRED_BINDINGS = {
    "fresh_client_nonce",
    "tdx_quote",
    "tdx_event_log",
    "tls_spki_der",
    "gpu_evidence",
    "report_data",
    "runtime_image_digest",
    "model_artifact_digest",
    "deployment_configuration_digest",
}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, message: str):
    if not condition:
        raise ValueError(message)


def repo_path(reference: object, *, directory: str, label: str) -> Path:
    """Resolve only a repository-local JSON document under ``directory``."""
    require(isinstance(reference, str), f"{label} must be a string")
    candidate = (ROOT / reference).resolve()
    root = ROOT.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository: {reference!r}") from exc
    expected_parent = (ROOT / directory).resolve()
    require(candidate.parent == expected_parent and candidate.suffix == ".json", f"invalid {label}: {reference!r}")
    require(candidate.is_file(), f"missing {label}: {reference!r}")
    return candidate


def validate_receipt_keys(policy: dict, model_id: str) -> None:
    keys = policy.get("receipt_keys")
    require(isinstance(keys, dict) and keys, f"active policy {model_id} has no receipt keys")
    for kid, key in keys.items():
        require(isinstance(kid, str) and kid, f"active policy {model_id} has invalid receipt key id")
        require(isinstance(key, dict), f"active policy {model_id} has invalid receipt key {kid!r}")
        require(key.get("kid") == kid, f"active policy {model_id} receipt key id mismatch")
        # A public registry must never carry private JWK material, including a
        # symmetric key ("k") masquerading as a verifier key.
        require("d" not in key and "k" not in key, f"active policy {model_id} exposes private receipt key material")
        require(key.get("use") == "sig", f"active policy {model_id} receipt key {kid!r} is not signing-only")
        require(key.get("kty") in {"EC", "OKP"}, f"active policy {model_id} receipt key {kid!r} has unsupported kty")
        require(isinstance(key.get("x"), str) and key["x"], f"active policy {model_id} receipt key {kid!r} lacks x")
        if key.get("kty") == "EC":
            require(key.get("crv") == "P-256" and key.get("alg") == "ES256", f"active policy {model_id} receipt key {kid!r} is not P-256/ES256")


def validate_manifest(path: Path) -> None:
    manifest = load(path)
    status = manifest.get("status")
    require(status in {"pre-activation", "active", "retired"}, f"invalid release state: {path.name}")
    release = manifest.get("release")
    require(isinstance(release, str) and RELEASE.fullmatch(release), f"invalid release name: {path.name}")
    require(path.name == f"attest-proxy-{release}.json", f"release file/name mismatch: {path.name}")

    source = manifest.get("source")
    require(isinstance(source, dict), f"missing source metadata: {path.name}")
    require(source.get("repository") == EXPECTED_SOURCE_REPOSITORY, f"unexpected source repository: {path.name}")
    require(source.get("tag") == release, f"release/source tag mismatch: {path.name}")
    require(isinstance(source.get("commit"), str) and COMMIT.fullmatch(source["commit"]), f"source commit must be a full SHA: {path.name}")

    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, f"release has no artifacts: {path.name}")
    names: set[str] = set()
    images: set[str] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict), f"invalid artifact record: {path.name}")
        name = artifact.get("name")
        image = artifact.get("image")
        require(isinstance(name, str) and name and name not in names, f"duplicate/invalid artifact name: {path.name}")
        require(isinstance(image, str) and IMAGE.fullmatch(image), f"un-pinned or unexpected artifact image: {path.name}")
        require(image not in images, f"duplicate artifact image: {path.name}")
        require(GITHUB_RUN.fullmatch(artifact.get("github_actions_run", "")) is not None, f"invalid GitHub Actions provenance URL: {path.name}")
        require(artifact.get("provenance") == "github-attestation", f"missing GitHub attestation: {path.name}")
        require(artifact.get("sbom") == "spdx", f"missing SPDX SBOM: {path.name}")
        names.add(name)
        images.add(image)

    missing = manifest.get("activation_missing")
    if status == "active":
        require(missing in (None, []), f"active release has unresolved activation requirements: {path.name}")
    else:
        require(isinstance(missing, list) and missing and all(isinstance(item, str) and item for item in missing), f"non-active release must state activation requirements: {path.name}")


def validate_active_policy(path: Path, policy: dict, model_id: str) -> None:
    for field in (
        "policy_id",
        "endpoint",
        "tls_spki_sha256",
        "receipt_keys",
        "evidence",
        "release_manifest",
        "runtime_image_digest",
        "model_artifact_digest",
        "deployment_configuration_digest",
    ):
        require(field in policy, f"active policy {model_id} missing {field}")
    bindings = policy.get("required_bindings")
    require(isinstance(bindings, list) and REQUIRED_BINDINGS.issubset(bindings), f"active policy {model_id} omits required hardware binding")
    for field in ("runtime_image_digest", "model_artifact_digest", "deployment_configuration_digest"):
        require(isinstance(policy.get(field), str) and SHA256.fullmatch(policy[field]), f"active policy {model_id} has invalid {field}")
    require(isinstance(policy.get("endpoint"), str) and policy["endpoint"].startswith("https://"), f"active policy {model_id} has invalid endpoint")
    require(isinstance(policy.get("tls_spki_sha256"), str) and SPKI.fullmatch(policy["tls_spki_sha256"]), f"active policy {model_id} has invalid TLS SPKI")
    validate_receipt_keys(policy, model_id)
    manifest_path = repo_path(policy["release_manifest"], directory="releases", label=f"release manifest for active policy {model_id}")
    manifest = load(manifest_path)
    require(manifest.get("status") == "active", f"active policy {model_id} references non-active release")


def validate_policy(path: Path, registered_policy_refs: set[str]) -> None:
    policy = load(path)
    status = policy.get("status")
    reference = path.relative_to(ROOT).as_posix()
    model_id = policy.get("model_id")
    require(isinstance(model_id, str) and MODEL_ID.fullmatch(model_id), f"invalid canonical model ID in {reference}")
    require(status in {"template-not-production", "active", "retired"}, f"invalid policy status in {reference}: {status!r}")
    release = policy.get("release")
    require(isinstance(release, dict) and release.get("source_repository") == EXPECTED_SOURCE_REPOSITORY, f"unexpected policy source in {reference}")
    if policy.get("release_manifest") is not None:
        repo_path(policy["release_manifest"], directory="releases", label=f"release manifest in {reference}")
    if status == "active":
        require(reference in registered_policy_refs, f"active policy is not selected by the model registry: {reference}")
        validate_active_policy(path, policy, model_id)
    elif status == "template-not-production":
        contract = policy.get("activation_contract")
        require(isinstance(contract, list) and contract and all(isinstance(item, str) and item for item in contract), f"template policy has no activation contract: {reference}")


def main() -> int:
    models = load(ROOT / "registry/models.json").get("models", [])
    require(isinstance(models, list) and models, "registry must contain models")
    ids: set[str] = set()
    registered_policy_refs: set[str] = set()
    for model in models:
        require(isinstance(model, dict), "invalid registry model record")
        ident = model.get("id")
        require(isinstance(ident, str) and MODEL_ID.fullmatch(ident), f"invalid canonical model ID: {ident!r}")
        require(ident not in ids, f"duplicate model ID: {ident}")
        ids.add(ident)
        policy_path = repo_path(model.get("policy_ref"), directory="policies", label=f"policy ref for {ident}")
        policy = load(policy_path)
        require(policy.get("model_id") == ident, f"policy/model mismatch for {ident}")
        registered_policy_refs.add(policy_path.relative_to(ROOT).as_posix())

    policy_paths = sorted((ROOT / "policies").glob("*.json"))
    require(policy_paths, "repository must contain at least one policy")
    for policy_path in policy_paths:
        validate_policy(policy_path, registered_policy_refs)
    for manifest_path in sorted((ROOT / "releases").glob("*.json")):
        validate_manifest(manifest_path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        print(f"registry validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
