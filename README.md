# Adverserial confidential policy registry

> **This repository is the signed source of the published verification policy.**
> The files under `policies/`, `releases/`, `registry/` and `schema/` are the
> ones served at <https://verify.adverserial.ai>, byte for byte. Every change
> to them on `main` is signed by this repository's GitHub Actions workflow with
> Sigstore keyless signing and recorded in the public Rekor transparency log.
> The signed files and their signature bundles are on the
> [`signed` branch](../../tree/signed). See [SIGNING.md](SIGNING.md).

Until 2026-11-24 this repository was an outdated mirror and the policy was
served unsigned from the website's own source. That is reversed: a policy
change now starts here, is reviewed here, is signed here, and only then is
copied to the site.

## Status on 2026-11-24

- The content was synchronised with the site on 2026-11-24 from the files the
  site was serving at that moment.
- **The first signed policy is the pre-rotation policy.** `policies/production.json`
  is the policy for proxy release `v0.1.0-rc.30`, published 2026-11-19, exactly
  as it was already being served. It is signed first so that the whole
  pipeline exists before the next policy needs it. It still says
  `trust.policy_distribution: "https-origin"` because its bytes were not
  changed.
- The service was moved to proxy release `v0.1.0-rc.33` on a new OS image on
  2026-11-24. The policy for that deployment can only be generated from a live
  attestation of it; it will be published through this repository, with the
  signed distribution declared, once that attestation has been verified. Until
  then the published policy describes `rc.30` and does not match the running
  deployment.
- Clients: ACK 0.2.15 checks the signature and reports the result without
  blocking; enforcement comes in a later release. Whether a signature exists
  for the policy the site serves right now is what `ack policy` and the
  `cosign` command in [SIGNING.md](SIGNING.md) tell you; do not take it from
  this page.

## What a signature means, and what it does not

- It means: these exact bytes were on `main` of this repository, the signing
  workflow ran on them after a named person approved the run, and that fact is
  in a public, append-only log under one identity.
- It does not mean the policy is right. Whoever can merge to `main` and approve
  the signing environment can sign a policy for a different deployment. Signing
  makes that public and attributable; it does not make it impossible. It is
  only useful if the log is watched.
  [`cyberseek-transparency`](https://github.com/AdverserialAI/cyberseek-transparency)
  runs a monitor for this identity; anyone can run their own.
- Measurements in the policy are approved by the operator from a deployment
  snapshot. A client still verifies fresh hardware evidence itself before
  sending anything confidential.
- Inference receipts are signed separately (ES256), with a key the policy pins.
- Release manifests record image digests and the GitHub Actions run that built
  them, with GitHub build provenance and an SBOM. They do not show that the
  images can be rebuilt bit for bit.

## What is here

- `policies/production.json` — the policy clients enforce for
  `adverserial/cyberseek`. Other files in `policies/` are for other services
  or earlier models.
- `releases/` — one manifest per proxy release, and `index.json`.
- `registry/` — the model and node registries.
- `schema/` — JSON schemas for the documents above.
- `deployments/` — not present yet. Deployment files (compose, app manifest)
  are published and attested in `cyberseek-transparency`; if they are mirrored
  here they are signed by the same workflow.
- `tools/validate_registry.py` — the fail-closed check that runs before
  anything is signed: documents are well formed and consistent with each
  other, the enforced policy has every pin, and nothing contains private key
  material. `tools/policy_release_check.py` decides which files a push signs.
- `.github/workflows/sign-policy.yml` — the signing workflow.
- `site/` — a landing-page snapshot from October 2026, kept as history.

This repository contains no credentials, private keys or model weights. The
policy does contain the deployment's measurements and digests: they are public
by design, because clients compare hardware evidence with them.

## Model identifiers

Every model ID is canonical and fully qualified, `publisher/model`. Policy,
attestation, metering, receipts and model discovery use the exact identifier.
The model in production is `adverserial/cyberseek`. `lordx64/cyberglm` and
`lordx64/cyberkimi` are earlier identifiers that still appear in older files.

## Security

Please report security vulnerabilities privately to [security@adverserial.ai](mailto:security@adverserial.ai). Do not open a public issue for a suspected vulnerability.

## License

This repository is source-available proprietary software owned by Adverserial
AI LLC. See [`LICENSE`](./LICENSE) and [`LICENSING.md`](./LICENSING.md).
Third-party components retain their own terms.
