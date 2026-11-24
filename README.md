# Adverserial confidential policy registry

> **This repository is not the live policy source and is out of date.**
> The policy, model registry, node registry and release manifests that clients
> verify against are published at **<https://verify.adverserial.ai>**:
>
> - policy: <https://verify.adverserial.ai/policies/production.json>
> - release manifests: <https://verify.adverserial.ai/releases/index.json>
> - registries: <https://verify.adverserial.ai/registry/models.json>,
>   <https://verify.adverserial.ai/registry/nodes.json>
>
> Those files are deployed from the website's own source, which is not a public
> GitHub repository. Nothing here is copied to the site automatically. This
> repository was last updated on 2026-10-17 and is kept as history: schemas, a
> validator, and pre-activation templates for an earlier model.

## How this repository differs from what is published

| | In this repository | Published at verify.adverserial.ai |
| --- | --- | --- |
| Model | `lordx64/cyberglm` | `adverserial/cyberseek` |
| `policies/production.json` | `template-not-production`, pins from `attest-proxy` `rc.17` | `active` |
| Release manifests | `rc.2` to `rc.28`, all `pre-activation` | Up to `rc.30` |
| Node registry | Empty | Lists the production inference node |
| `site/index.html` | Says confidential inference "is not active yet" | Not this page; the site is built elsewhere |

The proxy release deployed on 2026-11-24 is `v0.1.0-rc.33`. Its policy has not
been published yet: the status is "rolled out 2026-11-24, policy update
pending first live attestation". Until that update the published policy still
describes `rc.30`. The Docker Compose file of the current deployment is
documented in
[confidential-infra `deployed/`](https://github.com/AdverserialAI/confidential-infra/tree/main/deployed).

## What the published policy is, and is not

- It is a JSON document served over HTTPS. **It is not signed**: the published
  file states `trust.policy_distribution: "https-origin"` and
  `trust.detached_policy_signature: false`. Earlier text in this repository
  spoke of a "signed policy" and "signed manifest"; that was a goal, not
  something that exists.
- Inference receipts *are* signed (ES256), with a key the policy pins.
- Release manifests record image digests and the GitHub Actions run that built
  them, with GitHub build provenance and an SBOM. They do not show that the
  images can be rebuilt bit for bit.
- Measurements in the published policy are approved by the operator from a
  deployment snapshot. A client still has to verify fresh hardware evidence
  itself before sending anything confidential.
- A separate public repository, `AdverserialAI/cyberseek-transparency`, is
  being published with an independent Python verifier and a hash-chained
  attestation history.

## What is here

- `schema/` — JSON schemas for runtime policies and release manifests.
- `policies/` — templates for `lordx64/cyberglm`, marked
  `template-not-production`. Clients must reject them.
- `releases/` — pre-activation manifests for `attest-proxy` `rc.2` to `rc.28`.
- `registry/`, `site/` — a snapshot of the registry and landing page from
  October 2026.
- `tools/validate_registry.py` — the fail-closed validator CI runs over every
  policy and manifest in this repository. It rejects an `active` policy that
  lacks measured runtime, model, TLS, receipt-key, evidence or release
  bindings.

This repository contains no CVM IDs, credentials, model weights or live
deployment digests.

## Model identifiers

Every model ID is canonical and fully qualified, `publisher/model`. Policy,
attestation, metering, receipts and model discovery use the exact identifier.
The model in production is `adverserial/cyberseek`. `lordx64/cyberglm` and
`lordx64/cyberkimi`, used in the files here, are earlier identifiers.

## Security

Please report security vulnerabilities privately to [security@adverserial.ai](mailto:security@adverserial.ai). Do not open a public issue for a suspected vulnerability.

## License

This repository is source-available proprietary software owned by Adverserial
AI LLC. See [`LICENSE`](./LICENSE) and [`LICENSING.md`](./LICENSING.md).
Third-party components retain their own terms.
