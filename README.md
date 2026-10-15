# Adverserial confidential policy registry

This repository contains public, model- and hardware-agnostic policy schemas and pre-activation release templates. It intentionally contains no CVM IDs, cloud instance IDs, internal gateway hostnames, model weights, private network addresses, credentials, or live production deployment digests.

A production policy becomes `active` only when it pins the immutable model artifact, runtime image, deployment configuration, trusted verifier keys, and signed provenance. Clients must reject `template-not-production` policies. This repository deliberately contains no active policy: `policies/production.json` is a historical template and is not a source of runtime trust. The release manifests pin image digests before activation; CI rejects an active policy missing measured runtime, model, TLS, receipt-key, evidence, or release bindings. Fetch the live policy and evidence from `https://verify.adverserial.ai` only after independently validating its signed release and fresh hardware evidence.

Adding a model or node is a policy/release operation: publish a reviewed policy, signed manifest, provenance, and allowed evidence requirements. No SDK or proxy fork is required.

## Model identifiers

Every model ID is canonical and fully qualified: `publisher/model`, for
example `lordx64/cyberglm` and `lordx64/cyberkimi`. Policy, attestation,
metering, receipts, and model discovery use this exact identifier. A gateway
may translate a legacy short name before the request enters the confidential
boundary, but a short name is never a public or attested identifier.

## Security

Please report security vulnerabilities privately to [security@adverserial.ai](mailto:security@adverserial.ai). Do not open a public issue for a suspected vulnerability.

## License

This repository is source-available proprietary software owned by Adverserial
AI LLC. See [`LICENSE`](./LICENSE) and [`LICENSING.md`](./LICENSING.md).
Third-party components retain their own terms.
