# Adverserial confidential policy registry

This repository contains public, model- and hardware-agnostic policy schemas and release policy templates. It intentionally contains no CVM IDs, cloud instance IDs, internal gateway hostnames, model weights, private network addresses, credentials, or unverified production digests.

A production policy becomes `active` only when it pins the immutable model artifact, runtime image, deployment configuration, trusted verifier keys, and signed provenance. Clients must reject `template-not-production` policies.

Adding a model or node is a policy/release operation: publish a reviewed policy, signed manifest, provenance, and allowed evidence requirements. No SDK or proxy fork is required.

## Model identifiers

Every model ID is canonical and fully qualified: `publisher/model`, for
example `lordx64/cyberglm` and `lordx64/cyberkimi`. Policy, attestation,
metering, receipts, and model discovery use this exact identifier. A gateway
may translate a legacy short name before the request enters the confidential
boundary, but a short name is never a public or attested identifier.
