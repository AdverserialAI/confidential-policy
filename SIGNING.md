# Signed policies

Every policy, release manifest, registry file and (when mirrored here)
deployment file that changes on `main` is signed by `.github/workflows/sign-policy.yml` with Sigstore keyless signing and
recorded in the public Rekor transparency log. There is no signing key to steal
or to lose: the signature proves "this exact file was on `main` of this
repository and the signing workflow ran on it", and the log makes every such
signature public.

The signed files and their bundles (`<file>.sigstore.json`) are published

* on the `signed` branch of this repository, at the same paths, and
* at `https://verify.adverserial.ai/<path>` and `<path>.sigstore.json`, byte for byte.

## Verify a policy yourself

```sh
curl -sSO https://verify.adverserial.ai/policies/production.json
curl -sSO https://verify.adverserial.ai/policies/production.json.sigstore.json
cosign verify-blob \
  --bundle production.json.sigstore.json \
  --certificate-identity https://github.com/AdverserialAI/confidential-policy/.github/workflows/sign-policy.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-trigger push \
  production.json
```

`Verified OK` means: the file is the one that was signed, the signing
certificate was issued by Sigstore to this repository's signing workflow on
`main`, and the signature is in the transparency log. ACK 0.2.15 and later run
the same check (`ack policy`) and additionally compare the log time with the
policy they accepted before, so that an old signed policy cannot be replayed.
ACK 0.2.15 reports the result and does not block; `ack policy enforce` makes it
refuse anything unsigned, and a later release enforces by default.

The same command works for any signed file, for example
`releases/attest-proxy-v0.1.0-rc.30.json` or `registry/models.json`. To check
the copy in this repository instead of the site:

```sh
git fetch origin signed
git show origin/signed:policies/production.json > production.json
git show origin/signed:policies/production.json.sigstore.json > production.json.sigstore.json
```

## How a policy is published

1. A pull request changes files under `policies/`, `releases/`, `registry/`.
   `Validate policy` must pass and a code owner must approve.
2. The merge to `main` starts `sign-policy`. Its `validate` job repeats the
   checks; its `sign` job then **waits for a reviewer of the `policy-signing`
   environment**. Nothing is signed until a person approves that run
   (Actions → the run → "Review deployments" → `policy-signing` → Approve).
   Read the diff of the commit before approving: approving is signing.
3. The `sign` job signs each changed file exactly as committed and verifies
   its own signatures the way a client does. The `publish` job puts the files
   and bundles on the `signed` branch.
4. The site is updated from the `signed` branch, never from a working copy
   (`update_policy_signed.py --attach-signatures`), and checked afterwards
   (`--verify-live`).

## Decisions that become permanent

These were made on 2026-11-24. They can be changed until clients enforce
signatures; after that, changing any of them locks clients out until they
upgrade.

- Signing repository and identity: this repository, the workflow file
  `.github/workflows/sign-policy.yml`, `refs/heads/main`, GitHub's OIDC issuer,
  the `push` trigger. Clients compare all of these, plus the numeric ids of the
  repository (`1404762635`) and the organization (`158311530`).
- Rollback protection uses the transparency log's time, not a counter inside
  the policy, plus a minimum compiled into each client release.
- The first signed policy is the pre-rotation `rc.30` policy (see README).

## What this does not prove

It does not prove the policy is *right*. A policy that pins a malicious
deployment can be signed like any other, by whoever can merge to `main` and
approve the signing environment. What signing adds is that such a policy cannot
be shown to one user and hidden from everyone else: it is in a public log, under
this identity, forever. Watch the log (the transparency repository runs a
monitor; anyone can run their own).

## Repository settings the signature relies on

The identity above is only as strong as control of `main`. These settings are
part of the security of every client and must not be relaxed:

1. Ruleset on `main`: pull request required, the `Validate policy` check
   required, no force pushes, no deletions. To add once there is a second
   maintainer: an approving review from a code owner, and no bypass for
   administrators. With one maintainer those two cannot both hold, and the
   honest statement is "the operator can sign, but not secretly".
2. `CODEOWNERS` covers `.github/`, `tools/`, `policies/`, `releases/`, `registry/`.
3. Environment `policy-signing`: a required reviewer (`lordx64`), deployment
   branches limited to `main`. A second reviewer who is not the author of the
   change should be added as soon as one exists.
4. Actions: only GitHub-authored and the pinned `sigstore/cosign-installer`
   action allowed; workflow default token permissions read-only; fork pull
   request workflows need approval.
5. Organization: two-factor authentication required for all members.
6. No other workflow in this repository requests `id-token: write`.

Renaming the repository, the workflow file or the branch changes the identity
and makes every client refuse new policies. Do it only with a client release.
