# Releases

AgentHound releases are published on the
[GitHub Releases page](https://github.com/Yorji-Porji/AgentHound/releases). Each
release attaches a built **wheel** and **sdist**, and — for each — a Sigstore
signature bundle (`*.sigstore.json`).

## Provenance

Artifacts are signed in CI with **Sigstore keyless signing**. There is no
maintainer-held private key: the signing identity is the
[`release.yml`](../.github/workflows/release.yml) workflow's own GitHub Actions
OIDC token. A valid signature therefore proves an artifact was built by **this
repository's release workflow, at the tagged commit** — not re-uploaded,
re-built, or swapped by anyone else.

## Verifying a download

Install the [`sigstore`](https://pypi.org/project/sigstore/) client:

```bash
pip install sigstore
```

Download both the artifact and its matching `.sigstore.json` bundle from the
release, then verify (example for `v0.2.0`):

```bash
sigstore verify identity \
  --cert-identity "https://github.com/Yorji-Porji/AgentHound/.github/workflows/release.yml@refs/tags/v0.2.0" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  agenthound-0.2.0-py3-none-any.whl
```

`sigstore` looks for `agenthound-0.2.0-py3-none-any.whl.sigstore.json` next to
the file (or pass it explicitly with `--bundle`). Verification **succeeds only
if** the artifact was signed by this repo's release workflow for that exact tag.

For a later version, substitute the version in both the `--cert-identity` tag
ref and the artifact filename. Verify the sdist the same way by pointing at
`agenthound-<version>.tar.gz`.

## Cutting a release (maintainers)

1. Confirm `version` in `pyproject.toml` (and `agenthound.__version__`) is the
   version you intend to ship.
2. Publish a GitHub Release for the tag `v<version>` (e.g. `v0.2.0`) — via the
   GitHub UI or `gh release create v<version> --title v<version> --notes-file
   <notes>`.
3. Publishing the release triggers `release.yml`, which builds, signs, and
   attaches the wheel, sdist, and their `.sigstore.json` bundles. The workflow
   **fails fast** if the tag does not match the `pyproject.toml` version.
