# DevSecOps

Security scanning runs both in CI (GitHub Actions) and locally (`make`). All
tools print their reports to the console — SARIF upload is not used.

- [What runs](#what-runs)
- [GitHub Actions workflow](#github-actions-workflow)
- [Running the scans locally](#running-the-scans-locally)
- [Report-only vs gating](#report-only-vs-gating)
- [Handling findings](#handling-findings)

---

## What runs

| Scan | Tool | Scope |
|------|------|-------|
| Dependency vulnerabilities | [`pip-audit`](https://pypi.org/project/pip-audit/) | Installed Python dependencies vs the PyPA/OSV advisory DB |
| License compliance | [`pip-licenses`](https://pypi.org/project/pip-licenses/) | License of every dependency; flags copyleft/unknown |
| Python SAST | [`bandit`](https://bandit.readthedocs.io/) | Static analysis of `src/` |
| Dockerfile SAST / lint | [`hadolint`](https://github.com/hadolint/hadolint) | `Dockerfile` best practices and pitfalls |

---

## GitHub Actions workflow

The workflow lives at [`.github/workflows/devsecops.yml`](../.github/workflows/devsecops.yml)
and triggers on every push, every pull request, and manual dispatch. It has one
job per scan so failures are isolated and reports are easy to find:

- `dependency-scan` — installs the project, runs `pip-audit --desc`.
- `license-scan` — lists licenses and warns on `GPL|AGPL|LGPL|MPL|UNKNOWN`.
- `sast-bandit` — runs `bandit -r src/ -ll`.
- `dockerfile-lint` — runs the official `hadolint/hadolint-action`.

Each scan step is wrapped in a `::group::` so its output is collapsible in the
Actions log.

---

## Running the scans locally

The Python scanners are part of the `dev` extras, so `make install` already
installs them. For the Dockerfile scan, install `hadolint`
(`brew install hadolint`) or let the Makefile fall back to Docker.

```bash
source .venv/bin/activate
make security             # run all four scans
```

Or run them individually:

```bash
make security-deps        # pip-audit
make security-licenses    # pip-licenses + copyleft/unknown check
make security-sast        # bandit
make security-docker      # hadolint (local binary or Docker fallback)
```

See the [Makefile reference](makefile.md) for all targets.

---

## Report-only vs gating

The scans are **report-only for now**: in CI each scan step uses
`continue-on-error: true` (and hadolint uses `no-fail: true`), so findings are
surfaced without blocking merges.

To turn a scan into a hard gate, remove its `continue-on-error: true` (or set
hadolint's `no-fail: false`) in `.github/workflows/devsecops.yml`.

---

## Handling findings

- **False positives (bandit):** annotate the specific line with
  `# nosec <RULE_ID>` and a short justification. Example: the YARA scan path
  default `path="/tmp"` triggers `B108` but is a remote scan target, not a local
  temp file.
- **hadolint rules:** ignored rules live in [`.hadolint.yaml`](../.hadolint.yaml)
  with a documented reason. `DL3008`/`DL3013` (pin apt/pip versions) are ignored
  because pinning them breaks on routine point releases while dependency
  versions are already constrained in `pyproject.toml`.
- **Licenses:** `caio` reports `UNKNOWN` (its metadata omits the license; it is
  Apache-2.0 upstream) and `certifi` reports `MPL-2.0` — both are transitive and
  benign. Review any *new* copyleft/unknown entry before shipping.

---

Next: [Development](development.md) · [Security model](security.md) · [Makefile reference](makefile.md)
