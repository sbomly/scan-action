# SBOMly Scan Action

Generate an SBOM, scan for vulnerabilities, and upload results to GitHub Code Scanning -- in one step.

## Quick Start

```yaml
name: SBOMly Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: sbomly/scan-action@v1
        with:
          api-key: ${{ secrets.SBOMLY_API_KEY }}
```

## Setup

1. Sign up at [my.sbomly.com](https://my.sbomly.com)
2. Go to your profile and create an API key
3. Add the key as a repository secret named `SBOMLY_API_KEY`
4. Add the workflow file above to `.github/workflows/sbomly.yml`

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | Yes | -- | SBOMly API key |
| `api-url` | No | `https://my.sbomly.com` | API base URL |
| `manifest-path` | No | Auto-detect | Path to manifest file |
| `fail-on-severity` | No | `none` | Fail if vulns at this severity or higher (`critical`, `high`, `medium`, `low`, `none`) |

## Outputs

| Output | Description |
|--------|-------------|
| `scan-id` | SBOMly scan ID |
| `vulnerability-count` | Total vulnerabilities found |
| `critical-count` | Critical vulnerabilities |
| `high-count` | High vulnerabilities |
| `sarif-file` | Path to SARIF file |

## Supported Manifest Files

Auto-detected in order: package-lock.json, package.json, yarn.lock, pnpm-lock.yaml, requirements.txt, Pipfile.lock, pyproject.toml, go.mod, Cargo.lock, Gemfile.lock, composer.lock, pom.xml, build.gradle, packages.config.

## Features

- SBOM generation (CycloneDX via Syft)
- Vulnerability scanning (Grype + OSV dual-scanner)
- EPSS exploit probability scores
- CISA KEV status
- Automated fix commands
- End-of-life component detection
- Regulatory compliance scoring (NTIA, EU CRA, EO 14028)
- SARIF upload to GitHub Code Scanning
- Configurable severity thresholds
- Job summary with scan results table

## Examples

### Fail on critical vulnerabilities

```yaml
- uses: sbomly/scan-action@v1
  with:
    api-key: ${{ secrets.SBOMLY_API_KEY }}
    fail-on-severity: critical
```

### Scan a specific manifest

```yaml
- uses: sbomly/scan-action@v1
  with:
    api-key: ${{ secrets.SBOMLY_API_KEY }}
    manifest-path: backend/requirements.txt
```

### Use outputs in later steps

```yaml
- uses: sbomly/scan-action@v1
  id: sbomly
  with:
    api-key: ${{ secrets.SBOMLY_API_KEY }}

- name: Check results
  run: |
    echo "Found ${{ steps.sbomly.outputs.vulnerability-count }} vulnerabilities"
    echo "Critical: ${{ steps.sbomly.outputs.critical-count }}"
```
