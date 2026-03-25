#!/usr/bin/env bash
# SBOMly GitHub Action - Scan manifest, download SARIF, set outputs
set -euo pipefail

API_URL="${SBOMLY_API_URL:-https://api.sbomly.com}"
API_KEY="${SBOMLY_API_KEY:?Error: SBOMLY_API_KEY is required}"
MANIFEST_PATH="${SBOMLY_MANIFEST_PATH:-}"
FAIL_ON="${SBOMLY_FAIL_ON_SEVERITY:-none}"
SARIF_FILE="sbomly-results.sarif"

# --- Helper functions ---

log() { echo "::group::$1"; }
endlog() { echo "::endgroup::"; }

die() {
    echo "::error::$1"
    exit 1
}

# --- Find manifest file ---

find_manifest() {
    if [[ -n "$MANIFEST_PATH" && -f "$MANIFEST_PATH" ]]; then
        echo "$MANIFEST_PATH"
        return
    fi

    # Auto-detect in priority order
    local manifests=(
        "package-lock.json"
        "package.json"
        "yarn.lock"
        "pnpm-lock.yaml"
        "requirements.txt"
        "Pipfile.lock"
        "pyproject.toml"
        "go.mod"
        "Cargo.lock"
        "Cargo.toml"
        "Gemfile.lock"
        "composer.lock"
        "pom.xml"
        "build.gradle"
        "packages.config"
    )

    for m in "${manifests[@]}"; do
        if [[ -f "$m" ]]; then
            echo "$m"
            return
        fi
    done

    die "No manifest file found. Specify one with manifest-path input."
}

# --- Detect manifest type ---

detect_type() {
    local file="$1"
    local basename
    basename=$(basename "$file")

    case "$basename" in
        package.json)       echo "package.json" ;;
        package-lock.json)  echo "package-lock.json" ;;
        yarn.lock)          echo "yarn.lock" ;;
        pnpm-lock.yaml)     echo "package.json" ;;
        requirements.txt)   echo "requirements.txt" ;;
        Pipfile.lock|Pipfile) echo "requirements.txt" ;;
        pyproject.toml)     echo "requirements.txt" ;;
        go.mod)             echo "go.mod" ;;
        Cargo.toml|Cargo.lock) echo "Cargo.toml" ;;
        Gemfile.lock)       echo "Gemfile.lock" ;;
        composer.json|composer.lock) echo "composer.json" ;;
        pom.xml)            echo "pom.xml" ;;
        build.gradle|build.gradle.kts) echo "pom.xml" ;;
        packages.config)    echo "requirements.txt" ;;
        *)                  echo "unknown" ;;
    esac
}

# --- Main ---

log "SBOMly Scan"
echo "API URL: $API_URL"

# Find and read manifest
MANIFEST=$(find_manifest)
MANIFEST_TYPE=$(detect_type "$MANIFEST")
echo "Manifest: $MANIFEST (type: $MANIFEST_TYPE)"

MANIFEST_CONTENT=$(cat "$MANIFEST")

# Submit scan
log "Submitting scan to SBOMly"
SCAN_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST "${API_URL}/api/v1/manifest/upload" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: ${API_KEY}" \
    -d "$(jq -n \
        --arg content "$MANIFEST_CONTENT" \
        --arg type "$MANIFEST_TYPE" \
        '{manifest_content: $content, manifest_type: $type}')" \
    2>&1) || true

HTTP_CODE=$(echo "$SCAN_RESPONSE" | tail -1)
BODY=$(echo "$SCAN_RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" != "201" ]]; then
    die "Scan submission failed (HTTP $HTTP_CODE): $BODY"
fi

SCAN_ID=$(echo "$BODY" | jq -r '.scan_id')
echo "Scan ID: $SCAN_ID"
endlog

# Poll for completion
log "Waiting for scan to complete"
MAX_WAIT=300  # 5 minutes
ELAPSED=0
POLL_INTERVAL=5

while [[ $ELAPSED -lt $MAX_WAIT ]]; do
    STATUS_RESPONSE=$(curl -s \
        "${API_URL}/api/v1/scans/${SCAN_ID}/status" \
        -H "X-API-Key: ${API_KEY}" \
        2>&1) || true

    STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status')
    PROGRESS=$(echo "$STATUS_RESPONSE" | jq -r '.progress // 0')
    MESSAGE=$(echo "$STATUS_RESPONSE" | jq -r '.message // "Processing..."')

    echo "[$PROGRESS%] $MESSAGE"

    if [[ "$STATUS" == "completed" ]]; then
        break
    fi

    if [[ "$STATUS" == "failed" ]]; then
        die "Scan failed: $MESSAGE"
    fi

    sleep "$POLL_INTERVAL"
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

if [[ "$STATUS" != "completed" ]]; then
    die "Scan timed out after ${MAX_WAIT}s"
fi
endlog

# Extract results
VULN_COUNT=$(echo "$STATUS_RESPONSE" | jq -r '.critical_count + .high_count + .medium_count + .low_count + .negligible_count')
CRITICAL=$(echo "$STATUS_RESPONSE" | jq -r '.critical_count // 0')
HIGH=$(echo "$STATUS_RESPONSE" | jq -r '.high_count // 0')
MEDIUM=$(echo "$STATUS_RESPONSE" | jq -r '.medium_count // 0')
LOW=$(echo "$STATUS_RESPONSE" | jq -r '.low_count // 0')
COMPONENT_COUNT=$(echo "$STATUS_RESPONSE" | jq -r '.component_count // 0')
EOL_COUNT=$(echo "$STATUS_RESPONSE" | jq -r '.eol_count // 0')

echo ""
echo "=== SBOMly Scan Results ==="
echo "Components: $COMPONENT_COUNT"
echo "Vulnerabilities: $VULN_COUNT (Critical: $CRITICAL, High: $HIGH, Medium: $MEDIUM, Low: $LOW)"
echo "EOL Components: $EOL_COUNT"
echo "=========================="

# Download SARIF
log "Downloading SARIF report"
curl -s \
    "${API_URL}/api/v1/scans/${SCAN_ID}/sarif" \
    -H "X-API-Key: ${API_KEY}" \
    -o "$SARIF_FILE" 2>&1

if [[ -f "$SARIF_FILE" ]]; then
    SARIF_RULES=$(jq '.runs[0].tool.driver.rules | length' "$SARIF_FILE" 2>/dev/null || echo "0")
    SARIF_RESULTS=$(jq '.runs[0].results | length' "$SARIF_FILE" 2>/dev/null || echo "0")
    echo "SARIF: $SARIF_RULES rules, $SARIF_RESULTS results"
else
    echo "::warning::SARIF download failed"
fi
endlog

# Set outputs (for GitHub Actions)
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "scan-id=$SCAN_ID" >> "$GITHUB_OUTPUT"
    echo "vulnerability-count=$VULN_COUNT" >> "$GITHUB_OUTPUT"
    echo "critical-count=$CRITICAL" >> "$GITHUB_OUTPUT"
    echo "high-count=$HIGH" >> "$GITHUB_OUTPUT"
    echo "sarif-file=$SARIF_FILE" >> "$GITHUB_OUTPUT"
fi

# Set summary (for GitHub Actions)
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    cat >> "$GITHUB_STEP_SUMMARY" <<EOF
## SBOMly Scan Results

| Metric | Count |
|--------|-------|
| Components | $COMPONENT_COUNT |
| Vulnerabilities | $VULN_COUNT |
| Critical | $CRITICAL |
| High | $HIGH |
| Medium | $MEDIUM |
| Low | $LOW |
| EOL Components | $EOL_COUNT |

[View full report](${API_URL}/scan/${SCAN_ID})
EOF
fi

# Fail on severity threshold
if [[ "$FAIL_ON" != "none" ]]; then
    SHOULD_FAIL=0
    case "$FAIL_ON" in
        critical) [[ "$CRITICAL" -gt 0 ]] && SHOULD_FAIL=1 ;;
        high)     [[ "$CRITICAL" -gt 0 || "$HIGH" -gt 0 ]] && SHOULD_FAIL=1 ;;
        medium)   [[ "$CRITICAL" -gt 0 || "$HIGH" -gt 0 || "$MEDIUM" -gt 0 ]] && SHOULD_FAIL=1 ;;
        low)      [[ "$VULN_COUNT" -gt 0 ]] && SHOULD_FAIL=1 ;;
    esac

    if [[ "$SHOULD_FAIL" -eq 1 ]]; then
        die "Vulnerabilities found at or above '$FAIL_ON' severity threshold"
    fi
fi

echo "SBOMly scan complete."
