#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<EOF
Usage:
  $0 osm     --query <json> [--threshold <int>] [--from <iso8601>] [--output <file>]
  $0 claude  --url <url> [--model <id>] [--threshold <int>] [--output <file>]
  $0 file    --path <file> [--threshold <int>] [--output <file>]

Sources:
  file    Read the package list from a local JSON file.
          --path       Path to a JSON array of {name, ecosystem, versions}.

  osm     Fetch the package list from the OpenSourceMalware feed.
          --query      JSON query body sent to the OSM search endpoint.
          --from       Only keep records whose updated_at is newer than this value (ISO 8601).

  claude  Fetch a URL and ask the Claude API to extract vulnerable packages.
          --url        URL to fetch (advisory page, blog, JSON feed, etc.).
          --model      Claude model ID (default: claude-opus-4-7).
          Requires ANTHROPIC_API_KEY in the environment.

Common options:
  --output <file>  Write the resulting JSON to <file> instead of stdout.
  --threshold  Minimum download_count for a package to be included.

EOF
    exit 1
}

[[ $# -lt 1 ]] && usage
SOURCE="$1"; shift

QUERY=""
DOWNLOAD_COUNT_THRESHOLD=""
PATH_INPUT=""
URL_INPUT=""
MODEL="claude-opus-4-7"
OUTPUT_FILE=""
FROM_INPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --query)     QUERY="$2"; shift 2 ;;
        --threshold) DOWNLOAD_COUNT_THRESHOLD="$2"; shift 2 ;;
        --url)       URL_INPUT="$2"; shift 2 ;;
        --model)     MODEL="$2"; shift 2 ;;
        --path)      PATH_INPUT="$2"; shift 2 ;;
        --output)    OUTPUT_FILE="$2"; shift 2 ;;
        --from)      FROM_INPUT="$2"; shift 2 ;;
        -h|--help)   usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

case "$SOURCE" in
    file)
        [[ -z "$PATH_INPUT" ]] && usage
        [[ ! -f "$PATH_INPUT" ]] && { echo "File not found: $PATH_INPUT" >&2; exit 1; }

        PACKAGE_VERSIONS=$(jq '.' "$PATH_INPUT")
        ;;
    osm)
        [[ -z "$QUERY" || -z "$DOWNLOAD_COUNT_THRESHOLD" || -z "$OSM_API_KEY" ]] && usage

        QUERY=$(echo "$QUERY" | jq '.page = (.page//1) | .limit = (.limit//100)')

        PACKAGE_VERSIONS="[]"
        PAGE=1
        TOTAL_PAGES=1

read -r -d '' JQ_CMD << 'EOM' || true
    [(.data//[])[] | 
     select(.status == "verified" and ($from == "" or (.verified_at[:19] + "Z" | fromdateiso8601) > ($from | fromdateiso8601)))] |
    group_by(.resource_identifier) |
    [
        .[] |
        {
            "name" : .[0].package_name,
            "ecosystem": .[0].registry,
            "versions": [.[].version_info],
            "download_count_total": .[0].download_count
        }
    ]
EOM

        while :; do
            PAGED_QUERY=$(echo "$QUERY" | jq --argjson p "$PAGE" '.page = $p')

            RESPONSE=$(curl -s 'https://zyqmpfcrijqmwyzbkubf.supabase.co/functions/v1/query-search' \
                        -H 'apikey: $OSM_API_KEY' \
                        -H 'authorization: Bearer $OSM_API_KEY' \
                        -H 'content-type: application/json' \
                        -H 'origin: https://opensourcemalware.com' \
                        -H 'referer: https://opensourcemalware.com/' \
                        -H 'x-client-info: supabase-js-web/2.56.0' \
                        --data-raw "$PAGED_QUERY")

            PAGE_DATA=$(echo "$RESPONSE" | jq --arg from "$FROM_INPUT" "$JQ_CMD")
            PACKAGE_VERSIONS=$(echo "[$PACKAGE_VERSIONS,$PAGE_DATA]" | jq '.[0] + .[1]')

            TOTAL_PAGES=$(echo "$RESPONSE" | jq -r '.totalPages // 1')
            [[ "$PAGE" -ge "$TOTAL_PAGES" ]] && break
            PAGE=$((PAGE + 1))
        done

        ;;

    file)
        [[ -z "$PATH_INPUT" ]] && usage
        [[ ! -f "$PATH_INPUT" ]] && { echo "File not found: $PATH_INPUT" >&2; exit 1; }

        PACKAGE_VERSIONS=$(jq '.' "$PATH_INPUT")
        ;;

    claude)
        [[ -z "$URL_INPUT" ]] && usage
        [[ -z "${ANTHROPIC_API_KEY:-}" ]] && { echo "ANTHROPIC_API_KEY env var is required" >&2; exit 1; }

        tmp_output=$(mktemp boost.XXXXXX)
        URL_CONTENT=$(curl -fsSL -o "$tmp_output" --max-time 60 "$URL_INPUT") \
                     || { echo "Failed to fetch URL: $URL_INPUT" >&2; exit 1; }

        JQ_CMD='{
                model: $model,
                max_tokens: 16000,
                system: "You are a security analyst. From the provided content, extract every vulnerable, malicious, or compromised software package referenced. Return strictly the structured JSON defined by the schema. The ecosystem must be the package registry name in lowercase (npm, pypi, maven, rubygems, nuget, go, packagist, cargo, etc.). If no vulnerable packages are present, return an empty array.",
                output_config: {
                    format: {
                        type: "json_schema",
                        schema: {
                            type: "object",
                            properties: {
                                packages: {
                                    type: "array",
                                    items: {
                                        type: "object",
                                        properties: {
                                            name:      {type: "string"},
                                            ecosystem: {type: "string"},
                                            versions:  {type: "array", items: {type: "string"}}
                                        },
                                        required: ["name", "ecosystem", "versions"],
                                        additionalProperties: false
                                    }
                                }
                            },
                            required: ["packages"],
                            additionalProperties: false
                        }
                    }
                },
                messages: [{
                    role: "user",
                    content: "Source URL: \($url)\n\nContent:\n\($content)"
                }]
            }'

        REQUEST_BODY_FILE=$(mktemp boost-request.XXXXXX)
        echo "{}" | jq \
            --arg model "$MODEL" \
            --arg url "$URL_INPUT" \
            --rawfile content "$tmp_output" \
            "$JQ_CMD" \
            > "$REQUEST_BODY_FILE"

        RESPONSE=$(curl -sS https://api.anthropic.com/v1/messages \
            -H "Content-Type: application/json" \
            -H "x-api-key: $ANTHROPIC_API_KEY" \
            -H "anthropic-version: 2023-06-01" \
            -d "@$REQUEST_BODY_FILE")

        if echo "$RESPONSE" | jq -e '.type == "error"' > /dev/null 2>&1; then
            echo "Claude API error:" >&2
            echo "$RESPONSE" | jq '.error' >&2
            exit 1
        fi

        EXTRACTED=$(echo "$RESPONSE" | jq -r 'first(.content[] | select(.type == "text") | .text)')
        [[ -z "$EXTRACTED" || "$EXTRACTED" == "null" ]] && { echo "No text content in Claude response" >&2; echo "$RESPONSE" >&2; exit 1; }

        PACKAGE_VERSIONS=$(echo "$EXTRACTED" | jq '.packages')
        ;;
    stdin)

        [[ -t 0 ]] && { echo "stdin source requires JSON input piped to standard input" >&2; exit 1; }
        PACKAGE_VERSIONS=$(jq '.') \
            || { echo "Failed to parse JSON from stdin" >&2; exit 1; }
        ;;

    *)
        usage
        ;;
esac

PKG_COUNT=$(echo "$PACKAGE_VERSIONS" | jq 'length')

# Enrich npm packages missing download_count_total / download_count_latest
# using the npmjs last-week per-version downloads endpoint.
for i in $(seq 0 $((PKG_COUNT - 1))); do
    [[ $PKG_COUNT -eq 0 ]] && break
    PKG=$(echo "$PACKAGE_VERSIONS" | jq ".[$i]")

    HAS_TOTAL=$(echo "$PKG" | jq 'has("download_count_total")')
    HAS_LATEST=$(echo "$PKG" | jq 'has("download_count_latest")')

    if [[ "$HAS_TOTAL" == "true" || "$HAS_LATEST" == "true" ]]; then
        continue
    fi

    ECOSYSTEM=$(echo "$PKG" | jq -r '.ecosystem')
    [[ "$ECOSYSTEM" != "npm" ]] && continue

    NAME=$(echo "$PKG" | jq -r '.name')
    ENCODED_NAME=$(jq -rn --arg n "$NAME" '$n | @uri')

    NPM_RESPONSE=$(curl -sS "https://api.npmjs.org/versions/$ENCODED_NAME/last-week") || continue
    echo "$NPM_RESPONSE" | jq -e '.downloads' > /dev/null 2>&1 || continue

    TOTAL=$(echo "$NPM_RESPONSE" | jq '[.downloads | to_entries[].value] | add // 0')
    LATEST=$(echo "$NPM_RESPONSE" | jq '
        .downloads | to_entries
        | if length == 0 then 0
          else (max_by(.key | split(".") | map(tonumber? // 0)) | .value)
          end
    ')

    PKG=$(echo "$PKG" | jq \
        --argjson total "$TOTAL" \
        --argjson latest "$LATEST" \
        '. + {download_count_total: $total, download_count_latest: $latest}')
    PACKAGE_VERSIONS=$(echo "$PACKAGE_VERSIONS" | jq --argjson id "$i" --argjson p "$PKG" '.[$id] = $p')
done

if [[ -n "$DOWNLOAD_COUNT_THRESHOLD" ]]; then
    PACKAGE_VERSIONS=$(echo "$PACKAGE_VERSIONS" | jq --argjson count "$DOWNLOAD_COUNT_THRESHOLD" -r '[.[] | select(.download_count_total >= $count)]')
fi

echo "$PACKAGE_VERSIONS"

exit 0

# Check each package against the OSV.dev database (POST /v1/query).
for i in $(seq 0 $((PKG_COUNT - 1))); do
    [[ $PKG_COUNT -eq 0 ]] && break
    PKG=$(echo "$PACKAGE_VERSIONS" | jq ".[$i]")
    NAME=$(echo "$PKG" | jq -r '.name')
    ECOSYSTEM=$(echo "$PKG" | jq -r '.ecosystem')

    FOUND_VULN=false
    VULNC_COUNT=$(echo "$PKG" | jq -r '.vulns | length')
    if [[ "$VULNC_COUNT" -gt 0 ]]; then
        continue
    fi

    while IFS= read -r VERSION; do
        [[ -z "$VERSION" ]] && continue
        OSV_BODY=$(jq -n --arg n "$NAME" --arg e "$ECOSYSTEM" --arg v "$VERSION" \
            '{package: {name: $n, ecosystem: $e}, version: $v}')
        OSV_RESPONSE=$(curl -sS -X POST https://api.osv.dev/v1/query \
            -H 'Content-Type: application/json' \
            -d "$OSV_BODY") || continue        
        
        VULN_IDS=$(echo "$OSV_RESPONSE" | jq '[(.vulns // [])[] | .id]')
        if [[ "$VULN_IDS" != "[]" ]]; then
            PKG=$(echo "$PKG" | jq --argjson vuls "$VULN_IDS" '. + {vulns: $vuls}')
            PACKAGE_VERSIONS=$(echo "$PACKAGE_VERSIONS" | jq --argjson id "$i" --argjson p "$PKG" '.[$id] = $p')
            break
        fi
    done < <(echo "$PKG" | jq -r '.versions[]')
done


if [[ -n "$OUTPUT_FILE" ]]; then
    printf '%s\n' "$PACKAGE_VERSIONS" > "$OUTPUT_FILE"
else
    echo "$PACKAGE_VERSIONS"
fi
