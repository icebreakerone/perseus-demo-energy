#!/usr/bin/env bash
#
# Refresh every certificate used by the local development stack.
#
# Client and signing certificates are issued by the real sandbox directory
# service, so local testing exercises the same identities, roles and CA chains
# as production. Only the localhost server certificate is generated locally,
# because no directory will issue a certificate for localhost.
#
# Run ./scripts/refresh-certs.sh --help for usage.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; GREEN=$'\033[32m'; RESET=$'\033[0m'
else
  BOLD=''; RED=''; YELLOW=''; GREEN=''; RESET=''
fi

info() { printf '%s\n' "$*"; }
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }
warn() { printf '%sWarning:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()  { printf '%sError:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Defaults and configuration
# ---------------------------------------------------------------------------

DIRECTORY_API_URL="${DIRECTORY_API_URL:-}"
DIRECTORY_COGNITO_DOMAIN="${DIRECTORY_COGNITO_DOMAIN:-}"
DIRECTORY_COGNITO_CLIENT_ID="${DIRECTORY_COGNITO_CLIENT_ID:-}"
CAP_APP_ID="${CAP_APP_ID:-}"
CAP_ORGANIZATION="${CAP_ORGANIZATION:-}"
EDP_APP_ID="${EDP_APP_ID:-}"
EDP_ORGANIZATION="${EDP_ORGANIZATION:-}"
REVOKE_PREVIOUS="${REVOKE_PREVIOUS:-false}"

# The role the resource API requires of a CAP client certificate. Must match
# PROVIDER_ROLE in resource/api/conf.py, which is derived from SCHEME_BASE_URL.
SCHEME_BASE_URL="${SCHEME_BASE_URL:-https://registry.core.sandbox.trust.ib1.org/scheme/perseus}"
CAP_ROLE="$SCHEME_BASE_URL/role/carbon-accounting-provider"
EDP_ROLE="$SCHEME_BASE_URL/role/energy-data-provider"

ROTATE_JWT=false
RESTART=false
DRY_RUN=false
LIST_ONLY=false

# Anything the caller exported wins over the config file, so record what was
# already set before sourcing it. Written without associative arrays, because
# macOS ships bash 3.2.
CONFIG_VARS="DIRECTORY_API_URL DIRECTORY_COGNITO_DOMAIN DIRECTORY_COGNITO_CLIENT_ID
CAP_APP_ID CAP_ORGANIZATION EDP_APP_ID EDP_ORGANIZATION REVOKE_PREVIOUS"

for var in $CONFIG_VARS; do
  eval "PRESET_$var=\${$var:-}"
done

CONFIG_FILE="$SCRIPT_DIR/refresh-certs.env"
if [[ -f "$CONFIG_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
  set +a
fi

for var in $CONFIG_VARS; do
  eval "preset=\${PRESET_$var}"
  [[ -n "$preset" ]] && eval "$var=\$preset"
done
unset preset

usage() {
  cat <<'EOF'
Usage: ./scripts/refresh-certs.sh [options]

Refreshes every certificate the local development stack uses. Client and
signing certificates come from the sandbox directory service; the localhost
server certificate is generated locally with openssl.

Options:
  --cap-app ID          CAP application identifier (cap-demo's identity)
  --edp-app ID          EDP application identifier (the resource API's identity)
  --cap-org ID          Organisation owning the CAP application
  --edp-org ID          Organisation owning the EDP application
  --list-apps           List your organisations and applications, then exit
  --rotate-jwt-key      Regenerate the JWT signing key. This invalidates every
                        issued access token. Off by default.
  --revoke-previous     Revoke the certificates the last run issued
  --restart             Restart the nginx containers when finished
  --dry-run             Print what would happen, write nothing
  -h, --help            Show this message

Configuration is read from scripts/refresh-certs.env. See
scripts/refresh-certs.env.example. Exported environment variables take
precedence over that file, and these options take precedence over both.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cap-app) CAP_APP_ID="${2:?--cap-app needs a value}"; shift 2 ;;
    --edp-app) EDP_APP_ID="${2:?--edp-app needs a value}"; shift 2 ;;
    --cap-org) CAP_ORGANIZATION="${2:?--cap-org needs a value}"; shift 2 ;;
    --edp-org) EDP_ORGANIZATION="${2:?--edp-org needs a value}"; shift 2 ;;
    --list-apps) LIST_ONLY=true; shift ;;
    --rotate-jwt-key) ROTATE_JWT=true; shift ;;
    --revoke-previous) REVOKE_PREVIOUS=true; shift ;;
    --restart) RESTART=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "Unknown option: $1" ;;
  esac
done

export DIRECTORY_API_URL DIRECTORY_COGNITO_DOMAIN DIRECTORY_COGNITO_CLIENT_ID

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

step "Checking prerequisites"

for cmd in directory openssl unzip jq; do
  command -v "$cmd" >/dev/null || die "$cmd is not on PATH."
done

# macOS ships LibreSSL as /usr/bin/openssl, which does not support -addext.
# The localhost certificate needs it to carry a SubjectAltName.
if ! openssl version | grep -q '^OpenSSL 3'; then
  die "openssl is $(openssl version), but OpenSSL 3.x is required.
Install it and put it first on PATH, for example:
  brew install openssl@3 && export PATH=\"\$(brew --prefix openssl@3)/bin:\$PATH\""
fi

[[ -n "$DIRECTORY_API_URL" ]] || die "DIRECTORY_API_URL is not set. Copy scripts/refresh-certs.env.example to scripts/refresh-certs.env."
[[ -n "$DIRECTORY_COGNITO_CLIENT_ID" ]] || die "DIRECTORY_COGNITO_CLIENT_ID is not set. See scripts/refresh-certs.env.example."

login_help() {
  cat <<EOF >&2

Not authenticated to the directory at $DIRECTORY_API_URL.

Log in, then run this script again:

  export DIRECTORY_API_URL=$DIRECTORY_API_URL
  export DIRECTORY_COGNITO_DOMAIN=$DIRECTORY_COGNITO_DOMAIN
  export DIRECTORY_COGNITO_CLIENT_ID=$DIRECTORY_COGNITO_CLIENT_ID
  directory login

The cached token is stored per Cognito client id, so a token for another
environment does not work here.
EOF
}

# The directory CLI raises an uncaught exception on an expired refresh token and
# prints "API error: <code>" for everything else. Tell the two apart, so a wrong
# DIRECTORY_API_URL is not reported as a login problem.
if ORGS_RAW="$(directory --json me orgs 2>&1)"; then
  ORGS_JSON="$ORGS_RAW"
else
  if [[ "$ORGS_RAW" == *"API error"* ]]; then
    die "The directory at $DIRECTORY_API_URL rejected the request.

$(printf '%s' "$ORGS_RAW" | grep -v '^ *<' | head -3)

Check DIRECTORY_API_URL in $CONFIG_FILE."
  fi
  login_help
  exit 3
fi

# Both list endpoints wrap their results, and an application is identified by a
# URL whose last segment is the identifier the other commands take.
orgs_list() { jq -r '(.organizations // .)[] | .identifier' <<<"$ORGS_JSON"; }

org_name() {
  jq -r --arg id "$1" '(.organizations // .)[] | select(.identifier == $id)
    | (.legalName // .name // .title // "unknown")' <<<"$ORGS_JSON" 2>/dev/null
}

apps_in_org() { directory --json --organization "$1" apps list --scheme perseus 2>/dev/null; }

app_ids() {  # reads an apps list on stdin, optionally filtered by role in $1
  if [[ -n "${1:-}" ]]; then
    jq -r --arg role "$1" '(.applications // .)[]
      | select(((.role // .roles // []) | index($role)) != null)
      | .id | split("/") | last'
  else
    jq -r '(.applications // .)[] | .id | split("/") | last'
  fi
}

if [[ "$LIST_ONLY" == true ]]; then
  step "Organisations and applications"
  while read -r org; do
    [[ -n "$org" ]] || continue
    printf '\n%s  %s  %s%s\n' "$BOLD" "$org" "$(org_name "$org")" "$RESET"
    apps_in_org "$org" | jq -r '(.applications // .)[]? |
      "      " + (.id | split("/") | last) + "  " + (.title // "") +
      "\n          " + ((.role // .roles // []) | map(split("/") | last) | join(", "))' || true
  done < <(orgs_list)
  exit 0
fi

# --- Resolve which organisation owns each application ---------------------

step "Resolving applications"

resolve_org_for_app() {
  local app="$1" org
  while read -r org; do
    [[ -n "$org" ]] || continue
    if directory --json --organization "$org" apps get "$app" >/dev/null 2>&1; then
      printf '%s' "$org"
      return 0
    fi
  done < <(orgs_list)
  return 1
}

# Pick the single application in an organisation carrying a given role.
resolve_app_by_role() {
  local org="$1" role="$2" matches count
  matches="$(apps_in_org "$org" | app_ids "$role")" || return 1
  count="$(grep -c . <<<"$matches" || true)"
  [[ "$count" == "1" ]] || return 1
  printf '%s' "$matches"
}

[[ -n "$CAP_APP_ID" ]] || die "CAP_APP_ID is not set. Run with --list-apps to see your applications."

if [[ -z "$CAP_ORGANIZATION" ]]; then
  CAP_ORGANIZATION="$(resolve_org_for_app "$CAP_APP_ID")" \
    || die "Could not find application $CAP_APP_ID in any of your organisations. Run with --list-apps."
fi

if [[ -z "$EDP_APP_ID" ]]; then
  [[ -n "$EDP_ORGANIZATION" ]] || die "Set EDP_APP_ID, or EDP_ORGANIZATION so it can be looked up. Run with --list-apps."
  if ! EDP_APP_ID="$(resolve_app_by_role "$EDP_ORGANIZATION" "$EDP_ROLE")"; then
    printf '\nApplications in %s with the energy data provider role:\n\n' "$EDP_ORGANIZATION" >&2
    apps_in_org "$EDP_ORGANIZATION" | jq -r --arg role "$EDP_ROLE" '(.applications // .)[]
      | select(((.role // .roles // []) | index($role)) != null)
      | "  " + (.id | split("/") | last) + "  " + (.title // "")' >&2 || true
    die "More than one application could be the resource API. Set EDP_APP_ID in $CONFIG_FILE."
  fi
  info "Resolved EDP application: $EDP_APP_ID"
elif [[ -z "$EDP_ORGANIZATION" ]]; then
  EDP_ORGANIZATION="$(resolve_org_for_app "$EDP_APP_ID")" \
    || die "Could not find application $EDP_APP_ID in any of your organisations. Run with --list-apps."
fi

info "CAP application $CAP_APP_ID in $CAP_ORGANIZATION ($(org_name "$CAP_ORGANIZATION"))"
info "EDP application $EDP_APP_ID in $EDP_ORGANIZATION ($(org_name "$EDP_ORGANIZATION"))"

if [[ "$RESTART" == true ]]; then
  docker info >/dev/null 2>&1 || die "Docker is not running, but --restart was given."
fi

if [[ "$DRY_RUN" == true ]]; then
  cat <<EOF

Dry run. Would issue:
  EDP signing certificate  application $EDP_APP_ID  organisation $EDP_ORGANIZATION
  CAP client certificate   application $CAP_APP_ID  organisation $CAP_ORGANIZATION
  CAP signing certificate  application $CAP_APP_ID  organisation $CAP_ORGANIZATION
Would download the client and signing CA bundles from $DIRECTORY_API_URL.
Would generate a localhost server certificate chain with openssl.
JWT signing key: $([[ "$ROTATE_JWT" == true ]] && echo regenerate || echo preserve)
Would install into certs/, authentication/certs/, resource/certs/, and stage
cap-demo material in scripts/cap-demo-handoff/.
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# Work in a temporary directory. Nothing is installed until every check passes.
# ---------------------------------------------------------------------------

WORK="$(mktemp -d)"
KEEP_WORK=false
cleanup() {
  if [[ "$KEEP_WORK" == true ]]; then
    printf '\n%sWork directory kept for inspection:%s %s\n' "$YELLOW" "$RESET" "$WORK" >&2
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT
trap 'KEEP_WORK=true' ERR

umask 077
cd "$WORK"

STAMP="$(date -u +%Y-%m-%dT%H:%MZ)"

# --- Certificate authorities ----------------------------------------------

step "Downloading certificate authorities"

# The CA bundles are the same for every organisation, but the API still
# requires the header when the account can act for more than one.
directory --organization "$CAP_ORGANIZATION" ca download client  -o client-ca.zip  >/dev/null
directory --organization "$CAP_ORGANIZATION" ca download signing -o signing-ca.zip >/dev/null
unzip -oq client-ca.zip  -d client-ca
unzip -oq signing-ca.zip -d signing-ca

for f in client-ca/root-ca.pem client-ca/intermediate.pem \
         signing-ca/root-ca.pem signing-ca/intermediate.pem; do
  [[ -s "$f" ]] || die "Expected $f in the downloaded CA bundle."
done

# nginx ssl_verify_depth defaults to 1, so the intermediate must itself be in
# the trusted set. Intermediate first, then root.
cat client-ca/intermediate.pem client-ca/root-ca.pem > client-verify-bundle.pem
cp signing-ca/root-ca.pem signing-ca-cert.pem

info "client CA:  $(openssl x509 -in client-ca/root-ca.pem -noout -subject | sed 's/^subject=//')"
info "signing CA: $(openssl x509 -in signing-ca/root-ca.pem -noout -subject | sed 's/^subject=//')"

# --- Leaf certificates from the directory ---------------------------------

step "Issuing certificates"

sign_cert() {  # org, app, type, key-out, cert-out, name -> prints certificate id
  local org="$1" app="$2" type="$3" key="$4" cert="$5" name="$6" result
  result="$(directory --json --organization "$org" cert sign "$app" "$type" \
    --name "$name" --key-out "$key" --cert-out "$cert")" \
    || die "Failed to sign a $type certificate for application $app."
  [[ -s "$cert" && -s "$key" ]] || die "The directory did not return a $type certificate for $app."
  jq -r '.id // empty' <<<"$result"
}

EDP_SIGNING_ID="$(sign_cert "$EDP_ORGANIZATION" "$EDP_APP_ID" signing \
  edp-demo-signing-key.pem edp-demo-signing-cert.pem "resource API local $STAMP")"
info "EDP signing  $EDP_SIGNING_ID"

CAP_CLIENT_ID_CERT="$(sign_cert "$CAP_ORGANIZATION" "$CAP_APP_ID" client \
  cap-demo-key.pem cap-demo-cert.pem "cap-demo local $STAMP")"
info "CAP client   $CAP_CLIENT_ID_CERT"

CAP_SIGNING_ID="$(sign_cert "$CAP_ORGANIZATION" "$CAP_APP_ID" signing \
  cap-signing-key.pem cap-signing-cert.pem "cap-demo provenance local $STAMP")"
info "CAP signing  $CAP_SIGNING_ID"

# The authentication API sends revocation messages to applications over mTLS
# (api/messaging.py). It acts for the EDP, so it presents a client certificate
# issued to the same EDP application as the signing certificate above.
EDP_CLIENT_ID_CERT="$(sign_cert "$EDP_ORGANIZATION" "$EDP_APP_ID" client \
  client-key.pem edp-client-cert.pem "authentication API local $STAMP")"
info "EDP client   $EDP_CLIENT_ID_CERT"

# Record what was issued before anything can fail. If a later step stops the
# script, the kept work directory still names the certificates to revoke.
# The organisation is recorded with each certificate, because revoking one
# needs the same X-Organization header that issuing it did.
jq -n --arg stamp "$STAMP" \
      --arg edp_signing "$EDP_SIGNING_ID" --arg cap_client "$CAP_CLIENT_ID_CERT" \
      --arg cap_signing "$CAP_SIGNING_ID" --arg edp_client "$EDP_CLIENT_ID_CERT" \
      --arg edp_app "$EDP_APP_ID" --arg cap_app "$CAP_APP_ID" \
      --arg edp_org "$EDP_ORGANIZATION" --arg cap_org "$CAP_ORGANIZATION" \
  '{issued: $stamp, certificates: [
      {id: $edp_signing, type: "signing", app: $edp_app, org: $edp_org},
      {id: $cap_client,  type: "client",  app: $cap_app, org: $cap_org},
      {id: $cap_signing, type: "signing", app: $cap_app, org: $cap_org},
      {id: $edp_client,  type: "client",  app: $edp_app, org: $edp_org}]}' > issued-certs.json

# Leaf first in every bundle. resource/api/provenance.py loads the signing
# bundle as a certificate list, and cap-demo's lib/clientConfig.ts treats the
# first certificate in the mTLS bundle as the leaf.
cat edp-demo-signing-cert.pem signing-ca/intermediate.pem > signing-issued-intermediate-bundle.pem
cat cap-demo-cert.pem         client-ca/intermediate.pem  > cap-demo-bundle.pem
cat cap-signing-cert.pem      signing-ca/intermediate.pem > cap-signing-bundle.pem
cat edp-client-cert.pem       client-ca/intermediate.pem  > client-bundle.pem

san_uri() { openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null \
  | grep -o 'URI:[^,]*' | head -1 | cut -d: -f2- | tr -d ' '; }

CAP_CLIENT_URI="$(san_uri cap-demo-cert.pem)"
EDP_MEMBER_URI="$(openssl x509 -in edp-demo-signing-cert.pem -noout -subject \
  | grep -o 'CN *= *[^,]*' | sed 's/^CN *= *//')"

# --- Local server certificate chain ---------------------------------------

step "Generating the localhost server certificate"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
  -keyout server-ca-key.pem -out server-ca-cert.pem -days 3650 \
  -subj "/C=GB/ST=London/O=Local Development/CN=Local Development Server CA" \
  -addext "basicConstraints=critical,CA:true" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server-issuer-key.pem -out server-issuer.csr \
  -subj "/C=GB/ST=London/O=Local Development/CN=Local Development Server Issuer" 2>/dev/null

openssl x509 -req -in server-issuer.csr \
  -CA server-ca-cert.pem -CAkey server-ca-key.pem -CAcreateserial \
  -out server-issuer-cert.pem -days 1825 \
  -extfile <(printf '%s\n' \
    'basicConstraints=critical,CA:true,pathlen:0' \
    'keyUsage=critical,keyCertSign,cRLSign' \
    'subjectKeyIdentifier=hash' \
    'authorityKeyIdentifier=keyid:always,issuer') 2>/dev/null

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout localhost-key.pem -out localhost.csr \
  -subj "/C=GB/ST=London/O=Local Development/CN=localhost" 2>/dev/null

# The SubjectAltName is the point of generating this with openssl. The old
# ib1-directory command set only the CN, which strict TLS clients reject.
openssl x509 -req -in localhost.csr \
  -CA server-issuer-cert.pem -CAkey server-issuer-key.pem -CAcreateserial \
  -out localhost-cert.pem -days 825 \
  -extfile <(printf '%s\n' \
    'basicConstraints=critical,CA:false' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1,IP:::1' \
    'subjectKeyIdentifier=hash' \
    'authorityKeyIdentifier=keyid:always,issuer') 2>/dev/null

cat localhost-cert.pem server-issuer-cert.pem server-ca-cert.pem > server-complete-bundle.pem
cat server-issuer-cert.pem server-ca-cert.pem                    > server-bundle.pem

info "SubjectAltName: $(openssl x509 -in localhost-cert.pem -noout -ext subjectAltName | tail -1 | sed 's/^ *//')"

# --- JWT signing key -------------------------------------------------------

JWT_TARGET="$REPO_ROOT/authentication/certs/jwt-signing-key.pem"
if [[ "$ROTATE_JWT" == true || ! -f "$JWT_TARGET" ]]; then
  step "Generating the JWT signing key"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out jwt-signing-key.pem 2>/dev/null
  JWT_STATE=generated
  [[ "$ROTATE_JWT" == true ]] && warn "The JWT signing key was regenerated. Every previously issued access token is now invalid."
else
  JWT_STATE=preserved
fi

# --- Verify before installing ---------------------------------------------

step "Verifying"

openssl verify -CAfile client-ca/root-ca.pem  -untrusted client-ca/intermediate.pem  cap-demo-cert.pem >/dev/null \
  || die "The CAP client certificate does not chain to the downloaded client CA."
openssl verify -CAfile signing-ca/root-ca.pem -untrusted signing-ca/intermediate.pem edp-demo-signing-cert.pem >/dev/null \
  || die "The EDP signing certificate does not chain to the downloaded signing CA."
openssl verify -CAfile signing-ca/root-ca.pem -untrusted signing-ca/intermediate.pem cap-signing-cert.pem >/dev/null \
  || die "The CAP signing certificate does not chain to the downloaded signing CA."
openssl verify -CAfile client-ca/root-ca.pem  -untrusted client-ca/intermediate.pem  edp-client-cert.pem >/dev/null \
  || die "The EDP client certificate does not chain to the downloaded client CA."
openssl verify -CAfile server-ca-cert.pem     -untrusted server-issuer-cert.pem      localhost-cert.pem >/dev/null \
  || die "The localhost certificate does not chain to the generated server CA."

check_pair() {
  diff <(openssl pkey -in "$1" -pubout 2>/dev/null) \
       <(openssl x509 -in "$2" -pubkey -noout 2>/dev/null) >/dev/null \
    || die "Key and certificate do not match: $1 and $2"
}
check_pair cap-demo-key.pem        cap-demo-cert.pem
check_pair cap-signing-key.pem     cap-signing-cert.pem
check_pair edp-demo-signing-key.pem edp-demo-signing-cert.pem
check_pair client-key.pem          edp-client-cert.pem
check_pair localhost-key.pem       localhost-cert.pem

# Print the nth certificate (0 based) from a PEM bundle. Written with awk
# rather than csplit, because the BSD csplit on macOS has no -z.
nth_cert() {
  awk -v want="$2" '
    /-----BEGIN CERTIFICATE-----/ { n++ }
    n == want + 1 { print }
    /-----END CERTIFICATE-----/   { if (n == want + 1) exit }
  ' "$1"
}

# In a bundle the issuer of the first certificate must be the subject of the second.
check_bundle_order() {
  local bundle="$1" issuer subject
  subject="$(nth_cert "$bundle" 1 | openssl x509 -noout -subject 2>/dev/null | sed 's/^subject=//')"
  [[ -n "$subject" ]] || die "$bundle does not contain an intermediate certificate."
  issuer="$(nth_cert "$bundle" 0 | openssl x509 -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
  [[ "$issuer" == "$subject" ]] \
    || die "$bundle is out of order. The leaf must come first, then its issuer."
}
check_bundle_order cap-demo-bundle.pem
check_bundle_order cap-signing-bundle.pem
check_bundle_order signing-issued-intermediate-bundle.pem
check_bundle_order client-bundle.pem

# The role is scoped to a registry host. A certificate carrying the role for a
# different environment is accepted by nginx and then rejected by the resource
# API with a confusing 401, so check it here instead.
openssl x509 -in cap-demo-cert.pem -noout -text | grep -qF "$CAP_ROLE" \
  || die "The CAP client certificate does not carry the role
  $CAP_ROLE
Check the roles claimed by application $CAP_APP_ID in the directory."

info "${GREEN}All checks passed${RESET}"

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

step "Installing"

BACKUP="$REPO_ROOT/certs-backup/$(date -u +%Y%m%dT%H%M%SZ)"

install_set() {  # destination, files...
  local dest="$1"; shift
  local manifest="$dest/.refresh-certs-manifest" f
  mkdir -p "$dest"
  for f in "$@"; do
    if [[ -f "$dest/$f" ]]; then
      mkdir -p "$BACKUP/${dest#"$REPO_ROOT"/}"
      cp "$dest/$f" "$BACKUP/${dest#"$REPO_ROOT"/}/$f"
    fi
    # A file named here but absent from the work directory is one this run
    # deliberately did not regenerate, such as a preserved JWT signing key.
    # Leave the installed copy alone, but keep it in the manifest below so the
    # next run does not prune it as stale.
    if [[ -f "$WORK/$f" ]]; then
      cp "$WORK/$f" "$dest/$f.tmp"
      mv "$dest/$f.tmp" "$dest/$f"
    fi
  done
  # Remove only files a previous run of this script wrote and this one did not,
  # so hand-placed archive directories are left alone.
  if [[ -f "$manifest" ]]; then
    comm -23 <(sort "$manifest") <(printf '%s\n' "$@" | sort) | while read -r stale; do
      [[ -n "$stale" ]] && rm -f "$dest/$stale"
    done
  fi
  printf '%s\n' "$@" > "$manifest"
  chmod 600 "$dest"/*key*.pem 2>/dev/null || true
  info "  ${dest#"$REPO_ROOT"/}: $*"
}

install_set "$REPO_ROOT/certs" \
  server-complete-bundle.pem localhost-key.pem client-verify-bundle.pem

# jwt-signing-key.pem is only in the work directory when it was regenerated.
# Either way it belongs in the manifest, so install_set is given the same list.
install_set "$REPO_ROOT/authentication/certs" \
  jwt-signing-key.pem client-bundle.pem client-key.pem
[[ "$JWT_STATE" == preserved ]] && info "  authentication/certs: jwt-signing-key.pem preserved"

install_set "$REPO_ROOT/resource/certs" \
  edp-demo-signing-key.pem edp-demo-signing-cert.pem \
  signing-ca-cert.pem signing-issued-intermediate-bundle.pem

# --- cap-demo handoff ------------------------------------------------------

HANDOFF="$SCRIPT_DIR/cap-demo-handoff"
rm -rf "$HANDOFF"; mkdir -p "$HANDOFF"
cp cap-demo-bundle.pem cap-demo-key.pem \
   cap-signing-bundle.pem cap-signing-key.pem \
   server-bundle.pem "$HANDOFF/"
cp signing-ca/root-ca.pem "$HANDOFF/signing-root-ca.pem"
chmod 600 "$HANDOFF"/*key*.pem
info "  scripts/cap-demo-handoff: material for cap-demo"

# --- Archive the raw material and record what was issued -------------------

GENERATED="$SCRIPT_DIR/generated"
rm -rf "$GENERATED.prev"
[[ -d "$GENERATED" ]] && mv "$GENERATED" "$GENERATED.prev"
mkdir -p "$GENERATED"
cp -R "$WORK"/* "$GENERATED/" 2>/dev/null || true

PREVIOUS_CERTS="$GENERATED.prev/issued-certs.json"

cat > "$GENERATED/MANIFEST.txt" <<EOF
source=directory
directory_api=$DIRECTORY_API_URL
refreshed=$STAMP
cap_application=$CAP_APP_ID
cap_organisation=$CAP_ORGANIZATION
cap_client_uri=$CAP_CLIENT_URI
edp_application=$EDP_APP_ID
edp_organisation=$EDP_ORGANIZATION
edp_member_uri=$EDP_MEMBER_URI
jwt_signing_key=$JWT_STATE
EOF

# --- Revoke the previous run's certificates --------------------------------

if [[ -f "$PREVIOUS_CERTS" ]]; then
  # Each line is "<id> <organisation>".
  OLD_CERTS="$(jq -r '.certificates[]? | select(.id != null and .id != "")
    | .id + " " + (.org // "")' "$PREVIOUS_CERTS")"
  if [[ -n "$OLD_CERTS" ]]; then
    if [[ "$REVOKE_PREVIOUS" == true ]]; then
      step "Revoking the previous certificates"
      while read -r id org; do
        [[ -n "$id" ]] || continue
        if directory --json ${org:+--organization "$org"} cert revoke "$id" --yes >/dev/null 2>&1; then
          info "  revoked $id"
        else
          warn "could not revoke $id"
        fi
      done <<<"$OLD_CERTS"
    else
      REVOKE_NOTE="$OLD_CERTS"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# What to do next
# ---------------------------------------------------------------------------

CAP_ENV="$HANDOFF/cli.env"
cat > "$CAP_ENV" <<EOF
CLI_MTLS_BUNDLE_PATH=../certs/local/cap-demo-bundle.pem
CLI_MTLS_KEY_PATH=../certs/local/cap-demo-key.pem
CLI_SERVER_CA_PATH=../certs/local/server-bundle.pem
CLI_CLIENT_ID=$CAP_CLIENT_URI
CLI_PUBLIC_SERVER=https://localhost:8000
CLI_MTLS_AUTHORISATION_SERVER=https://localhost:8000
CLI_PROTECTED_RESOURCE_URL=https://localhost:8010/datasources/
CLI_REDIRECT_URI=http://localhost:3000/callback
CLI_POST_LOGIN_REDIRECT=http://localhost:3000/callback
EOF

{
  printf '\n%s%s%s\n' "$BOLD" "────────────────────────────────────────────────────────────" "$RESET"
  printf '%sRefresh complete%s\n\n' "$GREEN" "$RESET"
  printf '  directory       %s\n' "$DIRECTORY_API_URL"
  printf '  EDP signing     %s  application %s\n' "$EDP_SIGNING_ID" "$EDP_APP_ID"
  printf '  EDP member      %s\n' "$EDP_MEMBER_URI"
  printf '  CAP client      %s  application %s\n' "$CAP_CLIENT_ID_CERT" "$CAP_APP_ID"
  printf '  CAP signing     %s\n' "$CAP_SIGNING_ID"
  printf '  EDP client      %s  for outbound revocation messages\n' "$EDP_CLIENT_ID_CERT"
  printf '  CAP client id   %s\n' "$CAP_CLIENT_URI"
  printf '  localhost cert  expires %s\n' "$(openssl x509 -in "$GENERATED/localhost-cert.pem" -noout -enddate | sed 's/^notAfter=//')"
  printf '  JWT signing key %s\n' "$JWT_STATE"

  cat <<'EOT'

0) To let the authentication API send revocation messages over mTLS, add these
   to authentication/.env. They are optional, and unset by default.

     MTLS_CLIENT_BUNDLE=/certs/client-bundle.pem
     MTLS_CLIENT_KEY=/certs/client-key.pem
EOT

  if [[ "$RESTART" == true ]]; then
    printf '\n1) nginx restarted (see below).\n'
  else
    printf '\n1) Restart nginx. It reads its certificates once at startup.\n\n'
    printf '     cd %s\n' "$REPO_ROOT"
    printf '     docker compose restart authentication_web resource_web\n'
  fi

  cat <<EOF

2) Copy the cap-demo material. Set CAP to your cap-demo checkout.

     CAP=<path to your cap-demo checkout>
     mkdir -p "\$CAP/certs/local/signing"
     cp $HANDOFF/cap-demo-bundle.pem   "\$CAP/certs/local/"
     cp $HANDOFF/cap-demo-key.pem      "\$CAP/certs/local/"
     cp $HANDOFF/server-bundle.pem     "\$CAP/certs/local/"
     cp $HANDOFF/cap-signing-bundle.pem "\$CAP/certs/local/signing/issued-intermediate-bundle.pem"
     cp $HANDOFF/cap-signing-key.pem    "\$CAP/certs/local/signing/key.pem"
     cp $HANDOFF/signing-root-ca.pem    "\$CAP/certs/local/signing/root-ca.pem"
     chmod 600 "\$CAP/certs/local"/*key*.pem "\$CAP/certs/local/signing/key.pem"

3) Set these in <cap-demo>/cli/.env. Paths are relative to the cli directory.
   The same lines are saved in $CAP_ENV

$(sed 's/^/     /' "$CAP_ENV")

   The localhost certificate now carries a SubjectAltName, so
   CLI_SERVER_CA_PATH works and --insecure is no longer needed.

   cap-demo's provenance service reads certs/cap-demo-certs/signing/ through
   compose.yml. Point that mount at certs/local/signing, or copy the three
   signing files there instead.

4) The EDP signing identity is
     $EDP_MEMBER_URI
   If that differs from the value hard coded in cap-demo at
   cli/callback_server.ts, update it or the provenance check will fail.
EOF

  if [[ -n "${REVOKE_NOTE:-}" ]]; then
    printf '\n5) The previous run'"'"'s certificates are still valid. Revoke them with:\n\n'
    while read -r id org; do
      [[ -n "$id" ]] || continue
      if [[ -n "$org" ]]; then
        printf '     directory --organization %s cert revoke %s --yes\n' "$org" "$id"
      else
        printf '     directory cert revoke %s --yes\n' "$id"
      fi
    done <<<"$REVOKE_NOTE"
    printf '\n   Or re-run this script with --revoke-previous.\n'
  fi

  printf '%s%s%s\n' "$BOLD" "────────────────────────────────────────────────────────────" "$RESET"
} | tee "$HANDOFF/README.txt"

if [[ "$RESTART" == true ]]; then
  step "Restarting nginx"
  (cd "$REPO_ROOT" && docker compose restart authentication_web resource_web)
fi
