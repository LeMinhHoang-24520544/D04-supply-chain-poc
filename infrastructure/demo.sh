#!/usr/bin/env bash
# infrastructure/demo.sh
# End-to-End Air-Gapped Docker Demo for NT230 - Topic D04 (Supply Chain Compromise)
#
# Demonstrates:
#   1. Starting air-gapped Verdaccio registry (uplinks: {}) + victim-consumer container
#   2. Non-interactive user registration & publishing:
#        - Harmless local dependency stubs (internal-auth-config@99.0.0, lodash@4.17.21)
#          so offline npm install resolves without 404 on air-gapped Verdaccio
#        - Legitimate internal baseline: uit-core-auth@1.0.0
#        - Malicious PoC (Dependency Confusion + Base64 Eval): uit-core-auth@99.9.9
#        - Malicious PoC (Lifecycle preinstall hook): uit-marker-lifecycle@1.0.0
#        - Clean baseline: uit-benign@1.0.0
#   3. Pre-install CI/CD Security Gate (supply_chain_gate.py):
#        - PASS (exit 0) on 3 benign packages
#        - BLOCK (exit 1) on 3 malicious PoC packages (including SHA-512 tamper check)
#   4. Unprotected victim-consumer attack replay (without gate):
#        - `npm install` resolves uit-core-auth@99.9.9 over 1.0.0 and creates marker log
#        - `npm install uit-marker-lifecycle` triggers preinstall hook and creates marker log
#   5. Saves full output log to logs/docker_demo.log
#
# Usage:
#   bash infrastructure/demo.sh           # start & run full demo
#   bash infrastructure/demo.sh --reset   # wipe previous Verdaccio storage first

set -euo pipefail

# Prevent Git Bash (MINGW64) from mangling container paths like /app and /tmp/...
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then
  HOST_REPO_ROOT="$(cygpath -m "${REPO_ROOT}")"
else
  HOST_REPO_ROOT="${REPO_ROOT}"
fi
COMPOSE_FILE="${HOST_REPO_ROOT}/infrastructure/docker-compose.yml"
LOG_DIR="${REPO_ROOT}/logs"
LOG_FILE="${LOG_DIR}/docker_demo.log"
RESET=0

for arg in "$@"; do
  case "$arg" in
    --reset) RESET=1 ;;
    -h|--help)
      echo "Usage: bash infrastructure/demo.sh [--reset]"
      exit 0
      ;;
  esac
done

mkdir -p "${LOG_DIR}"
exec > >(tee "${LOG_FILE}") 2>&1

PYTHON_BIN=""
for cand in python3 python; do
  if command -v "${cand}" >/dev/null 2>&1 && "${cand}" -c "import sys" >/dev/null 2>&1; then
    PYTHON_BIN="${cand}"
    break
  fi
done
if [ -z "${PYTHON_BIN}" ]; then
  echo "[!] ERROR: Working python/python3 interpreter not found."
  exit 1
fi

banner() {
  echo ""
  echo "==========================================================================="
  echo " $1"
  echo "==========================================================================="
}

banner "NT230 - D04: AIR-GAPPED DOCKER END-TO-END DEMO"
echo "[*] Timestamp : $(date -u '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date)"
echo "[*] Repo Root : ${REPO_ROOT}"
echo "[*] Log File  : ${LOG_FILE}"

if ! command -v docker >/dev/null 2>&1; then
  echo "[!] ERROR: docker not found in PATH."
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "[!] ERROR: Docker daemon is not running. Start Docker first."
  exit 1
fi

if [ "${RESET}" -eq 1 ]; then
  banner "STEP 0: RESETTING PREVIOUS CONTAINERS & VERDACCIO STORAGE"
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans || true
  rm -rf "${SCRIPT_DIR}/storage/data" "${SCRIPT_DIR}/storage/htpasswd" || true
fi

banner "STEP 1: STARTING ISOLATED DOCKER LAB (VERDACCIO AIR-GAP + VICTIM)"
docker compose -f "${COMPOSE_FILE}" up -d --build

echo "[*] Waiting for Verdaccio (http://local-registry:4873/-/ping)..."
READY=0
for i in $(seq 1 30); do
  if docker exec victim-consumer curl -fsS "http://local-registry:4873/-/ping" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [ "${READY}" -ne 1 ]; then
  echo "[!] ERROR: Verdaccio did not become ready within 30s."
  docker compose -f "${COMPOSE_FILE}" logs --tail=30 local-registry
  exit 1
fi
echo "[+] Air-gapped Verdaccio is UP and reachable from victim-consumer."

banner "STEP 2: AUTHENTICATING & PUBLISHING PACKAGES TO LOCAL REGISTRY"
AUTH_TOKEN="$(docker exec victim-consumer bash -c '
  RESP=$(curl -sS -X PUT \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"labuser\",\"password\":\"labpass123\",\"email\":\"lab@uit.local\"}" \
    "http://local-registry:4873/-/user/org.couchdb.user:labuser")
  node -e "const d = JSON.parse(process.argv[1]); if (!d.token) process.exit(1); console.log(d.token);" "$RESP"
')"

if [ -z "${AUTH_TOKEN}" ]; then
  echo "[!] ERROR: Failed to obtain Verdaccio auth token. Try running with --reset."
  exit 1
fi
echo "[+] Authenticated as 'labuser' on local-registry:4873."

docker exec victim-consumer bash -c "
  rm -rf /tmp/publish_stage
  mkdir -p /tmp/publish_stage/internal-auth-config /tmp/publish_stage/lodash /tmp/publish_stage/uit-core-auth-v1
  printf 'registry=http://local-registry:4873/\n//local-registry:4873/:_authToken=%s\nstrict-ssl=false\naudit=false\n' '${AUTH_TOKEN}' > /tmp/pub.npmrc
  chmod 600 /tmp/pub.npmrc

  # 1. Harmless stub for transitive dependency of uit-core-auth@99.9.9 (air-gap offline resolution)
  cat <<'EOF' > /tmp/publish_stage/internal-auth-config/package.json
{
  \"name\": \"internal-auth-config\",
  \"version\": \"99.0.0\",
  \"description\": \"Harmless local stub dependency for air-gapped Verdaccio demo\",
  \"main\": \"index.js\",
  \"license\": \"ISC\"
}
EOF
  echo 'module.exports = { env: \"airgap-lab\" };' > /tmp/publish_stage/internal-auth-config/index.js

  # 2. Harmless stub for lodash so uit-benign can also install offline
  cat <<'EOF' > /tmp/publish_stage/lodash/package.json
{
  \"name\": \"lodash\",
  \"version\": \"4.17.21\",
  \"description\": \"Harmless local stub for offline Verdaccio demo\",
  \"main\": \"index.js\",
  \"license\": \"MIT\"
}
EOF
  echo 'module.exports = { noop: () => {} };' > /tmp/publish_stage/lodash/index.js

  # 3. Legitimate internal baseline uit-core-auth@1.0.0 (before confusion attack)
  cat <<'EOF' > /tmp/publish_stage/uit-core-auth-v1/package.json
{
  \"name\": \"uit-core-auth\",
  \"version\": \"1.0.0\",
  \"description\": \"Legitimate internal enterprise auth package (v1.0.0 baseline)\",
  \"main\": \"index.js\",
  \"license\": \"ISC\"
}
EOF
  cat <<'EOF' > /tmp/publish_stage/uit-core-auth-v1/index.js
module.exports = {
  authenticate: function(user) {
    console.log('[LEGIT AUTH v1.0.0] Verified user:', user);
    return true;
  }
};
EOF
"

# Copy repo PoC and benign packages into container staging area
docker cp "${HOST_REPO_ROOT}/packages/uit-benign" victim-consumer:/tmp/publish_stage/uit-benign
docker cp "${HOST_REPO_ROOT}/packages/uit-core-auth" victim-consumer:/tmp/publish_stage/uit-core-auth-v99
docker cp "${HOST_REPO_ROOT}/packages/uit-marker-lifecycle" victim-consumer:/tmp/publish_stage/uit-marker-lifecycle

publish_pkg() {
  local dir="$1"
  local label="$2"
  echo "[*] Publishing ${label}..."
  docker exec victim-consumer bash -c "
    cd '${dir}'
    OUT=\$(npm publish --userconfig /tmp/pub.npmrc --registry http://local-registry:4873/ 2>&1) || {
      if echo \"\$OUT\" | grep -qiE 'cannot publish over|already present|EPUBLISHCONFLICT|409'; then
        echo '    [INFO] Version already exists in Verdaccio (skipping).'
        exit 0
      fi
      echo \"\$OUT\"
      exit 1
    }
    echo '    [OK] Published successfully.'
  "
}

publish_pkg "/tmp/publish_stage/internal-auth-config" "internal-auth-config@99.0.0 (offline stub)"
publish_pkg "/tmp/publish_stage/lodash"               "lodash@4.17.21 (offline stub)"
publish_pkg "/tmp/publish_stage/uit-benign"           "uit-benign@1.0.0 (benign baseline)"
publish_pkg "/tmp/publish_stage/uit-core-auth-v1"     "uit-core-auth@1.0.0 (legitimate internal v1)"
publish_pkg "/tmp/publish_stage/uit-core-auth-v99"    "uit-core-auth@99.9.9 (Dependency Confusion PoC)"
publish_pkg "/tmp/publish_stage/uit-marker-lifecycle" "uit-marker-lifecycle@1.0.0 (Lifecycle preinstall PoC)"

banner "STEP 3: PRE-INSTALL CI/CD SECURITY GATE (DEFENSE DEMO)"
echo "[*] Preparing SHA-512 tampered artifact simulation..."
"${PYTHON_BIN}" "${HOST_REPO_ROOT}/packages/uit-marker-tamper/simulate_tamper.py"

for pkg in uit-benign uit-benign-native uit-benign-minified; do
  echo ""
  echo "[*] Gate check (expect PASS / exit 0): packages/${pkg}"
  "${PYTHON_BIN}" "${HOST_REPO_ROOT}/scripts/supply_chain_gate.py" "${HOST_REPO_ROOT}/packages/${pkg}"
done

for pkg in uit-core-auth uit-marker-lifecycle uit-marker-tamper; do
  echo ""
  echo "[*] Gate check (expect BLOCK / exit 1): packages/${pkg}"
  set +e
  "${PYTHON_BIN}" "${HOST_REPO_ROOT}/scripts/supply_chain_gate.py" "${HOST_REPO_ROOT}/packages/${pkg}"
  RC=$?
  set -e
  echo "[+] supply_chain_gate.py returned exit code: ${RC}"
  if [ "${RC}" -eq 0 ]; then
    echo "[!] ERROR: Security Gate failed to block malicious PoC packages/${pkg}!"
    exit 1
  fi
done

banner "STEP 4A: ATTACK REPLAY IN VICTIM CONTAINER — DEPENDENCY CONFUSION"
echo "[*] victim-consumer /app/package.json:"
docker exec victim-consumer cat /app/package.json
echo ""
echo "[*] Running 'npm install --foreground-scripts' inside victim-consumer..."
docker exec victim-consumer bash -c "
  rm -rf /app/node_modules /app/package-lock.json /tmp/uit_marker_*.log
  cd /app
  npm install --foreground-scripts
"
echo ""
echo "[*] Resolved dependency version (npm ls uit-core-auth):"
docker exec victim-consumer bash -c "cd /app && npm ls uit-core-auth"
echo ""
echo "[*] Checking safe marker file (/tmp/uit_marker_dependency_confusion.log):"
docker exec victim-consumer cat /tmp/uit_marker_dependency_confusion.log

banner "STEP 4B: ATTACK REPLAY IN VICTIM CONTAINER — LIFECYCLE PREINSTALL HOOK"
echo "[*] Installing uit-marker-lifecycle inside victim-consumer..."
docker exec victim-consumer bash -c "
  cd /app
  npm install --no-save --foreground-scripts uit-marker-lifecycle
"
echo ""
echo "[*] Checking safe marker file (/tmp/uit_marker_lifecycle.log):"
docker exec victim-consumer cat /tmp/uit_marker_lifecycle.log

# Cleanup temporary publish credentials inside container
docker exec victim-consumer rm -rf /tmp/pub.npmrc /tmp/publish_stage

banner "DEMO COMPLETED SUCCESSFULLY"
echo "[+] Full transcript saved to: ${LOG_FILE}"
echo "[+] To inspect registry UI: http://localhost:4873"
echo "[+] To tear down lab      : docker compose -f infrastructure/docker-compose.yml down"
