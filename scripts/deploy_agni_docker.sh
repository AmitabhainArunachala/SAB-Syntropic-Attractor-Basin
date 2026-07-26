#!/usr/bin/env bash
set -euo pipefail

# Deploy the current target branch to AGNI via Docker.
# Run from local machine that has SSH access to AGNI.
#
# Example:
#   AGNI_PUBLIC_BASE_URL=https://agora.example scripts/deploy_agni_docker.sh
#   AGNI_PUBLIC_BASE_URL=https://agora.example AGNI_BRANCH=main AGNI_SSH_TARGET=agni scripts/deploy_agni_docker.sh

usage() {
  cat <<'USAGE'
Usage: deploy_agni_docker.sh

Environment variables:
  AGNI_SSH_TARGET         SSH host/alias (default: agni)
  AGNI_REPO_PATH          Remote repo path (default: /home/openclaw/repos/saraswati-dharmic-agora)
  AGNI_BRANCH             Branch to deploy (default: main)
  AGNI_IMAGE              Docker image tag (default: dharmic-agora:latest)
  AGNI_CONTAINER_NAME     Container name (default: dharmic-agora)
  AGNI_HOST_PORT          Host port mapped to app (default: 8800)
  AGNI_CONTAINER_PORT     Container internal app port (default: 8000)
  AGNI_DATA_DIR           Host data dir mount (default: /home/openclaw/dharmic-agora-data)
  AGNI_DB_PATH            In-container SAB authority DB path (default: /app/data/sabp.db)
  AGNI_LOG_DIR            Host log dir mount (default: /home/openclaw/dharmic-agora-logs)
  AGNI_HEALTH_PATH        Canonical health path (default: /health)
  AGNI_ROOT_PATH          Root probe path (default: /)
  AGNI_PUBLIC_BASE_URL    Required public origin for proxy/OpenAPI/source parity verification
  AGNI_TIMEOUT_SECONDS    Wait timeout for health (default: 90)
  AGNI_RESTORE_BRANCH     Restore remote branch after deploy: 1/0 (default: 1)
USAGE
}

if [[ $# -gt 0 ]]; then
  case "$1" in
    --no-build)
      echo "ERROR: --no-build is disabled because an image label alone cannot prove source identity" >&2
      exit 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
fi

AGNI_SSH_TARGET="${AGNI_SSH_TARGET:-agni}"
AGNI_REPO_PATH="${AGNI_REPO_PATH:-/home/openclaw/repos/saraswati-dharmic-agora}"
AGNI_BRANCH="${AGNI_BRANCH:-main}"
AGNI_IMAGE="${AGNI_IMAGE:-dharmic-agora:latest}"
AGNI_CONTAINER_NAME="${AGNI_CONTAINER_NAME:-dharmic-agora}"
AGNI_HOST_PORT="${AGNI_HOST_PORT:-8800}"
AGNI_CONTAINER_PORT="${AGNI_CONTAINER_PORT:-8000}"
AGNI_DATA_DIR="${AGNI_DATA_DIR:-/home/openclaw/dharmic-agora-data}"
AGNI_DB_PATH="${AGNI_DB_PATH:-/app/data/sabp.db}"
AGNI_LOG_DIR="${AGNI_LOG_DIR:-/home/openclaw/dharmic-agora-logs}"
AGNI_HEALTH_PATH="${AGNI_HEALTH_PATH:-/health}"
AGNI_ROOT_PATH="${AGNI_ROOT_PATH:-/}"
AGNI_PUBLIC_BASE_URL="${AGNI_PUBLIC_BASE_URL:-}"
AGNI_TIMEOUT_SECONDS="${AGNI_TIMEOUT_SECONDS:-90}"
AGNI_RESTORE_BRANCH="${AGNI_RESTORE_BRANCH:-1}"

if [[ -z "${AGNI_SSH_TARGET}" ]] || [[ "${AGNI_SSH_TARGET}" == -* ]]; then
  echo "ERROR: AGNI_SSH_TARGET must not be empty or option-like" >&2
  exit 2
fi
if [[ -z "${AGNI_PUBLIC_BASE_URL}" ]]; then
  echo "ERROR: AGNI_PUBLIC_BASE_URL is required; public proxy parity must be verified before deployment can succeed" >&2
  exit 2
fi
invalid_public_origin() {
  echo "ERROR: AGNI_PUBLIC_BASE_URL must be a root HTTPS origin without credentials, path, query, fragment, whitespace, or shell metacharacters" >&2
  exit 2
}
if (( ${#AGNI_PUBLIC_BASE_URL} > 2048 )) || \
   [[ ! "${AGNI_PUBLIC_BASE_URL}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$ ]]; then
  invalid_public_origin
fi
AGNI_PUBLIC_BASE_URL="${AGNI_PUBLIC_BASE_URL%/}"
PUBLIC_AUTHORITY="${AGNI_PUBLIC_BASE_URL#https://}"
PUBLIC_HOST="${PUBLIC_AUTHORITY%%:*}"
PUBLIC_PORT=""
if [[ "${PUBLIC_AUTHORITY}" == *:* ]]; then
  PUBLIC_HOST="${PUBLIC_AUTHORITY%:*}"
  PUBLIC_PORT="${PUBLIC_AUTHORITY##*:}"
fi
if [[ -n "${PUBLIC_PORT}" ]] && \
   { (( ${#PUBLIC_PORT} > 5 )) || (( 10#${PUBLIC_PORT} < 1 )) || (( 10#${PUBLIC_PORT} > 65535 )); }; then
  invalid_public_origin
fi
if (( ${#PUBLIC_HOST} > 253 )) || [[ "${PUBLIC_HOST}" == .* ]] || \
   [[ "${PUBLIC_HOST}" == *. ]] || [[ "${PUBLIC_HOST}" == *..* ]]; then
  invalid_public_origin
fi
IFS='.' read -r -a PUBLIC_HOST_LABELS <<< "${PUBLIC_HOST}"
if [[ "${PUBLIC_HOST}" =~ ^[0-9.]+$ ]]; then
  if (( ${#PUBLIC_HOST_LABELS[@]} != 4 )); then
    invalid_public_origin
  fi
  for label in "${PUBLIC_HOST_LABELS[@]}"; do
    if [[ ! "${label}" =~ ^[0-9]+$ ]] || (( ${#label} > 3 )) || (( 10#${label} > 255 )); then
      invalid_public_origin
    fi
  done
else
  if (( ${#PUBLIC_HOST_LABELS[@]} < 2 )); then
    invalid_public_origin
  fi
  for label in "${PUBLIC_HOST_LABELS[@]}"; do
    if (( ${#label} > 63 )) || \
       [[ ! "${label}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
      invalid_public_origin
    fi
  done
fi

if [[ "${AGNI_HEALTH_PATH:0:1}" != "/" ]]; then
  AGNI_HEALTH_PATH="/${AGNI_HEALTH_PATH}"
fi
if [[ "${AGNI_ROOT_PATH:0:1}" != "/" ]]; then
  AGNI_ROOT_PATH="/${AGNI_ROOT_PATH}"
fi

LOCAL_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if ! LS_REMOTE_OUTPUT="$(
  cd -- "${LOCAL_REPO_ROOT}"
  git ls-remote --exit-code origin "refs/heads/${AGNI_BRANCH}"
)"; then
  echo "ERROR: unable to resolve the exact remote commit for AGNI_BRANCH" >&2
  exit 2
fi
read -r EXPECTED_DEPLOY_SHA _ <<< "${LS_REMOTE_OUTPUT}"
if [[ ! "${EXPECTED_DEPLOY_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: AGNI_BRANCH did not resolve to one full Git commit SHA" >&2
  exit 2
fi

echo "Deploy target:"
echo "  ssh=${AGNI_SSH_TARGET}"
echo "  repo=${AGNI_REPO_PATH}"
echo "  branch=${AGNI_BRANCH}"
echo "  image=${AGNI_IMAGE}"
echo "  container=${AGNI_CONTAINER_NAME}"
echo "  port=${AGNI_HOST_PORT}->${AGNI_CONTAINER_PORT}"
echo "  db_path=${AGNI_DB_PATH}"
echo "  health_path=${AGNI_HEALTH_PATH}"
echo "  public_base_url=${AGNI_PUBLIC_BASE_URL:-<not-set>}"
echo "  expected_deploy_sha=${EXPECTED_DEPLOY_SHA}"

REMOTE_ARGS=(
  bash -s --
  "${AGNI_REPO_PATH}"
  "${AGNI_BRANCH}"
  "${AGNI_CONTAINER_NAME}"
  "${AGNI_IMAGE}"
  "${AGNI_HOST_PORT}"
  "${AGNI_CONTAINER_PORT}"
  "${AGNI_DATA_DIR}"
  "${AGNI_DB_PATH}"
  "${AGNI_LOG_DIR}"
  "${AGNI_HEALTH_PATH}"
  "${AGNI_ROOT_PATH}"
  "${AGNI_TIMEOUT_SECONDS}"
  "${AGNI_RESTORE_BRANCH}"
  "${AGNI_PUBLIC_BASE_URL}"
  "${EXPECTED_DEPLOY_SHA}"
)
# OpenSSH joins remote argv into a shell command. Quote every argument into one
# explicit command string so operator-supplied values cannot become shell code.
printf -v REMOTE_COMMAND '%q ' "${REMOTE_ARGS[@]}"
SSH_OUTPUT_FILE="$(mktemp)"
cleanup_local() {
  rm -f -- "${SSH_OUTPUT_FILE}"
}
trap cleanup_local EXIT
set +e
ssh -- "${AGNI_SSH_TARGET}" "${REMOTE_COMMAND% }" <<'REMOTE' | tee "${SSH_OUTPUT_FILE}"
set -euo pipefail

REPO_PATH="$1"
TARGET_BRANCH="$2"
CONTAINER_NAME="$3"
IMAGE_NAME="$4"
HOST_PORT="$5"
CONTAINER_PORT="$6"
DATA_DIR="$7"
DB_PATH="$8"
LOG_DIR="$9"
HEALTH_PATH="${10}"
ROOT_PATH="${11}"
TIMEOUT_SECONDS="${12}"
RESTORE_BRANCH="${13}"
PUBLIC_BASE_URL="${14}"
REQUESTED_DEPLOY_SHA="${15}"

cd "${REPO_PATH}"
PREV_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
BUILD_CONTEXT=""
restore_branch() {
  if [[ -n "${BUILD_CONTEXT}" ]]; then
    rm -rf -- "${BUILD_CONTEXT}"
  fi
  if [[ "${RESTORE_BRANCH}" == "1" ]] && [[ "${PREV_BRANCH}" != "${TARGET_BRANCH}" ]]; then
    git checkout "${PREV_BRANCH}" >/dev/null 2>&1 || true
  fi
}
trap restore_branch EXIT

git fetch origin
git checkout "${TARGET_BRANCH}"
git pull --ff-only origin "${TARGET_BRANCH}"
DEPLOY_SHA="$(git rev-parse HEAD)"
REMOTE_BRANCH_SHA="$(git rev-parse "origin/${TARGET_BRANCH}")"
echo "deploy_sha=${DEPLOY_SHA}"
if [[ "${DEPLOY_SHA}" != "${REQUESTED_DEPLOY_SHA}" ]] || \
   [[ "${REMOTE_BRANCH_SHA}" != "${REQUESTED_DEPLOY_SHA}" ]]; then
  echo "ERROR: target branch moved or checkout does not match requested remote commit" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "ERROR: remote deployment worktree is dirty; refusing to mislabel image source" >&2
  exit 1
fi

BUILD_CONTEXT="$(mktemp -d)"
git archive --format=tar "${DEPLOY_SHA}" | tar -xf - -C "${BUILD_CONTEXT}"
docker build \
  --build-arg "SAB_BUILD_SHA=${DEPLOY_SHA}" \
  -t "${IMAGE_NAME}" \
  "${BUILD_CONTEXT}"

IMAGE_SHA="$(docker image inspect "${IMAGE_NAME}" --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}')"
if [[ ! "${IMAGE_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: image is missing a full Git revision label" >&2
  exit 1
fi
if [[ "${IMAGE_SHA}" != "${DEPLOY_SHA}" ]]; then
  echo "ERROR: image revision ${IMAGE_SHA} does not match checkout ${DEPLOY_SHA}" >&2
  exit 1
fi
IMAGE_ID="$(docker image inspect "${IMAGE_NAME}" --format '{{.Id}}')"
if [[ ! "${IMAGE_ID}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: built image is missing an immutable sha256 image ID" >&2
  exit 1
fi

mkdir -p "${DATA_DIR}" "${LOG_DIR}"
chown -R 1000:1000 "${DATA_DIR}" "${LOG_DIR}" || true

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
docker run -d --name "${CONTAINER_NAME}" --restart unless-stopped \
  -p "${HOST_PORT}:${CONTAINER_PORT}" \
  -e "SAB_AUTHORITY_DB_PATH=${DB_PATH}" \
  -e "SAB_BUILD_SHA=${IMAGE_SHA}" \
  -v "${DATA_DIR}:/app/data" \
  -v "${LOG_DIR}:/app/logs" \
  "${IMAGE_ID}" >/tmp/"${CONTAINER_NAME}".cid

for _ in $(seq 1 "${TIMEOUT_SECONDS}"); do
  if curl -fsS "http://127.0.0.1:${HOST_PORT}${HEALTH_PATH}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

ROOT_CODE="$(curl -fsS -o /dev/null -w "%{http_code}" "http://127.0.0.1:${HOST_PORT}${ROOT_PATH}")"
STATUS_CODE="$(curl -fsS -o /dev/null -w "%{http_code}" "http://127.0.0.1:${HOST_PORT}${HEALTH_PATH}")"
echo "root_code=${ROOT_CODE}"
echo "status_code=${STATUS_CODE}"
OPENAPI_SHA256="$(python3 scripts/check_deployment_parity.py \
  "http://127.0.0.1:${HOST_PORT}" \
  --expected-build-sha "${IMAGE_SHA}" \
  --openapi-sha256-only)"
if [[ ! "${OPENAPI_SHA256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "ERROR: internal OpenAPI did not produce one canonical SHA-256" >&2
  exit 1
fi
SAB_PARITY_VANTAGE=agni python3 scripts/check_deployment_parity.py \
  "${PUBLIC_BASE_URL}" \
  --expected-build-sha "${IMAGE_SHA}" \
  --expected-openapi-sha256 "${OPENAPI_SHA256}"
echo "sab_openapi_sha256=${OPENAPI_SHA256}"
docker ps --filter "name=${CONTAINER_NAME}" --format "container={{.Names}} image={{.Image}} ports={{.Ports}} status={{.Status}}"
REMOTE
PIPE_STATUSES=("${PIPESTATUS[@]}")
set -e
if (( PIPE_STATUSES[0] != 0 )); then
  exit "${PIPE_STATUSES[0]}"
fi
if (( PIPE_STATUSES[1] != 0 )); then
  exit "${PIPE_STATUSES[1]}"
fi

EXPECTED_OPENAPI_SHA256=""
OPENAPI_MARKER_COUNT=0
while IFS= read -r line; do
  case "${line}" in
    sab_openapi_sha256=*)
      EXPECTED_OPENAPI_SHA256="${line#sab_openapi_sha256=}"
      OPENAPI_MARKER_COUNT=$((OPENAPI_MARKER_COUNT + 1))
      ;;
  esac
done < "${SSH_OUTPUT_FILE}"
if (( OPENAPI_MARKER_COUNT != 1 )) || \
   [[ ! "${EXPECTED_OPENAPI_SHA256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "ERROR: remote deployment did not return one canonical OpenAPI SHA-256" >&2
  exit 1
fi

# Probe again from the caller, outside AGNI, so split DNS or an internal-only
# proxy cannot satisfy the public deployment gate.
SAB_PARITY_VANTAGE=external python3 \
  "${LOCAL_REPO_ROOT}/scripts/check_deployment_parity.py" \
  "${AGNI_PUBLIC_BASE_URL}" \
  --expected-build-sha "${EXPECTED_DEPLOY_SHA}" \
  --expected-openapi-sha256 "${EXPECTED_OPENAPI_SHA256}"
