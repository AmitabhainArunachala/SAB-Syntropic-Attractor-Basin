#!/usr/bin/env bash
set -euo pipefail

# Deploy the current target branch to AGNI via Docker.
# Run from local machine that has SSH access to AGNI.
#
# Example:
#   scripts/deploy_agni_docker.sh
#   AGNI_BRANCH=main AGNI_SSH_TARGET=agni scripts/deploy_agni_docker.sh
#   scripts/deploy_agni_docker.sh --no-build

usage() {
  cat <<'USAGE'
Usage: deploy_agni_docker.sh [--no-build]

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
  AGNI_PUBLIC_BASE_URL    Optional public origin for proxy/OpenAPI parity verification
  AGNI_TIMEOUT_SECONDS    Wait timeout for health (default: 90)
  AGNI_RESTORE_BRANCH     Restore remote branch after deploy: 1/0 (default: 1)
USAGE
}

NO_BUILD=0
if [[ $# -gt 1 ]]; then
  usage
  exit 1
fi
if [[ $# -eq 1 ]]; then
  case "$1" in
    --no-build)
      NO_BUILD=1
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

if [[ "${AGNI_HEALTH_PATH:0:1}" != "/" ]]; then
  AGNI_HEALTH_PATH="/${AGNI_HEALTH_PATH}"
fi
if [[ "${AGNI_ROOT_PATH:0:1}" != "/" ]]; then
  AGNI_ROOT_PATH="/${AGNI_ROOT_PATH}"
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
echo "  no_build=${NO_BUILD}"

ssh "${AGNI_SSH_TARGET}" bash -s -- \
  "${AGNI_REPO_PATH}" \
  "${AGNI_BRANCH}" \
  "${AGNI_CONTAINER_NAME}" \
  "${AGNI_IMAGE}" \
  "${AGNI_HOST_PORT}" \
  "${AGNI_CONTAINER_PORT}" \
  "${AGNI_DATA_DIR}" \
  "${AGNI_DB_PATH}" \
  "${AGNI_LOG_DIR}" \
  "${AGNI_HEALTH_PATH}" \
  "${AGNI_ROOT_PATH}" \
  "${AGNI_TIMEOUT_SECONDS}" \
  "${AGNI_RESTORE_BRANCH}" \
  "${NO_BUILD}" \
  "${AGNI_PUBLIC_BASE_URL}" <<'REMOTE'
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
NO_BUILD="${14}"
PUBLIC_BASE_URL="${15}"

cd "${REPO_PATH}"
PREV_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
restore_branch() {
  if [[ "${RESTORE_BRANCH}" == "1" ]] && [[ "${PREV_BRANCH}" != "${TARGET_BRANCH}" ]]; then
    git checkout "${PREV_BRANCH}" >/dev/null 2>&1 || true
  fi
}
trap restore_branch EXIT

git fetch origin
git checkout "${TARGET_BRANCH}"
git pull --ff-only origin "${TARGET_BRANCH}"
DEPLOY_SHA="$(git rev-parse HEAD)"
echo "deploy_sha=${DEPLOY_SHA}"

if [[ "${NO_BUILD}" == "1" ]]; then
  echo "skip_build=1"
else
  docker build --build-arg "SAB_BUILD_SHA=${DEPLOY_SHA}" -t "${IMAGE_NAME}" .
fi

IMAGE_SHA="$(docker image inspect "${IMAGE_NAME}" --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}')"
if [[ ! "${IMAGE_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: image is missing a full Git revision label" >&2
  exit 1
fi
if [[ "${IMAGE_SHA}" != "${DEPLOY_SHA}" ]]; then
  echo "ERROR: image revision ${IMAGE_SHA} does not match checkout ${DEPLOY_SHA}" >&2
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
  "${IMAGE_NAME}" >/tmp/"${CONTAINER_NAME}".cid

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
python3 scripts/check_deployment_parity.py \
  "http://127.0.0.1:${HOST_PORT}" \
  --expected-build-sha "${IMAGE_SHA}"
if [[ -n "${PUBLIC_BASE_URL}" ]]; then
  python3 scripts/check_deployment_parity.py \
    "${PUBLIC_BASE_URL}" \
    --expected-build-sha "${IMAGE_SHA}"
fi
docker ps --filter "name=${CONTAINER_NAME}" --format "container={{.Names}} image={{.Image}} ports={{.Ports}} status={{.Status}}"
REMOTE
