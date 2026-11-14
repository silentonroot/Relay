#!/usr/bin/env bash
#
# Scans one image for known vulnerabilities.
#
#   infra/ci/scan-image.sh aab/broker-api:local          an image in the local Docker store
#   infra/ci/scan-image.sh --archive path/to/image.tar   an archive written by `docker save` or
#                                                        `docker buildx build --output type=docker`
#
# Exits non-zero when the image has a HIGH or CRITICAL vulnerability for which a fixed version
# exists. Vulnerabilities without a fix are neither reported nor counted (--ignore-unfixed
# hides them), because nothing can be done about them by rebuilding.
#
# The scanner (Trivy) runs from an image pinned by digest. It reads an archive of the image, so
# it is given neither the Docker socket nor the repository. It needs network access to fetch
# its vulnerability database.
#
# STATUS: NOT YET RUN. Written with the nightly and release workflows.
set -euo pipefail

scanner='ghcr.io/aquasecurity/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb'

work="$(mktemp -d "${TMPDIR:-/tmp}/aab-scan.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
chmod 755 "${work}"

if [ "${1:-}" = "--archive" ]; then
  archive="${2:?usage: scan-image.sh --archive <file>}"
  cp "${archive}" "${work}/image.tar"
else
  image="${1:?usage: scan-image.sh <image> | --archive <file>}"
  docker save "${image}" --output "${work}/image.tar"
fi
chmod 644 "${work}/image.tar"

docker run --rm \
  --read-only --tmpfs /tmp --tmpfs /root/.cache \
  --cap-drop ALL --security-opt no-new-privileges \
  --volume "${work}:/scan:ro" \
  "${scanner}" image \
  --input /scan/image.tar \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --exit-code 1 \
  --no-progress
