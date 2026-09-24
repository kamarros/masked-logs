#!/usr/bin/env bash
# Publishes a release (parent pom + starter jar, sources) to a file based Maven repository,
# e.g. <application>/devops/libs, until a company artifact repository is available.
#
# Usage: publish-to-project-repo.sh <path-to-file-repository> <version>
#   e.g. publish-to-project-repo.sh ../santirek/santirek-backend/devops/libs 1.0.1
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <path-to-file-repository> <version>" >&2
    exit 1
fi

VERSION="$2"
case "$VERSION" in
    *-SNAPSHOT) echo "Refusing to publish a SNAPSHOT - use 'mvn install' for local development" >&2; exit 1 ;;
esac

# pwd -W gives a Windows path (C:/...) in Git Bash; plain pwd elsewhere
REPO_DIR="$(cd "$1" && (pwd -W 2>/dev/null || pwd))"
case "$REPO_DIR" in
    /*) REPO_URL="file://${REPO_DIR}" ;;
    *) REPO_URL="file:///${REPO_DIR}" ;;
esac
ARTIFACTS_DIR="${REPO_DIR}/pl/apilia/logging"

if [ -d "${ARTIFACTS_DIR}/log-masking-spring-boot-starter/${VERSION}" ]; then
    echo "Version ${VERSION} already published in ${REPO_DIR} - releases are immutable, bump the version" >&2
    exit 1
fi

cd "$(dirname "$0")/.."

mvn -B clean deploy -Drevision="${VERSION}" -DaltDeploymentRepository="project-libs::${REPO_URL}"

# keep only .sha1 - enough for Maven to verify downloads (without any checksum it logs
# "Could not validate integrity" warnings on every fresh build); .md5 is redundant
find "${ARTIFACTS_DIR}" -type f -name '*.md5' -delete

echo "Published ${VERSION} to ${REPO_DIR}"
