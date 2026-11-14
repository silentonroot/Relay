#!/usr/bin/env bash
#
# Prepares a GitHub-hosted Ubuntu runner for the bubblewrap sandbox tests and the end-to-end
# test: bubblewrap, a virtual display, a Chromium build, unprivileged user namespaces, a short
# private runtime directory and, when asked, a throwaway PostgreSQL cluster.
#
#   infra/ci/sandbox-prereqs.sh             sandbox tests
#   infra/ci/sandbox-prereqs.sh --postgres  also start PostgreSQL for the end-to-end test
#
# STATUS: ran on a GitHub runner in the nightly of 2026-11-14 (without --postgres) and the sandbox
# tests passed. The --postgres path has not run on a runner. It uses sudo and changes a
# kernel setting, so it is meant for disposable runners only. Do not run it on a workstation:
# docs/operations.md describes the local prerequisites instead.
#
# Run it from the repository root after dependencies are installed. It appends the variables
# later steps need to $GITHUB_ENV.
set -euo pipefail

want_postgres=0
[ "${1:-}" = "--postgres" ] && want_postgres=1

if [ -z "${GITHUB_ENV:-}" ] || [ "${CI:-}" != "true" ]; then
  echo "refusing to run outside continuous integration (CI=true and GITHUB_ENV are required)" >&2
  exit 1
fi

sudo apt-get update --quiet
sudo apt-get install --yes --no-install-recommends bubblewrap xvfb xdotool xauth

# The launcher runs Node inside the sandbox at /usr/bin/node (its default nodePath), and it
# mounts only binaries that are not under /usr. setup-node installs Node under
# /opt/hostedtoolcache, so a copy is placed at /usr/bin/node (a symlink would dangle inside
# the sandbox). install replaces an existing file or symlink.
node_bin="$(readlink -f "$(command -v node)")"
if [ "${node_bin}" != "$(readlink -f /usr/bin/node 2>/dev/null || true)" ]; then
  sudo install --mode=0755 "${node_bin}" /usr/bin/node
fi
/usr/bin/node --version

# Ubuntu 24.04 lets only AppArmor-confined programs create user namespaces. bubblewrap and
# Chromium's own sandbox both need them, so the restriction is lifted on this disposable
# machine. A long-lived host should use AppArmor profiles for the two programs instead.
if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
  sudo sysctl --write kernel.apparmor_restrict_unprivileged_userns=0
fi

# Chromium: the build that matches the installed playwright-core, plus its system libraries.
# It lands under ~/.cache/ms-playwright; the sandbox launcher mounts the binary's directory.
cli="$(pwd)/services/browser-worker/node_modules/playwright-core/cli.js"
node "${cli}" install --with-deps chromium
chromium="$(cd services/browser-worker && node --input-type=module --eval \
  "import { chromium } from 'playwright-core'; process.stdout.write(chromium.executablePath());")"
[ -x "${chromium}" ] || {
  echo "Chromium was not installed at ${chromium}" >&2
  exit 1
}

# Unix socket paths are limited to about 100 bytes, so the per-job runtime directories need a
# short base. /run/user/<uid> exists only for login sessions; create it for the runner user.
runtime="/run/user/$(id -u)"
sudo mkdir -p "${runtime}"
sudo chown "$(id -u):$(id -g)" "${runtime}"
chmod 700 "${runtime}"

{
  echo "AAB_TEST_CHROMIUM_PATH=${chromium}"
  echo "AAB_CHROMIUM_PATH=${chromium}"
  echo "XDG_RUNTIME_DIR=${runtime}"
} >>"${GITHUB_ENV}"

# Fail here, with a clear message, if a sandbox still cannot be created.
bwrap --unshare-all --die-with-parent --ro-bind /usr /usr --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 --symlink usr/bin /bin --proc /proc --dev /dev /usr/bin/true ||
  {
    echo "bubblewrap cannot create a sandbox on this runner" >&2
    exit 1
  }

if [ "${want_postgres}" = "1" ]; then
  # The end-to-end test wants a server on a private Unix socket where the current user may
  # create databases, and the client tools. Use the newest installed PostgreSQL, or install
  # the distribution's.
  bin="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort --version-sort | tail -1 || true)"
  if [ -z "${bin}" ] || [ ! -x "${bin}/initdb" ] || [ ! -x "${bin}/psql" ] ||
    [ ! -x "${bin}/createdb" ] || [ ! -x "${bin}/dropdb" ]; then
    sudo apt-get install --yes --no-install-recommends postgresql
    bin="$(ls -d /usr/lib/postgresql/*/bin | sort --version-sort | tail -1)"
  fi
  socket_dir="${runtime}/aab-pg"
  data_dir="${RUNNER_TEMP:-/tmp}/aab-pgdata"
  mkdir -p -m 700 "${socket_dir}"
  "${bin}/initdb" --pgdata "${data_dir}" --auth trust --encoding UTF8 --no-sync >/dev/null
  "${bin}/pg_ctl" --pgdata "${data_dir}" --wait --log "${data_dir}.log" \
    --options "-c listen_addresses='' -c unix_socket_directories=${socket_dir} -c port=54329 -c fsync=off" \
    start
  {
    echo "AAB_E2E_PG_BIN=${bin}"
    echo "AAB_E2E_PG_DIR=${socket_dir}"
    echo "AAB_E2E_PG_PORT=54329"
  } >>"${GITHUB_ENV}"
fi

echo "sandbox prerequisites are in place"
