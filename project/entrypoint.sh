#!/usr/bin/env bash
set -e # Exit on error

# Make sure uv is up-to-date
sudo python -m pip install --root-user-action=ignore -U uv

_VENV=$(realpath "../var/venv")
_FROZEN_PROJECT_REQUIREMENTS=$(realpath "../var/requirements_project_frozen.txt")
_FROZEN_PACKAGE_REQUIREMENTS=$(realpath "../var/requirements_package_frozen.txt")

if [ ! -f "${_VENV}/bin/activate" ]; then
  echo "Creating virtual environment..."
  uv venv "${_VENV}"
  # Remove the frozen requirements file hash, to force installation of dependencies
  rm -f "${_FROZEN_PROJECT_REQUIREMENTS}.sha1" "${_FROZEN_PACKAGE_REQUIREMENTS}.sha1"
fi

echo "Gathering dependencies..."

# Project requirements
uv pip compile ./requirements_local.txt -o "${_FROZEN_PROJECT_REQUIREMENTS}" --upgrade --no-annotate --no-header -q

# Package requirements
pushd "../packages/hidp"
uv pip compile ./requirements_local.txt -o "${_FROZEN_PACKAGE_REQUIREMENTS}" --upgrade --no-annotate --no-header -q
popd

# Install dependencies if:
# - sha1sum -c <file>.sha1 has a non-zero exit code because either:
#   - Checksum file (<file>.sha1) does not exist
#   - <file> has changed
if ! sha1sum -c "${_FROZEN_PROJECT_REQUIREMENTS}.sha1" || ! sha1sum -c "${_FROZEN_PACKAGE_REQUIREMENTS}.sha1"; then
  echo "Installing dependencies..."

  # Project requirements
  uv pip install -r "${_FROZEN_PROJECT_REQUIREMENTS}"

  # Package requirements
  pushd "../packages/hidp"
  uv pip install -r "${_FROZEN_PACKAGE_REQUIREMENTS}"
  popd

  # Update checksums
  sha1sum "${_FROZEN_PROJECT_REQUIREMENTS}" > "${_FROZEN_PROJECT_REQUIREMENTS}.sha1"
  sha1sum "${_FROZEN_PACKAGE_REQUIREMENTS}" > "${_FROZEN_PACKAGE_REQUIREMENTS}.sha1"
fi

if [ ! -f '../var/oidc.key' ]; then
    echo "Generating OIDC key..."
    openssl genrsa -out '../var/oidc.key' 4096
fi

if [ ! -f './hidp_sandbox/local.ini' ]; then
    echo "Creating local.ini..."
    cp './hidp_sandbox/local.example.ini' './hidp_sandbox/local.ini'
fi

# NOTE: To debug issues with the container, without starting the server,
#       run the container with the argument "debug-container".
if [ "${1}" = "debug-container" ]; then
  echo "Sleeping forever..."
  sleep infinity
fi

echo "Collecting static files..."
python ./manage.py collectstatic --clear --link --no-input

echo "Migrating database..."
python ./manage.py migrate

echo "Starting server..."
exec python -W module ./manage.py runserver 0:"${DJANGO_RUNSERVER_PORT:-8000}"
