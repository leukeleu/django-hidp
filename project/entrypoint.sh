#!/usr/bin/env bash
set -e # Exit on error

# Make sure uv is up-to-date
sudo python -m pip install --root-user-action=ignore -U uv

uv venv --allow-existing

echo "Installing dependencies..."
uv sync

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
uv run manage.py collectstatic --clear --link --no-input

echo "Migrating database..."
uv run manage.py migrate

echo "Starting server..."
exec uv run python -W module manage.py runserver 0:"${DJANGO_RUNSERVER_PORT:-8000}"
