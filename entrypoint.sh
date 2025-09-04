#!/usr/bin/env bash

set -e

python manage.py migrate
python manage.py collectstatic --no-input
uvicorn service_auth.asgi:application --host 0.0.0.0 --port 8000 --workers 4
