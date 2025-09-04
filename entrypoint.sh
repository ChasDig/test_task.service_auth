#!/usr/bin/env bash

set -e

echo "🔄 Выполнение миграций..."
python manage.py migrate
python manage.py collectstatic --no-input

echo "🔄 Загрузка тестовых данных..."
python ./load_test_data/load_data.py

echo "🚀 Запуск приложения..."
uvicorn service_auth.asgi:application --host 0.0.0.0 --port 8000 --workers 4
