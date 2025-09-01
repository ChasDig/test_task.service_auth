import os

import dotenv

dotenv.load_dotenv()

# Postgres
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("AUTH_POSTGRES_DB", "auth_db"),
        "USER": os.environ.get("AUTH_POSTGRES_USER", "auth_user"),
        "PASSWORD": os.environ.get("AUTH_POSTGRES_PASSWORD"),
        "HOST": os.environ.get("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.environ.get("POSTGRES_PORT", 5432),
    },
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Redis
REDIS_DB = int(os.environ.get("AUTH_REDIS_DB", 0))
REDIS_MAX_CONNECTION_POOL = int(
    os.environ.get(
        "AUTH_REDIS_MAX_CONNECTION_POOL",
        50,
    )
)
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = os.environ.get("REDIS_PORT", 6379)
