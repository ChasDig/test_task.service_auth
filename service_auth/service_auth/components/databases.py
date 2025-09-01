import os

import dotenv

dotenv.load_dotenv()

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
