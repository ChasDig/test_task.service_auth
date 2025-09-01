import os
from pathlib import Path

import dotenv
from split_settings.tools import include

dotenv.load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("AUTH_SECRET_KEY")
DEBUG = os.environ.get("ADMIN_DEBUG", False) == "True"

ALLOWED_HOSTS = os.environ.get(
    "AUTH_ALLOWED_HOSTS",
    ["localhost", "127.0.0.1"],
)

ROOT_URLCONF = 'service_auth.urls'

WSGI_APPLICATION = 'service_auth.wsgi.application'

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

STATIC_URL = 'static/'

# Components configs
include(
    "components/databases.py",
    "components/installed_apps.py",
    "components/middleware.py",
    "components/templates.py",
    "components/auth_password_validators.py",
    "components/rest_framework.py",
    "components/open_api.py",
    "components/cors.py",
    "components/hasher.py",
)
