INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',  # Django REST Framework
    'corsheaders',  # CORS headers
    'drf_spectacular',  # OpenAPI
    'api_auth.apps.ApiAuthConfig', # APIAuth
]
