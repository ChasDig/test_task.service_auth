import os

import dotenv

dotenv.load_dotenv()

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Token
TOKEN_ALGORITHM = os.environ.get("AUTH_TOKEN_ALGORITHM", "HS256")
TOKEN_SECRET = os.environ.get("AUTH_TOKEN_SECRET", "token_sec")
REFRESH_TOKEN_EXP_DAYS = os.environ.get("AUTH_REFRESH_TOKEN_EXP_DAYS", 7)
ACCESS_TOKEN_EXP_MIN = os.environ.get("AUTH_ACCESS_TOKEN_EXP_MIN", 30)

# UserPermissionsByGroup
USER_PERMISSION_BY_GROUP_EXP_MIN = 15
