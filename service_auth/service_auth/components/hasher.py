import os

import dotenv

dotenv.load_dotenv()

# Хеширование
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]
LENGTH_HASH = int(os.environ.get("HASHER_SALT_LENGTH_BYTES", 32))
COUNT_HASH_ITER = int(os.environ.get("HASHER_COUNT_ITER", 100_000))

# Шифрование
SALT_LENGTH_BYTES = int(os.environ.get("CRYPTO_SALT_LENGTH_BYTES", 16))
NONCE_LENGTH_BYTES = int(os.environ.get("CRYPTO_NONCE_LENGTH_BYTES", 12))

# Список мастер-паролей для Шифрования под разные сущности
EMAIL_MASTER_PASSWORD = os.environ.get("CRYPTO_EMAIL_MASTER_PASSWORD")
