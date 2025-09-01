import hashlib
import hmac

from django.conf import settings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Hasher:
    """Utils - хеширование данных."""

    password_template = "{iter}{delimiter}{salt}{delimiter}{password_hash_str}"

    @staticmethod
    def gen_driver_key(password: str, salt: bytes) -> bytes:
        """
        Хеширование пароля благодаря функции формирования ключа PBKDF2-HMAC.

        @type password: str
        @param password: Мастер-пароль (в открытом виде).
        @type salt: bytes
        @param salt: Соль.

        @rtype: bytes
        @return:
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=settings.LENGTH_HASH,
            salt=salt,
            iterations=settings.COUNT_HASH_ITER,
        )

        return kdf.derive(password.encode())

    @staticmethod
    def hash_str(str_: str, password: str) -> str:
        """
        Хеширование строки.

        @type str_: str
        @param str_:
        @type password: str
        @param password: Пароль в открытом виде.

        @rtype: str
        @return:
        """
        normalize_str = str_.lower().strip()

        return hmac.new(
            password.encode(),
            normalize_str.encode(),
            hashlib.sha256,
        ).hexdigest()
