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

        :param password: Мастер-пароль (в открытом виде).
        :type password: str
        :param salt:
        :type salt: bytes

        :return:
        :rtype: bytes
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

        :param str_:
        :type str_: str
        :param password: Пароль в открытом виде.
        :type password: str

        :return:
        :rtype: str
        """
        normalize_str = str_.lower().strip()

        return hmac.new(
            password.encode(),
            normalize_str.encode(),
            hashlib.sha256,
        ).hexdigest()
