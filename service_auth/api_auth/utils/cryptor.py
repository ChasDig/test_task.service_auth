import base64
import os

from django.conf import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .hasher import Hasher


class Cryptor:
    """Utils - шифрование данных."""

    @staticmethod
    def encrypt_str(str_: str, password: str | None = None) -> str:
        """
        Шифрование строки.

        @type str_: str
        @param str_:
        @type password: str | None
        @param password: Мастер-пароль (в открытом виде).

        @rtype: str
        @return:
        """
        salt = os.urandom(settings.SALT_LENGTH_BYTES)
        nonce = os.urandom(settings.NONCE_LENGTH_BYTES)
        if password is None:
            password = settings.EMAIL_MASTER_PASSWORD

        key = Hasher.gen_driver_key(password=password, salt=salt)

        aes_gcm = AESGCM(key)
        ciphertext = aes_gcm.encrypt(nonce, str_.encode(), None)

        encrypted_block = salt + nonce + ciphertext
        return base64.b64encode(encrypted_block).decode()

    @staticmethod
    def decrypt_str(str_: str, password: str | None = None) -> str:
        """
        Расшифровывание строки.

        @type str_: str
        @param str_:
        @type password: str | None
        @param password: Мастер-пароль (в открытом виде).

        @rtype: str
        @return:
        """
        if password is None:
            password = settings.EMAIL_MASTER_PASSWORD

        decoded = base64.b64decode(str_.encode())

        salt_len = settings.SALT_LENGTH_BYTES
        nonce_len = settings.NONCE_LENGTH_BYTES
        salt = decoded[:salt_len]

        nonce = decoded[salt_len : salt_len + nonce_len]
        ciphertext = decoded[salt_len + nonce_len :]

        key = Hasher.gen_driver_key(password=password, salt=salt)
        aes_gcm = AESGCM(key)
        decrypted = aes_gcm.decrypt(nonce, ciphertext, None)

        return decrypted.decode()
