from rest_framework import status
from rest_framework.exceptions import APIException


class UserNotFoundError(APIException):
    """Обработчик ошибки - Пользователь не найден."""

    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "User not found"
    default_code = "user_not_found_error"


class AuthDataInvalidError(APIException):
    """Обработчик ошибки - данные для авторизации невалидны."""

    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Not valid email or пароль"
    default_code = "user_login_data_error"


class TokenDataInvalidError(APIException):
    """Обработчик ошибки - данные токена невалидны."""

    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Invalid token, please login again"
    default_code = "token_error"
