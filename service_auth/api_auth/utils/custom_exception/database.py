from rest_framework import status
from rest_framework.exceptions import APIException


class RedisError(APIException):
    """Обработчик ошибки - ошибка с Redis."""

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "Ошибка при работе с Redis"
    default_code = "internal_server_error"
