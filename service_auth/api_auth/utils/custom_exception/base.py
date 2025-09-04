from rest_framework import status
from rest_framework.exceptions import APIException


class EntityHasRelations(APIException):
    """Обработчик ошибки - ресурс с мягким удалением имеет активные связи."""

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Entity Has Relations"
    default_code = "entity-has-relations"
