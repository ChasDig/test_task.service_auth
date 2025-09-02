from asgiref.sync import async_to_sync
from rest_framework.exceptions import NotAuthenticated
from rest_framework.permissions import BasePermission

from .database import redis_context_manager
from .utils import Tokenizer
from .utils.custom_enum import TokenType
from .models import UsersRole


class CookieTokenPermission(BasePermission):

    def has_permission(self, request, view) -> bool:
        try:
            access_token = request.get_signed_cookie(TokenType.access.name)

        except KeyError:
            raise NotAuthenticated(detail="token not allowed")

        user_id = self._get_user_id_by_token(access_token)
        user_agent = request.META.get("HTTP_USER_AGENT", "not_user_agent")

        access_token_from_redis = async_to_sync(self._get_token_from_redis)(
            user_id,
            user_agent,
            TokenType.access.name,
        )

        if access_token_from_redis != access_token:
            raise NotAuthenticated(detail="token not allowed")

        return True

    @staticmethod
    def _get_user_id_by_token(access_token: str) -> str:
        token_payload = Tokenizer.decode_token(access_token)

        return str(token_payload.sub)

    @staticmethod
    async def _get_token_from_redis(
        user_id: str,
        user_agent: str,
        token_type: str,
    ) -> str | None:
        async with redis_context_manager() as redis_client:
            token_from_redis = await redis_client.get(
                key=Tokenizer.token_key_template.format(
                    user_id=user_id,
                    user_agent=user_agent,
                    token_type=token_type,
                )
            )

            return token_from_redis


class IsSelfOrAdminPermission(BasePermission):

    def has_permission(self, request, view) -> bool:
        try:
            user_id_from_query = view.kwargs["pk"]
            access_token = request.get_signed_cookie(TokenType.access.name)

        except KeyError:
            raise NotAuthenticated(detail="token not allowed")

        high_lvl_roles = (UsersRole.ADMIN.value, UsersRole.SUPERUSER.value)
        access_token_payload = Tokenizer.decode_token(access_token)

        if (
            user_id_from_query == access_token_payload.sub
        ) or (
            access_token_payload.user_role in high_lvl_roles
        ):
            return True

        return False

class ChangeUserRolePermission(BasePermission):

    def has_permission(self, request, view) -> bool:
        user_role = request.data.get("role")
        access_token = request.get_signed_cookie(TokenType.access.name)
        access_token_payload = Tokenizer.decode_token(access_token)

        high_lvl_users_roles = (UsersRole.ADMIN.value, UsersRole.SUPERUSER.value)

        update_user_role_in_high_lvl_roles = user_role in high_lvl_users_roles
        request_user_have_high_lvl_role = (
            access_token_payload.user_role in high_lvl_users_roles
        )
        if (
            user_role and
            (not request_user_have_high_lvl_role) and
            update_user_role_in_high_lvl_roles
        ):
            return False

        return True
