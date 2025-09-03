import logging
from datetime import datetime, UTC, timedelta

from django.conf import settings
from rest_framework.response import Response
from asgiref.sync import async_to_sync

from .custom_dataclasses import Tokens
from .custom_enum import TokenType
from .custom_exception import UserNotFoundError, RedisError
from .tokenizer import Tokenizer
from ..database import redis_context_manager
from ..models import User, PermissionByGroup

logger = logging.getLogger(__name__)


class TokenizerWorkMixin(Tokenizer):

    def _refresh_tokens(
        self,
        user: User,
        response: Response,
        user_agent: str = "not_user_agent",
    ) -> Tokens:
        tokens = Tokenizer.gen_tokens(
            user_id=str(user.id),
            user_role=user.role,
            user_agent=user_agent,
        )
        async_to_sync(self._delete_old_tokens_from_redis)(user, user_agent)
        async_to_sync(self._save_tokens_in_redis)(tokens, user, user_agent)

        response.set_signed_cookie(
            key=TokenType.access.name,
            value=tokens.access_token.token,
            httponly=True,
            secure=not settings.DEBUG,
            samesite="Strict",
        )
        response.set_signed_cookie(
            key=TokenType.refresh.name,
            value=tokens.refresh_token.token,
            httponly=True,
            secure=not settings.DEBUG,
            samesite="Strict",
        )

        return tokens

    @staticmethod
    async def _save_tokens_in_redis(
        tokens: Tokens,
        user: User,
        user_agent: str = "not_user_agent",
    ) -> None:
        for_gen, user_id = f"{user.last_name} / {user_agent}", str(user.id)

        async with redis_context_manager() as redis_client:
            await redis_client.set(
                key=Tokenizer.token_key_template.format(
                    user_id=user_id,
                    user_agent=user_agent,
                    token_type=tokens.access_token.type,
                ),
                value=tokens.access_token.token,
                ttl=tokens.access_token.ttl,
            )
            logger.debug(f"{tokens.access_token.type} token gen {for_gen}")

            await redis_client.set(
                key=Tokenizer.token_key_template.format(
                    user_id=user_id,
                    user_agent=user_agent,
                    token_type=tokens.refresh_token.type,
                ),
                value=tokens.refresh_token.token,
                ttl=tokens.refresh_token.ttl,
            )
            logger.debug(f"{tokens.refresh_token.type} token gen {for_gen}")

    @staticmethod
    async def _delete_old_tokens_from_redis(
        user: User,
        user_agent: str = "not_user_agent",
        all_device: bool = False
    ) -> None:
        if all_device:
            pattern = Tokenizer.token_key_sort_template.format(
                user_id=str(user.id),
            )
            del_for = user.last_name

        else:
            pattern = Tokenizer.token_key_template.format(
                user_id=str(user.id),
                user_agent=user_agent,
                token_type="*",
            )
            del_for = f"{user.last_name} / {user_agent}"

        async with redis_context_manager() as redis_client:
            await redis_client.delete_by_pattern(pattern=pattern)

            logger.debug(f"All old tokens delete for {del_for}")

    @staticmethod
    def _get_user_by_token(token: str) -> User:
        try:
            return User.objects.get(pk=str(Tokenizer.decode_token(token).sub))

        except User.DoesNotExist:
            raise UserNotFoundError()

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


class UsersPermissionsWorkMixin:

    user_permission_tag = "user_permission"

    async def _get_user_permissions_from_redis(self, user_id: str):
        async with redis_context_manager() as redis_client:
            user_permissions = await redis_client.get(
                key=f"{user_id}&{self.user_permission_tag}",
                as_dict=True,
            )

            return user_permissions

    async def _set_user_permissions_in_redis(
        self,
        user_id: str,
        user_permissions: dict[str, str],
    ) -> None:
        now_ = datetime.now(UTC)
        permissions_exp = (
            now_ + timedelta(minutes=settings.USER_PERMISSION_BY_GROUP_EXP_MIN)
        ).timestamp()

        async with redis_context_manager() as redis_client:
            await redis_client.set(
                key=f"{user_id}&{self.user_permission_tag}",
                value=user_permissions,
                ttl=int(permissions_exp - now_.timestamp()),
            )

    @staticmethod
    def _get_user_permissions_by_groups(user_id: str) -> dict[str, str]:
        permissions_by_groups_qs = (
            PermissionByGroup.objects.filter(
                group__user_by_group__user__id=user_id,
            )
        )

        return {
            permission_by_group.uri_name: permission_by_group.uri
            for permission_by_group in permissions_by_groups_qs
        }

    async def _delete_user_permissions_in_redis(self, user_id: str) -> None:
        async with redis_context_manager() as redis_client:
            try:
                await redis_client.delete(
                    key=f"{user_id}&{self.user_permission_tag}",
                )

            except RedisError as ex:
                logger.error(f"Error delete permission: {ex}")
