import logging
from datetime import UTC, datetime, timedelta

from django.conf import settings

from asgiref.sync import async_to_sync
from rest_framework.response import Response

from ..database import redis_context_manager
from ..models import Resource, User
from .custom_dataclasses import Tokens
from .custom_enum import TokenType
from .custom_exception import RedisError, UserNotFoundError
from .tokenizer import Tokenizer

logger = logging.getLogger(__name__)


class TokenizerWorkMixin(Tokenizer):
    """Work - mixin по работе с Tokenizer."""

    def _refresh_tokens(
        self,
        user: User,
        response: Response,
        user_agent: str = "not_user_agent",
    ) -> Tokens:
        """
        Обновление токенов в Redis и Cookies.

        :param user:
        :type user: User
        :param response:
        :type response: Response
        :param user_agent:
        :type user_agent: str

        :return:
        :rtype: str | Any
        """
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
        """
        Сохранение токенов в Redis.

        :param user:
        :type user: User
        :param tokens:
        :type tokens: Tokens
        :param user_agent:
        :type user_agent: str

        :return:
        :rtype: None
        """
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
        all_device: bool = False,
    ) -> None:
        """
        Удаление токенов в Redis.

        :param user:
        :type user: User
        :param all_device: Флаг - удалять все токены.
        :type all_device: bool
        :param user_agent:
        :type user_agent: str

        :return:
        :rtype: None
        """
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
        """
        Получение Пользователя по токену.

        :param token:
        :type token: str

        :return:
        :rtype: User
        """
        try:
            return User.objects.get(
                pk=str(Tokenizer.decode_token(token).sub),
                deleted_at__isnull=True,
            )

        except User.DoesNotExist:
            raise UserNotFoundError()

    @staticmethod
    async def _get_token_from_redis(
        user_id: str,
        user_agent: str,
        token_type: str,
    ) -> dict[str, str | int] | str | None:
        """
        Получение токена из Redis.

        :param user_id:
        :type user_id: str
        :param token_type:
        :type token_type: str
        :param user_agent:
        :type user_agent: str

        :return:
        :rtype: dict[str, str | int] | str | None
        """
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
    """Work - mixin по работе с правками доступа Пользователя."""

    user_permission_tag = "user_permission"

    async def _get_user_permissions_from_redis(
        self,
        user_id: str,
    ) -> dict[str, str | int] | str | None:
        """
        Получение прав доступа Пользователя из Redis.

        :param user_id:
        :type user_id: str

        :return:
        :rtype: dict[str, str | int] | str | None
        """
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
        """
        Сохранение прав доступа Пользователя в Redis.

        :param user_id:
        :type user_id: str
        :param user_permissions:
        :type user_permissions: dict[str, str]

        :return:
        :rtype: None
        """
        now_ = datetime.now(UTC)
        permissions_exp = (
            now_ + timedelta(minutes=settings.USER_PERMISSION_BY_GROUP_EXP_MIN)
        ).timestamp()

        async with redis_context_manager() as redis_client:
            await redis_client.set(
                key=f"{user_id}&{self.user_permission_tag}",
                value=user_permissions,  # type: ignore
                ttl=int(permissions_exp - now_.timestamp()),
            )

    @staticmethod
    def _get_user_permissions_by_groups(user_id: str) -> dict[str, str]:
        """
        Получение прав доступа Пользователя по Группам из Postgres.

        :param user_id:
        :type user_id: str

        :return:
        :rtype: dict[str, str]
        """
        resources_qs = Resource.objects.filter(
            group_permission__group__user_by_group__user__id=user_id,
            group_permission__group__user_by_group__deleted_at__isnull=True,  # noqa: E501
        )

        return {
            resource_qs.name: resource_qs.uri for resource_qs in resources_qs
        }

    async def _delete_user_permissions_in_redis(self, user_id: str) -> None:
        """
        Удаление прав доступа Пользователя из Redis.

        :param user_id:
        :type user_id: str

        :return:
        :rtype: None
        """
        async with redis_context_manager() as redis_client:
            try:
                await redis_client.delete(
                    key=f"{user_id}&{self.user_permission_tag}",
                )

            except RedisError as ex:
                logger.error(f"Error delete permission: {ex}")


class PasswordCheckerWorker:
    """Worker - проверка пароля."""

    @staticmethod
    def check_password(value: str) -> bool:
        if len(value) < 8:
            return False

        elif not any(s.isupper() for s in value):
            return False

        return True
