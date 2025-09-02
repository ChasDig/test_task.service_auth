import logging
from copy import deepcopy

from django.conf import settings
from django.contrib.auth.hashers import check_password
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from asgiref.sync import async_to_sync

from .models import User
from .database import redis_context_manager
from .utils import Hasher
from .utils.tokenizer import Tokenizer
from .utils.custom_enum import TokenType
from .utils.custom_dataclasses import Tokens
from .utils.custom_exception import UserNotFoundError, AuthDataInvalidError
from .permissions import (
    CookieTokenPermission,
    IsSelfOrAdminPermission,
    ChangeUserRolePermission,
)
from .serializers import (
    UserCreateSerializer,
    UserUpdateSerializer,
    LoginSerializer,
    LogoutSerializer,
)

logger = logging.getLogger(__name__)


class UserCreateView(generics.CreateAPIView):
    serializer_class = UserCreateSerializer
    permission_classes = [AllowAny]


class LoginView(APIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = User.objects.get(
                email_hash=Hasher.hash_str(
                    str_=serializer.validated_data["email"],
                    password=settings.EMAIL_MASTER_PASSWORD,
                ),
            )

        except User.DoesNotExist:
            raise UserNotFoundError()

        if not check_password(
            serializer.validated_data["password"],
            user.password_hash,
        ):
            raise AuthDataInvalidError()

        user_agent = request.META.get("HTTP_USER_AGENT", "not_user_agent")
        tokens = Tokenizer.gen_tokens(
            user_id=str(user.id),
            user_role=user.role,
            user_agent=user_agent,
        )
        async_to_sync(self._delete_old_tokens)(user, user_agent)
        async_to_sync(self._save_tokens)(tokens, user, user_agent)

        response = Response()
        response.set_signed_cookie(
            key=TokenType.access.name,
            value=tokens.access_token.token,
            httponly=True,
            secure=not settings.DEBUG,
            samesite="Strict",
        )

        return response

    @staticmethod
    async def _save_tokens(
        tokens: Tokens,
        user: User,
        user_agent: str,
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
    async def _delete_old_tokens(user: User, user_agent: str) -> None:
        async with redis_context_manager() as redis_client:
            await redis_client.delete_by_pattern(
                pattern=Tokenizer.token_key_template.format(
                    user_id=str(user.id),
                    user_agent=user_agent,
                    token_type="*",
                ),
            )
            logger.debug(
                f"All old tokens delete for {user.last_name} / {user_agent}"
            )


class LogoutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [CookieTokenPermission]

    def post(self, request) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_agent = request.META.get("HTTP_USER_AGENT", "not_user_agent")
        all_device = serializer.validated_data.get("all_device", False)

        user_id = self._get_user_id_by_token(
            access_token=request.get_signed_cookie(TokenType.access.name),
        )
        async_to_sync(self._delete_old_tokens)(user_id, user_agent, all_device)

        response = Response()
        response.delete_cookie(TokenType.access.name)

        return response

    @staticmethod
    def _get_user_id_by_token(access_token: str) -> str:
        token_payload = Tokenizer.decode_token(access_token)

        return str(token_payload.sub)

    @staticmethod
    async def _delete_old_tokens(
        user_id: str,
        user_agent: str,
        all_device: bool,
    ) -> None:

        async with redis_context_manager() as redis_client:
            if all_device:
                key = Tokenizer.token_key_sort_template.format(user_id=user_id)

            else:
                key = Tokenizer.token_key_template.format(
                    user_id=user_id,
                    user_agent=user_agent,
                    token_type="*",
                )

            await redis_client.delete_by_pattern(pattern=key)


class UserSoftDeleteView(APIView):
    permission_classes = [CookieTokenPermission, IsSelfOrAdminPermission]

    def delete(self, request, pk) -> Response:
        try:
            user = User.objects.get(pk=pk)

        except User.DoesNotExist:
            raise UserNotFoundError()

        user.soft_delete()
        user.save()

        async_to_sync(self._delete_old_tokens)(user_id=pk)

        return Response(status=status.HTTP_204_NO_CONTENT)

    @staticmethod
    async def _delete_old_tokens(user_id: str) -> None:
        async with redis_context_manager() as redis_client:
            pattern = Tokenizer.token_key_sort_template.format(user_id=user_id)
            await redis_client.delete_by_pattern(pattern=pattern)


class UserUpdateView(APIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [
        CookieTokenPermission,
        IsSelfOrAdminPermission,
        ChangeUserRolePermission,
    ]

    def patch(self, request, pk) -> Response:
        try:
            user = User.objects.get(pk=pk)
            old_user = deepcopy(user)

        except User.DoesNotExist:
            raise UserNotFoundError()

        serializer = self.serializer_class(instance=user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        updated_user = serializer.save()

        response = Response(serializer.data, status=status.HTTP_200_OK)
        if old_user.role != updated_user.role:
            user_agent = request.META.get("HTTP_USER_AGENT", "not_user_agent")
            tokens = Tokenizer.gen_tokens(
                user_id=str(user.id),
                user_role=user.role,
                user_agent=user_agent,
            )

            async_to_sync(self._delete_old_tokens)(str(user.id))
            async_to_sync(self._save_tokens)(tokens, user, user_agent)

            response.delete_cookie(TokenType.access.name)
            response.set_signed_cookie(
                key=TokenType.access.name,
                value=tokens.access_token.token,
                httponly=True,
                secure=not settings.DEBUG,
                samesite="Strict",
            )

        return response

    @staticmethod
    async def _delete_old_tokens(user_id: str) -> None:
        async with redis_context_manager() as redis_client:
            pattern = Tokenizer.token_key_sort_template.format(user_id=user_id)
            await redis_client.delete_by_pattern(pattern=pattern)

    @staticmethod
    async def _save_tokens(
        tokens: Tokens,
        user: User,
        user_agent: str,
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
