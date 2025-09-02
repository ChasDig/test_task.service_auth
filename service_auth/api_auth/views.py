import logging
from dataclasses import asdict

from django.conf import settings
from django.contrib.auth.hashers import check_password
from rest_framework import generics
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
from .serializers import UserWriteSerializer, LoginSerializer


logger = logging.getLogger(__name__)


class UserCreateView(generics.CreateAPIView):
    serializer_class = UserWriteSerializer
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

        access_token_dict = asdict(tokens.access_token)
        response = Response({TokenType.access.value: access_token_dict})
        response.set_cookie(
            key=TokenType.refresh.name,
            value=tokens.refresh_token.token,
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
            await redis_client.delete(
                key=Tokenizer.token_key_template.format(
                    user_id=str(user.id),
                    user_agent=user_agent,
                    token_type="*",
                ),
            )
            logger.debug(
                f"All old tokens delete for {user.last_name} / {user_agent}"
            )
