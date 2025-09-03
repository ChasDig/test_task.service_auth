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
from .utils import Hasher
from .utils.mixins import TokenizerWorkMixin
from .utils.custom_enum import TokenType
from .utils.custom_exception import UserNotFoundError, AuthDataInvalidError
from .permissions import (
    CookieAccessTokenPermission,
    CookieTokensPermission,
    IsSelfOrAdminPermission,
    ChangeUserRolePermission,
    UserPermissionByGroup,
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


class LoginView(APIView, TokenizerWorkMixin):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = self._get_user_by_email(serializer.validated_data["email"])
        self._check_user_password(user, serializer.validated_data["password"])

        response = Response()
        self._refresh_tokens(
            user=user,
            user_agent=request.META.get("HTTP_USER_AGENT", "not_user_agent"),
            response=response,
        )

        return response

    @staticmethod
    def _get_user_by_email(email: str) -> User:
        try:
            return User.objects.get(
                email_hash=Hasher.hash_str(
                    str_=email,
                    password=settings.EMAIL_MASTER_PASSWORD,
                ),
            )

        except User.DoesNotExist:
            raise UserNotFoundError()

    @staticmethod
    def _check_user_password(user: User, inc_password: str) -> None:
        if not check_password(inc_password, user.password_hash):
            raise AuthDataInvalidError()


class RefreshTokenView(APIView, TokenizerWorkMixin):
    permission_classes = [CookieTokensPermission]

    def post(self, request) -> Response:
        refresh_token = request.get_signed_cookie(TokenType.refresh.name)

        response = Response()
        self._refresh_tokens(
            user=self._get_user_by_token(token=refresh_token),
            user_agent=request.META.get("HTTP_USER_AGENT", "not_user_agent"),
            response=response,
        )

        return response


class LogoutView(APIView, TokenizerWorkMixin):
    serializer_class = LogoutSerializer
    permission_classes = [CookieAccessTokenPermission]

    def post(self, request) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        access_token = request.get_signed_cookie(TokenType.access.name)
        async_to_sync(self._delete_old_tokens_from_redis)(
            user=self._get_user_by_token(token=access_token),
            user_agent=request.META.get("HTTP_USER_AGENT", "not_user_agent"),
            all_device=serializer.validated_data.get("all_device", False),
        )

        response = Response()
        response.delete_cookie(TokenType.access.name)
        response.delete_cookie(TokenType.refresh.name)

        return response


class UserSoftDeleteView(APIView, TokenizerWorkMixin):
    permission_classes = [
        CookieAccessTokenPermission,
        IsSelfOrAdminPermission,
        UserPermissionByGroup,
    ]

    def delete(self, request, pk) -> Response:
        try:
            user = User.objects.get(pk=pk)

        except User.DoesNotExist:
            raise UserNotFoundError()

        user.soft_delete()
        user.save()

        async_to_sync(self._delete_old_tokens_from_redis)(
            user=user,
            all_device=True,
        )

        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie(TokenType.access.name)
        response.delete_cookie(TokenType.refresh.name)

        return response


class UserUpdateView(APIView, TokenizerWorkMixin):
    serializer_class = UserUpdateSerializer
    permission_classes = [
        CookieAccessTokenPermission,
        IsSelfOrAdminPermission,
        ChangeUserRolePermission,
        UserPermissionByGroup,
    ]

    def patch(self, request, pk) -> Response:
        if pk != request.data.get("id"):
            raise UserNotFoundError()

        try:
            user = User.objects.get(pk=pk)
            old_user = deepcopy(user)

        except User.DoesNotExist:
            raise UserNotFoundError()

        serializer = self.serializer_class(
            instance=user,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        updated_user = serializer.save()

        response = Response(serializer.data, status=status.HTTP_200_OK)

        if old_user.role != updated_user.role:
            user_agent = request.META.get("HTTP_USER_AGENT", "not_user_agent")
            self._refresh_tokens(
                user=updated_user,
                user_agent=user_agent,
                response=response,
            )

        return response
