import logging
from copy import deepcopy

from django.conf import settings
from django.contrib.auth.hashers import check_password
from rest_framework import generics, status
from rest_framework.generics import get_object_or_404
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from asgiref.sync import async_to_sync

from .utils import Hasher
from .utils.custom_enum import TokenType
from .utils.mixins import TokenizerWorkMixin, UsersPermissionsWorkMixin
from .utils.custom_exception import UserNotFoundError, AuthDataInvalidError
from .permissions import (
    CookieAccessTokenPermission,
    CookieTokensPermission,
    IsSelfOrAdminPermission,
    ChangeUserRolePermission,
    UserPermissionByGroup,
    IsAdminPermission,
)
from .serializers import (
    UserCreateSerializer,
    UserUpdateSerializer,
    LoginSerializer,
    LogoutSerializer,
    GroupCreateSerializer,
    PermissionByGroupCreateSerializer,
    UserByGroupAssociationCreateSerializer,
)
from .models import (
    User,
    Group,
    PermissionByGroup,
    UserByGroupAssociation,
)

logger = logging.getLogger(__name__)

# --- User --- #
class UserCreateView(generics.CreateAPIView):
    """View - создание Пользователя."""

    serializer_class = UserCreateSerializer
    permission_classes = [AllowAny]


class UserSoftDeleteView(
    APIView,
    TokenizerWorkMixin,
    UsersPermissionsWorkMixin,
):
    """View - мягкое удаление Пользователя."""

    permission_classes = [
        CookieAccessTokenPermission,
        (IsSelfOrAdminPermission | UserPermissionByGroup),
    ]

    def delete(self, request: Request, pk: str) -> Response:
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

        async_to_sync(self._delete_user_permissions_in_redis)(str(user.id))

        return response


class UserUpdateView(APIView, TokenizerWorkMixin):
    """View - обновление Пользователя."""

    serializer_class = UserUpdateSerializer
    permission_classes = [
        CookieAccessTokenPermission,
        (
            IsSelfOrAdminPermission |
            ChangeUserRolePermission |
            UserPermissionByGroup
        ),
    ]

    def patch(self, request: Request, pk: str) -> Response:
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

        # Если пользователь изменил свою роль - обновляем его токен
        access_token = request.get_signed_cookie(TokenType.access.name)
        if (
            old_user.role != updated_user.role
        ) and (
            pk == self._get_user_by_token(access_token).id
        ):
            user_agent = request.META.get("HTTP_USER_AGENT", "not_user_agent")
            self._refresh_tokens(
                user=updated_user,
                user_agent=user_agent,
                response=response,
            )

        return response


# --- Auth --- #
class LoginView(APIView, TokenizerWorkMixin):
    """View - авторизация Пользователя."""

    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
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
    """View - обновление токена Пользователя."""

    permission_classes = [CookieTokensPermission]

    def post(self, request: Request) -> Response:
        refresh_token = request.get_signed_cookie(TokenType.refresh.name)

        response = Response()
        self._refresh_tokens(
            user=self._get_user_by_token(token=refresh_token),
            user_agent=request.META.get("HTTP_USER_AGENT", "not_user_agent"),
            response=response,
        )

        return response


class LogoutView(APIView, TokenizerWorkMixin, UsersPermissionsWorkMixin):
    """View - ре-авторизация Пользователя."""

    serializer_class = LogoutSerializer
    permission_classes = [CookieAccessTokenPermission]

    def post(self, request: Request) -> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        access_token = request.get_signed_cookie(TokenType.access.name)
        user = self._get_user_by_token(token=access_token)

        async_to_sync(self._delete_old_tokens_from_redis)(
            user=user,
            user_agent=request.META.get("HTTP_USER_AGENT", "not_user_agent"),
            all_device=serializer.validated_data.get("all_device", False),
        )

        response = Response()
        response.delete_cookie(TokenType.access.name)
        response.delete_cookie(TokenType.refresh.name)

        async_to_sync(self._delete_user_permissions_in_redis)(str(user.id))

        return response


# --- Group --- #
class GroupCreateView(generics.CreateAPIView):
    """View - создание Группы."""

    serializer_class = GroupCreateSerializer
    permission_classes = [
        CookieAccessTokenPermission,
        (IsAdminPermission | UserPermissionByGroup),
    ]


class GroupSoftDeleteView(APIView, TokenizerWorkMixin):
    """View - мягкое удаление Группы."""

    permission_classes = [
        CookieAccessTokenPermission,
        (IsAdminPermission | UserPermissionByGroup),
    ]

    def delete(self, request: Request, pk: str) -> Response:
        group = get_object_or_404(Group, pk=pk)
        group.soft_delete()
        group.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


# --- PermissionByGroup --- #
class PermissionByGroupCreateView(generics.CreateAPIView):
    """View - выделение Группе прав доступа к ресурсу."""

    serializer_class = PermissionByGroupCreateSerializer
    permission_classes = [
        CookieAccessTokenPermission,
        (IsAdminPermission | UserPermissionByGroup),
    ]

class PermissionByGroupSoftDeleteView(APIView, TokenizerWorkMixin):
    """View - мягкое удаление у Группы права доступа к ресурсу."""

    permission_classes = [
        CookieAccessTokenPermission,
        (IsAdminPermission | UserPermissionByGroup),
    ]

    def delete(self, request: Request, pk: str) -> Response:
        permission_by_group = get_object_or_404(PermissionByGroup, pk=pk)
        permission_by_group.soft_delete()
        permission_by_group.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


# --- UserByGroupAssociation --- #
class UserByGroupAssociationCreateView(generics.CreateAPIView):
    """View - создание связки Пользователя и Группы."""

    serializer_class = UserByGroupAssociationCreateSerializer
    permission_classes = [
        CookieAccessTokenPermission,
        (IsAdminPermission | UserPermissionByGroup),
    ]

class UserByGroupAssociationSoftDeleteView(
    APIView,
    TokenizerWorkMixin,
):
    """View - мягкое удаление связки Пользователя и Группы."""

    permission_classes = [
        CookieAccessTokenPermission,
        (IsAdminPermission | UserPermissionByGroup),
    ]

    def delete(self, request: Request, pk: str) -> Response:
        user_by_group_association = get_object_or_404(
            UserByGroupAssociation,
            pk=pk,
        )
        user_by_group_association.soft_delete()
        user_by_group_association.save()

        return Response(status=status.HTTP_204_NO_CONTENT)
