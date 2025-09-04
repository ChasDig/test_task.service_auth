from asgiref.sync import async_to_sync
from django.urls import resolve
from rest_framework.exceptions import NotAuthenticated
from rest_framework.permissions import BasePermission

from .utils import Tokenizer
from .utils.custom_enum import TokenType
from .models import UsersRole
from .utils.custom_exception import TokenDataInvalidError
from .utils.mixins import TokenizerWorkMixin, UsersPermissionsWorkMixin


class CookieAccessTokenPermission(BasePermission, TokenizerWorkMixin):
    """Permission - Пользователь имеет AccessToken в Cookies."""

    def has_permission(self, request, view) -> bool:
        try:
            access_token = request.get_signed_cookie(TokenType.access.name)

        except KeyError:
            raise NotAuthenticated(detail="token not allowed")

        user_agent = request.META.get("HTTP_USER_AGENT", "not_user_agent")
        access_token_from_redis = async_to_sync(self._get_token_from_redis)(
            user_id=str(self._get_user_by_token(access_token).id),
            user_agent=user_agent,
            token_type=TokenType.access.name,
        )

        if access_token_from_redis != access_token:
            raise NotAuthenticated(detail="token not allowed")

        return True


class CookieTokensPermission(BasePermission, TokenizerWorkMixin):
    """Permission - Пользователь имеет Access/RefreshToken в Cookies."""

    def has_permission(self, request, view) -> bool:
        try:
            access_token = request.get_signed_cookie(TokenType.access.name)

        except KeyError:
            raise NotAuthenticated(detail="token not allowed")

        user_agent = request.META.get("HTTP_USER_AGENT", "not_user_agent")

        try:
            access_token_from_redis = async_to_sync(
                self._get_token_from_redis)(
                user_id=str(self._get_user_by_token(access_token).id),
                user_agent=user_agent,
                token_type=TokenType.access.name,
            )

            if access_token_from_redis != access_token:
                raise NotAuthenticated(detail="token not allowed")

        except TokenDataInvalidError:
            try:
                refresh_token = request.get_signed_cookie(
                    TokenType.refresh.name,
                )

                refresh_token_from_redis = async_to_sync(
                    self._get_token_from_redis)(
                    user_id=str(self._get_user_by_token(refresh_token).id),
                    user_agent=user_agent,
                    token_type=TokenType.refresh.name,
                )

            except KeyError:
                raise NotAuthenticated(detail="token not allowed")

            if refresh_token_from_redis != refresh_token:
                raise NotAuthenticated(detail="token not allowed")

        return True


class IsSelfOrAdminPermission(BasePermission):
    """Permission - запрос совершает сам Пользователь или Admin/Superuser."""

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


class IsAdminPermission(BasePermission):
    """Permission - запрос совершает Admin/Superuser."""

    def has_permission(self, request, view) -> bool:
        try:
            access_token = request.get_signed_cookie(TokenType.access.name)

        except KeyError:
            raise NotAuthenticated(detail="token not allowed")

        high_lvl_roles = (UsersRole.ADMIN.value, UsersRole.SUPERUSER.value)
        access_token_payload = Tokenizer.decode_token(access_token)

        if access_token_payload.user_role in high_lvl_roles:
            return True

        return False


class ChangeUserRolePermission(BasePermission):
    """Permission - проверка права менять роль Пользователя."""

    def has_permission(self, request, view) -> bool:
        user_role = request.data.get("role")
        access_token = request.get_signed_cookie(TokenType.access.name)
        access_token_payload = Tokenizer.decode_token(access_token)

        update_user_role_in_high_lvl_roles = (
                user_role in UsersRole.high_lvl_users_roles()
        )
        request_user_have_high_lvl_role = (
            access_token_payload.user_role in UsersRole.high_lvl_users_roles()
        )

        if (
            user_role and
            (not request_user_have_high_lvl_role) and
            update_user_role_in_high_lvl_roles
        ):
            return False

        return True

class UserPermissionByGroup(BasePermission, UsersPermissionsWorkMixin):
    """Permission - проверка доступа к ресурсу по группе прав Пользователя."""

    def has_permission(self, request, view) -> bool:
        access_token = request.get_signed_cookie(TokenType.access.name)
        access_token_payload = Tokenizer.decode_token(access_token)
        user_id = access_token_payload.sub

        user_permissions = async_to_sync(
            self._get_user_permissions_from_redis,
        )(user_id)

        if not user_permissions:
            user_permissions = self._get_user_permissions_by_groups(user_id)
            async_to_sync(
                self._set_user_permissions_in_redis,
            )(user_id, user_permissions)

        resolver_m = resolve(request.path_info)
        if resolver_m.route == user_permissions.get(resolver_m.url_name):
            return True

        return False
