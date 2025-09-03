from django.urls import path
from .views import (
    UserCreateView,
    UserSoftDeleteView,
    UserUpdateView,
    LoginView,
    RefreshTokenView,
    LogoutView,
    GroupCreateView,
    GroupSoftDeleteView,
    PermissionByGroupCreateView,
    PermissionByGroupSoftDeleteView,
    UserPermissionByGroupAssociationCreateView,
    UserPermissionByGroupAssociationSoftDeleteView,
)


urlpatterns = [
    # Users
    path("registry", UserCreateView.as_view(), name="registry_user"),
    path(
        "users/delete/<str:pk>/",
        UserSoftDeleteView.as_view(),
        name="delete_user",
    ),
    path(
        "users/update/<str:pk>/",
        UserUpdateView.as_view(),
        name="update_user",
    ),
    # Auth
    path("login", LoginView.as_view(), name="login_user"),
    path(
        "refresh_tokens",
        RefreshTokenView.as_view(),
        name="refresh_user_tokens",
    ),
    path("logout", LogoutView.as_view(), name="logout_user"),
    # Group
    path(
        "groups/create",
        GroupCreateView.as_view(),
        name="create_group",
    ),
    path(
        "groups/delete/<str:pk>/",
        GroupSoftDeleteView.as_view(),
        name="delete_group",
    ),
    # PermissionByGroup
    path(
        "permission_by_group/create",
        PermissionByGroupCreateView.as_view(),
        name="create_permission_by_group",
    ),
    path(
        "permission_by_group/delete/<str:pk>/",
        PermissionByGroupSoftDeleteView.as_view(),
        name="delete_permission_by_group",
    ),
    # UserPermissionByGroupAssociation
    path(
        "user_permission_by_group_assoc/create",
        UserPermissionByGroupAssociationCreateView.as_view(),
        name="create_user_permission_by_group_assoc",
    ),
    path(
        "user_permission_by_group_assoc/delete/<str:pk>/",
        UserPermissionByGroupAssociationSoftDeleteView.as_view(),
        name="delete_user_permission_by_group_assoc",
    ),
]
