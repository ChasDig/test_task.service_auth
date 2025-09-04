from django.urls import path

from .views import (
    GroupCreateView,
    GroupSoftDeleteView,
    LoginView,
    LogoutView,
    PermissionByGroupCreateView,
    PermissionByGroupSoftDeleteView,
    RefreshTokenView,
    ResourceCreateView,
    ResourceSoftDeleteView,
    UserByGroupAssociationCreateView,
    UserByGroupAssociationSoftDeleteView,
    UserCreateView,
    UserSoftDeleteView,
    UserUpdateView,
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
    # Resource
    path(
        "resource/create",
        ResourceCreateView.as_view(),
        name="create_resource",
    ),
    path(
        "resource/delete/<str:pk>/",
        ResourceSoftDeleteView.as_view(),
        name="delete_resource",
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
    # UserByGroupAssociation
    path(
        "user_by_group_association/create",
        UserByGroupAssociationCreateView.as_view(),
        name="create_user_by_group_association",
    ),
    path(
        "user_by_group_association/delete/<str:pk>/",
        UserByGroupAssociationSoftDeleteView.as_view(),
        name="delete_user_by_group_association",
    ),
]
