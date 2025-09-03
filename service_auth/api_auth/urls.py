from django.urls import path
from .views import (
    UserCreateView,
    UserSoftDeleteView,
    UserUpdateView,
    LoginView,
    RefreshTokenView,
    LogoutView,
)


urlpatterns = [
    path("registry", UserCreateView.as_view(), name="registry"),
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
    path("login", LoginView.as_view(), name="login"),
    path(
        "refresh_tokens",
        RefreshTokenView.as_view(),
        name="refresh_tokens",
    ),
    path("logout", LogoutView.as_view(), name="logout"),
]
