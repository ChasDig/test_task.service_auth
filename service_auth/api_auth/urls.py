from django.urls import path
from .views import UserCreateView, LoginView


urlpatterns = [
    path("registry", UserCreateView.as_view(), name="registry"),
    path("login", LoginView.as_view(), name="login"),
]
