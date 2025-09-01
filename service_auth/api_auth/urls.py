from django.urls import path
from .views import UserCreateView


urlpatterns = [
    path("registry", UserCreateView.as_view(), name="users")
]
