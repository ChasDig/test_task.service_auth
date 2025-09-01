from rest_framework import generics

from .serializers import UserWriteSerializer


class UserCreateView(generics.CreateAPIView):
    serializer_class = UserWriteSerializer
