from django.conf import settings
from django.contrib.auth.hashers import make_password
from rest_framework import serializers

from .utils import Cryptor, Hasher
from .models import User

class UserWriteSerializer(serializers.ModelSerializer):
    """Serializer - создание Пользователя."""

    @staticmethod
    def validate_unique_email(value: str):
        """Проверка уникальности email Пользователя."""

        email_hash = Hasher.hash_str(
            str_=value,
            password=settings.EMAIL_MASTER_PASSWORD,
        )

        if User.objects.filter(email_hash=email_hash).exists():
            raise serializers.ValidationError(
                "Пользователь с таким email уже существует",
            )

        return value

    email = serializers.EmailField(
        write_only=True,
        validators=[
            validate_unique_email,
        ],
    )
    password_first_try = serializers.CharField(write_only=True)
    password_second_try = serializers.CharField(write_only=True)

    email_dec = serializers.ReadOnlyField(
        help_text="Email пользователя в расшифрованном виде",
    )

    class Meta:
        model = User
        fields = [
            "first_name",
            "second_name",
            "last_name",
            "email",
            "email_dec",
            "password_first_try",
            "password_second_try",
        ]

        write_only_fields = [
            "password_first_try",
            "password_second_try",
        ]

        read_only_fields = [
            "email_dec",
        ]

    def validate(self, data):
        if data["password_first_try"] != data["password_second_try"]:
            raise serializers.ValidationError("Пароли не совпадают")

        return data

    def create(self, validated_data):
        email = validated_data["email"]

        user = User(
            first_name=validated_data["first_name"],
            second_name=validated_data.get("second_name"),
            last_name=validated_data["last_name"],
            email_enc=Cryptor.encrypt_str(str_=email),
            email_hash=Hasher.hash_str(
                str_=email,
                password=settings.EMAIL_MASTER_PASSWORD,
            ),
            password_hash=make_password(validated_data["password_first_try"]),
        )
        user.save()

        return user
