from django.conf import settings
from django.contrib.auth.hashers import make_password
from rest_framework import serializers

from .utils import Cryptor, Hasher
from .models import User, UsersRole

class UserCreateSerializer(serializers.ModelSerializer):

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
        max_length=128,
    )
    password_first_try = serializers.CharField(
        write_only=True,
        max_length=128,
    )
    password_second_try = serializers.CharField(
        write_only=True,
        max_length=128,
    )

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
            "role",
            "email_dec",
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
            password_hash=make_password(
                validated_data["password_first_try"],
            ),
            role=validated_data.get("role", UsersRole.USER.value),
        )

        user.save()

        return user

class UserUpdateSerializer(serializers.ModelSerializer):

    id = serializers.CharField(max_length=256)
    email = serializers.EmailField(write_only=True, max_length=128)
    password_first_try = serializers.CharField(
        write_only=True,
        max_length=128,
    )
    password_second_try = serializers.CharField(
        write_only=True,
        max_length=128,
    )

    email_dec = serializers.ReadOnlyField(
        help_text="Email пользователя в расшифрованном виде",
    )

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "second_name",
            "last_name",
            "email",
            "role",
            "email_dec",
            "password_first_try",
            "password_second_try",
        ]
        read_only_fields = [
            "email_dec",
        ]

    def validate(self, data):
        if data["password_first_try"] != data["password_second_try"]:
            raise serializers.ValidationError("Пароли не совпадают")

        email_hash = Hasher.hash_str(
            str_=data["email"],
            password=settings.EMAIL_MASTER_PASSWORD,
        )
        if (
            User.objects.filter(
                email_hash=email_hash,
            ).exclude(
                id=data["id"],
            ).exists()
        ):
            raise serializers.ValidationError(
                "Пользователь с таким email уже существует",
            )

        return data

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            if attr == "email":
                email_enc_ = Cryptor.encrypt_str(str_=value)
                email_hash_ = Hasher.hash_str(
                    str_=value,
                    password=settings.EMAIL_MASTER_PASSWORD,
                )
                setattr(instance, "email_enc", email_enc_)
                setattr(instance, "email_hash", email_hash_)

            elif attr == "password":
                password_hash_ = make_password(value)
                setattr(instance, "password_hash", password_hash_)

            else:
                setattr(instance, attr, value)

        instance.save()
        return instance


class LoginSerializer(serializers.Serializer):

    email = serializers.CharField(write_only=True, max_length=128)
    password = serializers.CharField(
        write_only=True,
        max_length=128,
    )

class LogoutSerializer(serializers.Serializer):

    all_device = serializers.BooleanField(default=False)

