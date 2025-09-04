from typing import Any

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.db.models import Q
from rest_framework import serializers
from rest_framework.generics import get_object_or_404

from .utils import Cryptor, Hasher, Tokenizer
from .models import (
    User,
    UsersRole,
    Group,
    PermissionByGroup,
    UserByGroupAssociation,
)
from .utils.custom_enum import TokenType
from .utils.custom_exception import TokenDataInvalidError


# --- User --- #
class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer - создание Пользователя."""

    @staticmethod
    def validate_unique_email(value: str) -> str:
        """
        Проверка уникальности email Пользователя.

        :param value:
        :type value: str

        :return:
        :rtype: str
        """
        email_hash = Hasher.hash_str(
            str_=value,
            password=settings.EMAIL_MASTER_PASSWORD,
        )

        if User.objects.filter(email_hash=email_hash).exists():
            raise serializers.ValidationError(
                "Пользователь с таким email уже существует",
            )

        return value

    @staticmethod
    def validate_role(value: str) -> str:
        """
        Проверка роли Пользователя.

        :param value:
        :type value: str

        :return:
        :rtype: str
        """
        if value not in UsersRole.values():
            raise serializers.ValidationError("Указанная роль не существует")

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
    role = serializers.CharField(
        validators=[
            validate_role,
        ],
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

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Доп. валидация параметров:
        - Обе попытки ввода пароля должны быть схожи.
        - Пользователей с высоким уровнем роли может создавать только
        авторизованный пользователь с высокой ролью согласно иерархии.

        :param data:
        :type data: dict[str, Any]

        :return:
        :rtype: dict[str, Any]
        """
        if data["password_first_try"] != data["password_second_try"]:
            raise serializers.ValidationError("Пароли не совпадают")

        if data["role"] in UsersRole.high_lvl_users_roles():
            try:
                request = self.context.get("request")
                access_token = request.get_signed_cookie(TokenType.access.name)
                access_token_payload = Tokenizer.decode_token(access_token)

            except TokenDataInvalidError:
                raise serializers.ValidationError(
                    "Для создания пользователя с указанной ролью требуется "
                    "авторизоваться"
                )

            user_role = access_token_payload.user_role
            if (
                data["role"] not in
                UsersRole.get_permissions_on_create(user_role)
            ):
                raise serializers.ValidationError(
                    "У вас не хватает прав для создания пользователя с "
                    "указанной ролью"
                )

        return data

    def create(self, validated_data: dict[str, Any]) -> User:
        """
        Создание Пользователя.

        :param validated_data:
        :type validated_data: dict[str, Any]

        :return:
        :rtype: User
        """
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
    """Serializer - обновление Пользователя."""

    id = serializers.CharField(max_length=256)
    email = serializers.EmailField(
        write_only=True,
        max_length=128,
        default=None,
    )
    password_first_try = serializers.CharField(
        write_only=True,
        max_length=128,
        default=None,
    )
    password_second_try = serializers.CharField(
        write_only=True,
        max_length=128,
        default=None,
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

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Доп. валидация параметров:
        - Если обновляется пароль, то обе попытки его ввода должны быть схожи.
        - Если обновляется email, то он не должен быть среди email других
        Пользователей.

        :param data:
        :type data: dict[str, Any]

        :return:
        :rtype: dict[str, Any]
        """
        update_pass = (
            data.get("password_first_try") and data.get("password_second_try")
        )
        if (
            update_pass and
            data["password_first_try"] != data["password_second_try"]
        ):
            raise serializers.ValidationError("Пароли не совпадают")

        if new_email := data.get("email"):
            email_hash = Hasher.hash_str(
                str_=new_email,
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

    def update(self, instance: User, validated_data: dict[str, Any]) -> User:
        """
        Обновление Пользователя.

        :param instance:
        :type instance: User
        :param validated_data:
        :type validated_data: dict[str, Any]

        :return:
        :rtype: User
        """
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


# --- Auth --- #
class LoginSerializer(serializers.Serializer):
    """Serializer - авторизация Пользователя."""

    email = serializers.EmailField(write_only=True, max_length=128)
    password = serializers.CharField(
        write_only=True,
        max_length=128,
    )

class LogoutSerializer(serializers.Serializer):
    """Serializer - ре-авторизация Пользователя."""

    all_device = serializers.BooleanField(
        default=False,
        help_text="Флаг - требуется ли ре-авторизоваться со всех устройств",
    )


# --- Group --- #
class GroupCreateSerializer(serializers.ModelSerializer):
    """Serializer - создание Группы."""

    title = serializers.CharField(max_length=128)
    alias = serializers.CharField(max_length=128)

    class Meta:
        model = Group
        fields = ["id", "title", "alias"]
        read_only_fields = ["id", ]

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Доп. валидация параметров:
        - Валидация уникальности Группы.

        :param data:
        :type data: dict[str, Any]

        :return:
        :rtype: dict[str, Any]
        """
        if Group.objects.filter(
            (
                Q(title=data["title"]) | Q(alias=data["alias"])
            ) &
            Q(deleted_at__isnull=True)
        ).exists():
            raise serializers.ValidationError(
                "Группа со схожими параметрами имеется"
            )

        return data

    def create(self, validated_data: dict[str, Any]) -> Group:
        """
        Создание Группы.

        :param validated_data:
        :type validated_data: dict[str, Any]

        :return:
        :rtype: Group
        """
        group = Group(
            title=validated_data["title"],
            alias=validated_data["alias"],
        )
        group.save()

        return group


# --- PermissionByGroup --- #
class PermissionByGroupCreateSerializer(serializers.ModelSerializer):
    """Serializer - выделение Группе прав к ресурсу."""

    uri = serializers.CharField(max_length=256)
    uri_name = serializers.CharField(max_length=256)
    group_id = serializers.CharField()
    comment = serializers.CharField(
        max_length=256,
        allow_null=True,
        default=None,
    )

    class Meta:
        model = PermissionByGroup
        fields = ["id", "uri", "uri_name", "group_id", "comment"]
        read_only_fields = ["id", ]

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Доп. валидация параметров:
        - Проверка наличия у Группы выделяемого доступа к ресурсу.

        :param data:
        :type data: dict[str, Any]

        :return:
        :rtype: dict[str, Any]
        """
        group = get_object_or_404(Group, pk=data["group_id"])

        if PermissionByGroup.objects.filter(
            (
                Q(uri=data["uri"]) & Q(group=group)
            ) &
            Q(deleted_at__isnull=True)
        ).exists():
            raise serializers.ValidationError(
                "Группа уже имеет указанные права"
            )

        data["group"] = group

        return data

    def create(self, validated_data: dict[str, Any]) -> PermissionByGroup:
        """
        Выделение группе прав доступа к ресурсу.

        :param validated_data:
        :type validated_data: dict[str, Any]

        :return:
        :rtype: PermissionByGroup
        """
        permission_by_group = PermissionByGroup(
            uri=validated_data["uri"],
            uri_name=validated_data["uri_name"],
            comment=validated_data.get("comment"),
            group=validated_data["group"],
        )
        permission_by_group.save()

        return permission_by_group


# --- UserByGroupAssociation --- #
class UserByGroupAssociationCreateSerializer(
    serializers.ModelSerializer,
):
    """Serializer - связка Пользователя с Группой."""

    user_id = serializers.CharField()
    group_id = serializers.CharField()

    class Meta:
        model = UserByGroupAssociation
        fields = ["id", "user_id", "group_id"]
        read_only_fields = ["id", ]

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Доп. валидация параметров:
        - Проверка связки Пользователя с Группой.

        :param data:
        :type data: dict[str, Any]

        :return:
        :rtype: dict[str, Any]
        """
        user = get_object_or_404(User, pk=data["user_id"])
        group = get_object_or_404(Group, pk=data["group_id"])

        if UserByGroupAssociation.objects.filter(
            (
                Q(user=user) & Q(group=group)
            ) &
            Q(deleted_at__isnull=True)
        ).exists():
            raise serializers.ValidationError(
                "Пользователь уже связан с указанной группой"
            )

        data["user"] = user
        data["group"] = group

        return data

    def create(self, validated_data: dict[str, Any]) -> UserByGroupAssociation:
        """
        Связка пользователя с группой.

        :param validated_data:
        :type validated_data: dict[str, Any]

        :return:
        :rtype: UserByGroupAssociation
        """
        user_by_group_association = UserByGroupAssociation(
            user=validated_data["user"],
            group=validated_data["group"],
        )
        user_by_group_association.save()

        return user_by_group_association
