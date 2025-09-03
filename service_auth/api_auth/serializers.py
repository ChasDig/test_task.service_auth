from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.db.models import Q
from rest_framework import serializers
from rest_framework.generics import get_object_or_404

from .utils import Cryptor, Hasher
from .models import (
    User,
    UsersRole,
    Group,
    PermissionByGroup,
    UserPermissionByGroupAssociation,
)


# --- User --- #
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


# --- Auth --- #
class LoginSerializer(serializers.Serializer):

    email = serializers.CharField(write_only=True, max_length=128)
    password = serializers.CharField(
        write_only=True,
        max_length=128,
    )

class LogoutSerializer(serializers.Serializer):

    all_device = serializers.BooleanField(default=False)


# --- Group --- #
class GroupCreateSerializer(serializers.ModelSerializer):

    title = serializers.CharField(max_length=128)
    alias = serializers.CharField(max_length=128)

    class Meta:
        model = Group
        fields = ["id", "title", "alias"]
        read_only_fields = ["id", ]

    def validate(self, data):
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

    def create(self, validated_data):
        group = Group(
            title=validated_data["title"],
            alias=validated_data["alias"],
        )
        group.save()

        return group


# --- PermissionByGroup --- #
class PermissionByGroupCreateSerializer(serializers.ModelSerializer):

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

    def validate(self, data):
        group = get_object_or_404(PermissionByGroup, pk=data["group_id"])

        if PermissionByGroup.objects.filter(
            (
                Q(uri=data["uri"]) & Q(group=group)
            ) &
            Q(deleted_at__isnull=True)
        ).exists():
            raise serializers.ValidationError(
                "Группа уже имеет указанные права"
            )

        return data

    def create(self, validated_data):
        permission_by_group = PermissionByGroup(
            uri=validated_data["uri"],
            uri_name=validated_data["uri_name"],
            comment=validated_data.get("comment"),
            group_id=validated_data["group_id"],
        )
        permission_by_group.save()

        return permission_by_group


# --- UserPermissionByGroupAssociation --- #
class UserPermissionByGroupAssociationCreateSerializer(
    serializers.ModelSerializer,
):

    user_id = serializers.CharField()
    permission_by_group_id = serializers.CharField()

    class Meta:
        model = UserPermissionByGroupAssociation
        fields = ["id", "user_id", "permission_by_group_id"]
        read_only_fields = ["id", ]

    def validate(self, data):
        user = get_object_or_404(User, pk=data["user_id"])
        permission_by_group = get_object_or_404(
            PermissionByGroup,
            pk=data["permission_by_group_id"],
        )

        if UserPermissionByGroupAssociation.objects.filter(
            (
                Q(user=user) & Q(permission_by_group=permission_by_group)
            ) &
            Q(deleted_at__isnull=True)
        ).exists():
            raise serializers.ValidationError(
                "Пользователь уже связан с указанной группой прав"
            )

        data["user"] = user
        data["permission_by_group"] = permission_by_group

        return data

    def create(self, validated_data):
        user_permission_by_g_a = UserPermissionByGroupAssociation(
            user=validated_data["user"],
            permission_by_group=validated_data["permission_by_group"],
        )
        user_permission_by_g_a.save()

        return user_permission_by_g_a
