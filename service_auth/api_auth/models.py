from uuid import uuid4
from enum import Enum

from django.conf import settings
from django.utils import timezone
from django.db import models

from .utils import Cryptor


class UsersRole(Enum):
    """Группы пользователей."""

    SUPERUSER = "superuser"
    ADMIN = "admin"
    USER = "user"

    @classmethod
    def choices(cls) -> list[tuple[str, str]]:
        return [(item.value, item.name.capitalize()) for item in cls]

    @classmethod
    def high_lvl_users_roles(cls) -> tuple[str, ...]:
        return cls.SUPERUSER.value, cls.ADMIN.value


class UUIDMixin(models.Model):
    """Mixin - ID(UUID)."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)

    class Meta:
        abstract = True


class DatetimeStampedMixin(models.Model):
    """Mixin - DatetimeStamped."""

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Время создания сущности",
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Время обновления сущности",
    )
    deleted_at = models.DateTimeField(
        default=None,
        null=True,
        help_text="Время удаления сущности (мягкое удаление)",
    )

    def soft_delete(self) -> None:
        """Мягкое удаление сущности."""

        self.deleted_at = timezone.now()
        self.save()

    def soft_update(self) -> None:
        """Обновление/восстановление сущности."""

        self.deleted_at = None
        self.save()

    def is_active(self) -> bool:
        """Проверка - сущность активна."""

        return self.deleted_at is None

    class Meta:
        abstract = True


class User(UUIDMixin, DatetimeStampedMixin):
    """Модель - Пользователь."""

    first_name = models.CharField(max_length=64, null=False, help_text="Имя")
    second_name = models.CharField(
        max_length=64,
        null=True,
        help_text="Отчество (при наличии)",
    )
    last_name = models.CharField(
        max_length=64,
        null=False,
        help_text="Фамилия",
    )
    email_enc = models.CharField(
        max_length=512,
        null=False,
        help_text="Email (в зашифрованном виде)",
    )
    email_hash = models.CharField(
        max_length=128,
        null=False,
        help_text="Email (хеш)",
    )
    password_hash = models.CharField(
        max_length=128,
        null=False,
        help_text="Пароль (хеш)",
    )
    role = models.CharField(
        max_length=32,
        choices=UsersRole.choices(),
        null=False,
        default=UsersRole.USER.value,
        help_text="Роль",
    )

    @property
    def email_dec(self) -> str:
        """Дешифровка email."""

        return Cryptor.decrypt_str(
            str_=self.email_enc,
            password=settings.EMAIL_MASTER_PASSWORD,
        )

    class Meta:
        db_table = 'users"."user'
        verbose_name = "Пользователь"
        verbose_name_plural = "Пользователи"
        constraints = [
            models.UniqueConstraint(
                fields=["email_hash"],
                name="unique_email_hash",
                condition=models.Q(deleted_at__isnull=True),
                violation_error_message=(
                    "Пользователь с указанным email уже создан"
                ),
            ),
        ]

    def __str__(self) -> str:
        return (
            f"{self.first_name} {self.second_name} {self.last_name}"
            if self.second_name
            else f"{self.first_name} {self.last_name}"
        )


class UserPermissionByGroupAssociation(UUIDMixin, DatetimeStampedMixin):
    """Модель-связь - Пользователь и Право доступа по группе."""

    user = models.ForeignKey("User", on_delete=models.CASCADE)
    permission_by_group = models.ForeignKey(
        "PermissionByGroup",
        on_delete=models.CASCADE,
    )

    class Meta:
        db_table = 'users"."user_permission_by_group_association'
        constraints = [
            models.UniqueConstraint(
                fields=["user", "permission_by_group"],
                name="unique_user_group_permission",
                condition=models.Q(deleted_at__isnull=True),
                violation_error_message=(
                    "Пользователю уже выданы указанные права"
                ),
            ),
        ]

    def __str__(self) -> str:
        return (
            f"UserID={self.user.id}, "
            f"PermissionByGroupID={self.permission_by_group.id}"
        )


class PermissionByGroup(UUIDMixin, DatetimeStampedMixin):
    """Модель - Право доступа по группе."""

    uri = models.CharField(max_length=256, null=False, help_text="URI ресурса")
    comment = models.CharField(
        max_length=256,
        null=True,
        help_text=(
            "Комментарий к выделению права для группы "
            "(может использоваться для объяснения причины и т.д.)"
        ),
    )

    group = models.ForeignKey("Group", on_delete=models.CASCADE)

    class Meta:
        db_table = 'users"."permission_by_group'
        verbose_name = "Право доступа по группе"
        verbose_name_plural = "Права доступа по группам"

        constraints = [
            models.UniqueConstraint(
                fields=["uri", "group"],
                name="group_permission_unique",
                condition=models.Q(deleted_at__isnull=True),
                violation_error_message="У группы имеется доступ к ресурсу",
            ),
        ]

    def __str__(self) -> str:
        return f"GroupID={self.group.id}(URI={self.uri})"


class Group(UUIDMixin, DatetimeStampedMixin):
    """Модель - Группа."""
    title = models.CharField(
        max_length=128,
        null=False,
        help_text="Наименование группы (ru)",
    )
    alias = models.CharField(
        max_length=128,
        null=False,
        help_text="Alias группы (en)",
    )

    class Meta:
        db_table = 'users"."group'
        verbose_name = "Группа"
        verbose_name_plural = "Группы"

        constraints = [
            models.UniqueConstraint(
                fields=["title"],
                name="group_title_unique",
                condition=models.Q(deleted_at__isnull=True),
                violation_error_message="Группа с таким наименованием создана",
            ),
            models.UniqueConstraint(
                fields=["alias"],
                name="group_alias_unique",
                condition=models.Q(deleted_at__isnull=True),
                violation_error_message="Группа с таким alias создана",
            ),
        ]

    def __str__(self) -> str:
        return f"GroupTitle={self.title}(Alias={self.alias})"
