from uuid import uuid4

from django.utils import timezone
from django.db import models


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


class UserPermissionByRoleAssociation(UUIDMixin, DatetimeStampedMixin):
    """Модель-связь - Пользователь и Право доступа роли."""

    user = models.ForeignKey("User", on_delete=models.CASCADE)
    permission_by_role = models.ForeignKey(
        "PermissionByRole",
        on_delete=models.CASCADE,
    )

    class Meta:
        db_table = 'users"."user_permission_by_role_association'
        constraints = [
            models.UniqueConstraint(
                fields=["user", "permission_by_role"],
                name="unique_user_role_permission",
                condition=models.Q(deleted_at__isnull=True),
                violation_error_message=(
                    "Пользователю уже выданы указанные права"
                ),
            ),
        ]

    def __str__(self) -> str:
        return (
            f"UserID={self.user.id}, "
            f"PermissionByRoleID={self.permission_by_role.id}"
        )


class PermissionByRole(UUIDMixin, DatetimeStampedMixin):
    """Модель - Право доступа по роли."""

    uri = models.CharField(max_length=256, null=False, help_text="URI ресурса")
    comment = models.CharField(
        max_length=256,
        null=True,
        help_text=(
            "Комментарий к выделению права для роли "
            "(может использоваться для объяснения причины и т.д.)"
        ),
    )

    role = models.ForeignKey("Role", on_delete=models.CASCADE)

    class Meta:
        db_table = 'users"."permission_by_role'
        verbose_name = "Право доступа по роли"
        verbose_name_plural = "Права доступа по ролям"

        constraints = [
            models.UniqueConstraint(
                fields=["uri", "role"],
                name="role_permission_unique",
                condition=models.Q(deleted_at__isnull=True),
                violation_error_message="У роли уже имеется доступ к ресурсу",
            ),
        ]

    def __str__(self) -> str:
        return f"RoleID={self.role.id}(URI={self.uri})"


class Role(UUIDMixin, DatetimeStampedMixin):
    """Модель - Роль."""

    name = models.CharField(max_length=128, null=False)

    class Meta:
        db_table = 'users"."role'
        verbose_name = "Роль"
        verbose_name_plural = "Роли"

        constraints = [
            models.UniqueConstraint(
                fields=["name"],
                name="role_name_unique",
                condition=models.Q(deleted_at__isnull=True),
                violation_error_message="Роль с таким наименованием создана",
            ),
        ]

    def __str__(self) -> str:
        return f"RoleName={self.name}"
