import asyncio
import logging
from uuid import uuid4
from datetime import datetime, timezone

import psycopg
from psycopg import AsyncConnection

from config import config


loger = logging.getLogger(__name__)


class DataForTestsGen:
    """Класс для генерации тестовых данных."""

    @property
    def insert_user(self) -> str:
        return (
            "INSERT INTO users.user "
            "(id, created_at, updated_at, first_name, second_name, last_name, "
            "email_enc, email_hash, password_hash, role) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        )

    @property
    def insert_group(self) -> str:
        return (
            "INSERT INTO users.group "
            "(id, created_at, updated_at, title, alias) "
            "VALUES (%s, %s, %s, %s, %s)"
        )

    @property
    def insert_resource(self) -> str:
        return (
            "INSERT INTO users.resource "
            "(id, created_at, updated_at, uri, name, comment) "
            "VALUES (%s, %s, %s, %s, %s, %s)"
        )

    @property
    def insert_permission_by_group(self) -> str:
        return (
            "INSERT INTO users.permission_by_group "
            "(id, created_at, updated_at, resource_id, group_id) "
            "VALUES (%s, %s, %s, %s, %s)"
        )

    @property
    def insert_user_by_group_association(self) -> str:
        return (
            "INSERT INTO users.user_by_group_association "
            "(id, created_at, updated_at, user_id, group_id) "
            "VALUES (%s, %s, %s, %s, %s)"
        )

    async def gen(self) -> None:
        async with await psycopg.AsyncConnection.connect(
            config.pg_url_connection
        ) as pg_connect:
            try:
                await self._gen_test_data_for_base_user(pg_connect)
                loger.info("Gen data for user with role 'User'")

                await self._gen_test_data_for_admin_user(pg_connect)
                loger.info("Gen data for user with role 'Admin'")

                await pg_connect.commit()

            except Exception as ex:
                loger.error(f"Не удалось загрузить тестовые данные: {ex}")

    loger.info("All test data was gen")

    async def _gen_test_data_for_base_user(
        self,
        pg_connect: AsyncConnection,
    ) -> None:
        now_ = datetime.now(timezone.utc).isoformat()
        user_id = str(uuid4())
        group_id = str(uuid4())
        resource_id = str(uuid4())
        user_by_group_association_id = str(uuid4())
        permission_by_group_id = str(uuid4())

        async with pg_connect.cursor() as cursor:
            await cursor.execute(
                self.insert_user,
                (
                    user_id,
                    now_,
                    now_,
                    "first_name_1",
                    "second_name_1",
                    "last_name_1",
                    "yFBNQT4p5LIz5DfjoLoV+KsAcj0oXv+eIyE4AS/im8cvB8MmbH7F95HTyXfBDvh4HkwEHJ1JtOjrnvYruaA=",  # noqa: E501
                    "0fcd35b0d353586ef82fe870022358efaea1b61a5a5553b0ff4b693caed806ef",  # noqa: E501
                    "pbkdf2_sha256$1000000$0vv4vSqRyLMWp92ZVqoBVB$MFtVct7HAOMsf/ino91g2vY+z7KdlB58Z5tpnVX1R0o=",  # noqa: E501
                    "user",
                ),
            )
            await cursor.execute(
                self.insert_group,
                (
                    group_id,
                    now_,
                    now_,
                    "title_1",
                    "alias_1",
                ),
            )
            await cursor.execute(
                self.insert_resource,
                (
                    resource_id,
                    now_,
                    now_,
                    "auth/groups/create",
                    "create_group",
                    "comment",
                ),
            )
            await cursor.execute(
                self.insert_permission_by_group,
                (
                    permission_by_group_id,
                    now_,
                    now_,
                    resource_id,
                    group_id,
                ),
            )
            await cursor.execute(
                self.insert_user_by_group_association,
                (
                    user_by_group_association_id,
                    now_,
                    now_,
                    user_id,
                    group_id,
                ),
            )

    async def _gen_test_data_for_admin_user(
        self,
        pg_connect: AsyncConnection,
    ) -> None:
        now_ = datetime.now(timezone.utc).isoformat()
        user_id = str(uuid4())

        async with pg_connect.cursor() as cursor:
            await cursor.execute(
                self.insert_user,
                (
                    user_id,
                    now_,
                    now_,
                    "first_name_2",
                    "second_name_2",
                    "last_name_2",
                    "Bz0DSzleDrM8Yb9auNZQgSWi9oHDAOWcDsyifXSihDCZaY5o/puN42fbd534V7CU9GGIv+xyHWaal6rPe50=",  # noqa: E501
                    "e8b02b8b69aea861b1ef459e3fcb7a5794b1074c7c2d63c69394bac31e53835f",  # noqa: E501
                    "pbkdf2_sha256$1000000$qvzOvL9rlG4HipJeHGd1Jt$Uw6K6zYW5vn1MfpGOyUMh3gY86WqgM5ikBLXlqxTel4=",  # noqa: E501
                    "admin",
                ),
            )


if __name__ == "__main__":
    asyncio.run(DataForTestsGen().gen())
