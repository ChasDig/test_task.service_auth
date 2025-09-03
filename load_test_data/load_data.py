from datetime import datetime, timezone
from uuid import uuid4
import asyncio
import logging

import psycopg

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
    def insert_user_by_group_association(self) -> str:
        return (
            "INSERT INTO users.user_by_group_association "
            "(id, created_at, updated_at, user_id, group_id) "
            "VALUES (%s, %s, %s, %s, %s)"
        )

    @property
    def insert_permission_by_group(self) -> str:
        return (
            "INSERT INTO users.permission_by_group "
            "(id, created_at, updated_at, uri, uri_name, comment, group_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)"
        )

    async def gen(self) -> None:
        async with await psycopg.AsyncConnection.connect(
            config.pg_url_connection
        ) as pg_connect:
            await self._gen_test_data_for_base_user(pg_connect)
            loger.info("Gen data for user with role 'User'")

            await self._gen_test_data_for_admin_user(pg_connect)
            loger.info("Gen data for user with role 'Admin'")

            await pg_connect.commit()

    loger.info("All test data was gen")

    async def _gen_test_data_for_base_user(self, pg_connect):
        now_ = datetime.now(timezone.utc).isoformat()
        user_id = str(uuid4())
        group_id = str(uuid4())
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
                    "bMvWwYg5wupZjci9CnnLYBCZ9YCthlxQ0Q1VNcWtCab1c7Xq4lU3Kh6nXV9WwditI2eur0jqEcqKygIX",
                    "945e4a270e0741c046bc76480fe8e57a59bd1b542b6cf81d546711febe6869c2",
                    "pbkdf2_sha256$1000000$IiuPs3Irpp4JFjk0kNS0O7$bjPd/vSaBn4b8G/Mg8UrEO1q/XdMH1WYNt7Tu/yqfIQ=",
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
                self.insert_user_by_group_association,
                (
                    user_by_group_association_id,
                    now_,
                    now_,
                    user_id,
                    group_id,
                ),
            )
            await cursor.execute(
                self.insert_permission_by_group,
                (
                    permission_by_group_id,
                    now_,
                    now_,
                    "auth/groups/create",
                    "create_group",
                    "comment",
                    group_id,
                ),
            )

    async def _gen_test_data_for_admin_user(self, pg_connect):
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
                    "Ej67AK/e5HE6IyEjZEn+SDGD1wtKCq1RcBiblFkr0fx9ruk+AQn1zCxYXRozCD1HpJfl2buwhI6lhQjAZA==",
                    "27e127563b9ba3f976e53569250fd4b58ee4b96fa7fc9abd9edc5e6952684720",
                    "pbkdf2_sha256$1000000$OmjTDaIec7yzJJ17XcWiDl$N/RRWa0h/ZL38f6wr+PeWm66a1Oc5BVQZQBawCAHLH0=",
                    "admin",
                ),
            )


if __name__ == "__main__":
    asyncio.run(DataForTestsGen().gen())