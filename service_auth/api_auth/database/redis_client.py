import json
import logging

from django.conf import settings
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from redis.asyncio import ConnectionPool, Redis
from ..utils.custom_exception import RedisError


logger = logging.getLogger(__name__)

redis_pool = ConnectionPool(
    password=settings.REDIS_PASSWORD,
    db=settings.REDIS_DB,
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    decode_responses=True,
    max_connections=settings.REDIS_MAX_CONNECTION_POOL,
)


class RedisClient:
    """Асинхронный клиент Redis."""

    def __init__(self) -> None:
        self._client = Redis(connection_pool=redis_pool)

    async def close(self) -> None:
        await self._client.close()

    async def ping(self) -> None:
        await self._client.ping()

    async def set(
        self,
        key: str,
        value: str | dict[str, str | int],
        ttl: int | None = None,
    ) -> None:
        """
        Прослойка - вставка значений в Redis.

        @type key: str
        @param key:
        @type value: str | dict[str, str | int]
        @param value:
        @type ttl: int | None
        @param ttl:

        @rtype: None
        @return:
        """
        if isinstance(value, dict):
            value = json.dumps(value)

        try:
            await self._client.set(key, value, ex=ttl)

        except Exception as ex:
            logger.error(f"Error set data in Redis: {ex}")
            raise RedisError()

    async def get(
        self,
        key: str | Any,
        as_dict: bool = False,
    ) -> dict[str, str | int] | str | None:
        """
        Прослойка - получение значений из Redis.

        @type key: str | bytes | bytearray
        @param key:
        @type as_dict: bool
        @param as_dict: Флаг - для получаемых значений требуется сериализация.

        @rtype value: dict[str, str | int] | str | None
        @return value:
        """
        try:
            value = await self._client.get(key)

        except Exception as ex:
            logger.error(f"Error get data from Redis: {ex}")
            raise RedisError()

        if as_dict and value is not None:
            try:
                value = json.loads(value)

            except (json.JSONDecodeError, TypeError) as ex:
                logger.warning(f"Can't parse str as dict: {ex}")

        return value  # type: ignore

    async def delete(self, key: str) -> None:
        """
        Прослойка - удаление значений из Redis.

        @type key: str
        @param key:

        @rtype: None
        @return:
        """
        try:
            await self._client.delete(key)

        except Exception as ex:
            logger.error(f"Error delete data from Redis: {ex}")
            raise RedisError()

    async def delete_by_pattern(self, pattern: str):
        cursor = b"0"
        while cursor:
            cursor, keys = await self._client.scan(
                cursor=cursor,
                match=pattern,
                count=100,
            )
            if keys:
                await self._client.delete(*keys)


@asynccontextmanager
async def redis_context_manager() -> AsyncGenerator[RedisClient, Any]:
    """
    Асинхронный контекстный менеджер для получения активного клиента Redis.

    @rtype: AsyncGenerator[RedisClient, Any]
    @return:
    """
    client = RedisClient()

    try:
        yield client

    finally:
        await client.close()
