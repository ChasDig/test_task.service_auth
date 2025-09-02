from datetime import UTC, datetime, timedelta
from typing import Any
from dataclasses import asdict

from django.conf import settings
from jose import JWTError, jwt

from .custom_enum import TokenType
from .custom_exception import TokenDataInvalidError
from .custom_dataclasses import TokenInfo, TokenPayload, Tokens


class Tokenizer:
    """Utils - работа с токенами Пользователя."""

    header = {"algorithm": settings.TOKEN_ALGORITHM, "type": "JWT"}
    token_key_template = "{user_id}${user_agent}${token_type}"

    @classmethod
    def gen_token(
        cls,
        type_: str,
        now_: datetime,
        exp_: float,
        sub: str,
        user_role: str,
        user_agent: str,
    ) -> str | Any:
        payload = TokenPayload(
            type=type_,
            iat=now_.timestamp(),
            exp=exp_,
            sub=sub,
            user_role=user_role,
            user_agent=user_agent,
        )
        return jwt.encode(
            claims=asdict(payload),
            key=settings.TOKEN_SECRET,
            algorithm=settings.TOKEN_ALGORITHM,
            headers=cls.header,
        )

    @classmethod
    def gen_tokens(
        cls,
        user_id: str,
        user_role: str,
        user_agent: str,
    ) -> Tokens:
        now_ = datetime.now(UTC)
        access_exp = (
            now_ + timedelta(minutes=settings.ACCESS_TOKEN_EXP_MIN)
        ).timestamp()
        refresh_exp = (
            now_ + timedelta(days=settings.REFRESH_TOKEN_EXP_DAYS)
        ).timestamp()

        return Tokens(
            access_token=TokenInfo(
                type=TokenType.access.name,
                ttl=int(access_exp - now_.timestamp()),
                token=cls.gen_token(
                    type_=TokenType.access.name,
                    now_=now_,
                    exp_=access_exp,
                    sub=user_id,
                    user_role=user_role,
                    user_agent=user_agent,
                ),
            ),
            refresh_token=TokenInfo(
                type=TokenType.refresh.name,
                ttl=int(refresh_exp - now_.timestamp()),
                token=cls.gen_token(
                    type_=TokenType.refresh.name,
                    now_=now_,
                    exp_=refresh_exp,
                    sub=user_id,
                    user_role=user_role,
                    user_agent=user_agent,
                ),
            ),
        )

    @staticmethod
    def decode_token(token: str) -> TokenPayload:
        try:
            token_data: dict[str, Any] = jwt.decode(
                token=token,
                key=settings.TOKEN_SECRET,
                algorithms=[settings.TOKEN_ALGORITHM],
            )

            return TokenPayload(
                type=token_data["type"],
                iat=token_data["iat"],
                exp=token_data["exp"],
                sub=token_data["sub"],
                user_role=token_data["user_role"],
                user_agent=token_data["user_agent"],
            )

        except (JWTError, KeyError):
            raise TokenDataInvalidError()
