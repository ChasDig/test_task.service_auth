from dataclasses import dataclass

@dataclass
class TokenPayload:
    """Модель данных - payload формируемого токена."""

    type: str
    iat: float
    exp: float
    sub: str
    user_role: str
    user_agent: str


@dataclass
class TokenInfo:
    """Модель данных - token + meta-информация по нему."""

    type: str
    ttl: int
    token: str


@dataclass
class Tokens:
    """Модель данных - token-ы."""

    access_token: TokenInfo
    refresh_token: TokenInfo
