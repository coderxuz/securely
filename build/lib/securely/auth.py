from passlib.context import CryptContext
from authlib.jose import jwt, JWTClaims  # type: ignore
from authlib.jose.errors import (
    DecodeError,
    ExpiredTokenError,
    BadSignatureError,
    InvalidClaimError,
)
from fastapi import HTTPException, status


from datetime import datetime, timedelta
from typing import TypedDict


class Tokens(TypedDict):
    accessToken: str
    refreshToken: str


class Auth:

    def __init__(
        self,
        secret_key: str,
        access_token_expires: timedelta,
        refresh_token_expires: timedelta,
    ):

        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.secret_key = secret_key
        self.refresh_token_expires = refresh_token_expires
        self.access_token_expires = access_token_expires

    def hash_password(self, password: str) -> str:
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str):
        return self.pwd_context.verify(plain_password, hashed_password)

    def create_tokens(self, subject: str) -> Tokens:
        # Access token expires in 'access_exp' minutes
        access_token_exp = datetime.utcnow() + self.access_token_expires
        access_token = jwt.encode(
            {"alg": "HS256"}, {"sub": subject, "exp": access_token_exp}, self.secret_key
        ).decode()

        # Refresh token expires in 'refresh_exp' days
        refresh_token_exp = datetime.utcnow() + self.refresh_token_expires
        refresh_token = jwt.encode(
            {"alg": "HS256"},
            {"sub": subject, "exp": refresh_token_exp},
            self.secret_key,
        ).decode()

        return {"accessToken": access_token, "refreshToken": refresh_token}

    def _decode_token(self, token: str) -> JWTClaims:
        try:
            token_decoded:JWTClaims = jwt.decode(token, self.secret_key) # type: ignore
            if not token_decoded:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
                )
            if not isinstance(token_decoded, JWTClaims):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
                )
            return token_decoded
        except DecodeError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
            )

    def get_subject(self, token: str) -> JWTClaims:
        try:
            # Decode the token
            payload: JWTClaims = jwt.decode(token, self.secret_key) # type: ignore

            # Extract the subject
            subject:JWTClaims = payload.get("sub") # type: ignore
            if not subject:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Token subject is missing",
                )
            return subject

        except (ExpiredTokenError, DecodeError, BadSignatureError, InvalidClaimError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
