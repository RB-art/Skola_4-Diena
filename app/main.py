"""2. līmenis · HTTP API (FastAPI), kas savieno prezentācijas un datu līmeni.

Palaišana:  uvicorn app.main:app --reload
"""

import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from app.data import UserRepository
from app.service import AuthError, AuthService

STATIC_DIR = Path(__file__).parent / "static"
DEFAULT_DB_PATH = Path(os.environ.get("APP_DB_PATH", Path(__file__).parent / "app.db"))


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


def create_app(db_path: Path = DEFAULT_DB_PATH) -> FastAPI:
    service = AuthService(UserRepository(db_path))
    app = FastAPI(title="Pieslēgšanās demo")

    def bearer_token(authorization: str = Header(default="")) -> str:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail="Nav pieslēgšanās")
        return token

    @app.exception_handler(AuthError)
    async def handle_auth_error(_request, exc: AuthError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.post("/api/register", status_code=201)
    def register(body: RegisterRequest) -> dict:
        user = service.register(body.username, body.email, body.password)
        return {"id": user.id, "username": user.username, "email": user.email}

    @app.post("/api/login")
    def login(body: LoginRequest) -> dict:
        return {"token": service.login(body.username, body.password)}

    @app.get("/api/me")
    def me(token: str = Depends(bearer_token)) -> dict:
        user = service.current_user(token)
        return {"id": user.id, "username": user.username, "email": user.email}

    @app.post("/api/logout", status_code=204)
    def logout(token: str = Depends(bearer_token)) -> None:
        service.logout(token)

    return app


app = create_app()
