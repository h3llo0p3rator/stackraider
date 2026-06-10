"""Unified StackRaider FastAPI web server."""

from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from stackraider.web.config import settings
from stackraider.web.routers import chat, code, graphql, health, legacy, models, session_router
from stackraider.web.session import (
    LEGACY_SESSION_COOKIE,
    SESSION_COOKIE,
    get_or_create_session,
)

STATIC_DIR = Path(__file__).parent / "static"


def create_app(default_path: Optional[str] = None) -> FastAPI:
    app = FastAPI(title="StackRaider", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins + ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def session_middleware(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            has_cookie = SESSION_COOKIE in request.cookies or LEGACY_SESSION_COOKIE in request.cookies
            set_cookie = response.headers.get("set-cookie", "")
            handler_set = SESSION_COOKIE in set_cookie or LEGACY_SESSION_COOKIE in set_cookie
            if not has_cookie and not handler_set:
                sid, _ = get_or_create_session(None)
                response.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="lax")
        return response

    app.include_router(health.router)
    app.include_router(models.router)
    app.include_router(session_router.router)
    app.include_router(code.router)
    app.include_router(graphql.router)
    app.include_router(chat.router)
    app.include_router(legacy.router)

    if STATIC_DIR.exists():
        assets_dir = STATIC_DIR / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/{full_path:path}")
        async def serve_spa(full_path: str):
            if full_path == "api" or full_path.startswith("api/"):
                raise HTTPException(404, detail="API route not found")
            file_path = STATIC_DIR / full_path
            if file_path.is_file():
                return FileResponse(file_path)
            index = STATIC_DIR / "index.html"
            if index.exists():
                return FileResponse(index)
            raise HTTPException(
                404,
                "Frontend not built. Run: cd frontend && npm install && npm run build",
            )

    if default_path:
        sid, state = get_or_create_session(None)
        state["default_path"] = str(Path(default_path).resolve())

    return app


def _wait_and_open_browser(url: str) -> None:
    import threading
    import time
    import urllib.request

    def _open():
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{url}/api/health", timeout=0.5)
                webbrowser.open(url)
                return
            except Exception:
                time.sleep(0.2)

    threading.Thread(target=_open, daemon=True).start()


def start(path: Optional[str] = None, port: int = 8000, open_browser: bool = True):
    import uvicorn

    app = create_app(default_path=path)
    url = f"http://127.0.0.1:{port}"
    print(f"\n  StackRaider Web UI:  {url}")
    print(f"  Health:  {url}/api/health")
    print()
    print("  If the browser shows 'Unable to connect':")
    print("    - Disable Burp Suite / VPN proxy in Firefox (common cause)")
    print("    - Or add 127.0.0.1 to Firefox → Settings → Network → No proxy for")
    print()

    if open_browser:
        _wait_and_open_browser(url)

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
