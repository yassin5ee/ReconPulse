"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes import assets, exports, findings, graph, projects, scans, stats
from backend.core.config import get_settings
from backend.core.logging import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(get_settings().log_level)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ReconPulse API",
        description=(
            "REST API for the ReconPulse reconnaissance platform. "
            "For use ONLY on targets you are explicitly authorized to test."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o for o in settings.cors_origins.split(",") if o],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    for router in (projects.router, scans.router, assets.router,
                   findings.router, graph.router, stats.router, exports.router):
        app.include_router(router)

    @app.get("/health", tags=["system"])
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()


def main() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run("backend.api.app:app", host=settings.api_host, port=settings.api_port)
