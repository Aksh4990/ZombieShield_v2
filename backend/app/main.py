import faulthandler
import logging
import signal
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.models  # noqa: F401 - registers SQLAlchemy models
from app.api.routers import auth, discovery, insights, inventory, pipeline, remediation, validation
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import engine
from app.services import bootstrap

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
if hasattr(signal, "SIGUSR1"):  # `docker kill -s USR1 <backend>` prints every thread's stack to the container log
    faulthandler.register(signal.SIGUSR1, all_threads=True)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(bind=engine)  # local runs and tests; PostgreSQL uses Alembic migrations
    bootstrap.recover_interrupted_runs()
    bootstrap.seed_users()
    bootstrap.seed_threat_cache()
    bootstrap.seed_sources()
    bootstrap.start_log_follower()
    yield
    bootstrap.stop_log_follower()


settings = get_settings()
app = FastAPI(title="ZombieShield API", version="2.0.0", lifespan=lifespan,
              description="API inventory, lifecycle classification and evidence-based risk insight for zombie and shadow APIs.")
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "healthy"}


for module in (auth, inventory, discovery, pipeline, insights, remediation, validation):
    app.include_router(module.router)
