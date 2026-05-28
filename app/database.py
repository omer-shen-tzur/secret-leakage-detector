from pathlib import Path

from sqlmodel import SQLModel, create_engine

from app import models  # noqa: F401

DATABASE_PATH = Path("data/scans.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

engine = create_engine(DATABASE_URL, echo=False)


def init_db() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SQLModel.metadata.create_all(engine)
