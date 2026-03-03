from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# 以项目根目录为基准构建稳定路径（避免工作目录变化导致路径错乱）
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
ENCRYPTED_DIR = DATA_DIR / "encrypted_files"
DB_PATH = DATA_DIR / "quantum_guard.db"

# 启动即确保目录存在
DATA_DIR.mkdir(parents=True, exist_ok=True)
ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)

# SQLite URL（使用绝对路径更稳）
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH.as_posix()}"

# FastAPI + SQLite 常用配置
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    future=True,
    expire_on_commit=False,
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """数据库会话生成器（FastAPI Depends 使用）"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()