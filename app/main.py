from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.database import engine
from app import models
from app.routers import key_exchange, file_transfer


def _migrate_add_updated_at():
    """为旧版 user_public_keys 表补全 updated_at 列（若缺失）"""
    with engine.connect() as conn:
        try:
            conn.execute(text(
                "ALTER TABLE user_public_keys ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP"
            ))
            conn.commit()
        except Exception as e:
            if "duplicate column" in str(e).lower():
                pass  # 列已存在，忽略
            else:
                raise


@asynccontextmanager
async def lifespan(_: FastAPI):
    models.Base.metadata.create_all(bind=engine)
    try:
        _migrate_add_updated_at()
    except Exception:
        pass  # 表不存在或迁移失败时跳过
    yield


app = FastAPI(
    title="QuantumGuard Backend",
    version="1.0.0",
    lifespan=lifespan,
)

# 开发环境：允许任意来源，避免 CORS 拦截；生产环境请改为具体前端域名
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(_, exc: Exception):
    """未捕获异常统一返回 500 + JSON，便于前端显示且带 CORS"""
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc) or "服务器内部错误"},
        headers={"Access-Control-Allow-Origin": "*"},
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok"}

app.include_router(key_exchange.router)
app.include_router(file_transfer.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)