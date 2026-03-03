import base64
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import UserPublicKey

router = APIRouter(prefix="/keys", tags=["Key Exchange"])

# ML-KEM-768 公钥长度（字节）
MLKEM768_PUBLIC_KEY_BYTES = 1184

# user_id 白名单（按你项目需要可放宽）
USER_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# 指纹格式：例如 "AA:BB:CC:...:FF" 共16字节 => 47字符
FINGERPRINT_RE = re.compile(r"^(?:[0-9A-F]{2}:){15}[0-9A-F]{2}$")


def validate_public_key_b64(pk_b64: str) -> None:
    try:
        raw = base64.b64decode(pk_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="public_key_b64 非法（Base64 解析失败）")

    if len(raw) != MLKEM768_PUBLIC_KEY_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"public_key_b64 长度非法，解码后为 {len(raw)} 字节，期望 {MLKEM768_PUBLIC_KEY_BYTES}"
        )


class PublicKeyUpload(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    public_key_b64: str = Field(..., min_length=100, max_length=4096)
    fingerprint: str = Field(..., min_length=47, max_length=47)

    @field_validator("user_id")
    @classmethod
    def _validate_user_id(cls, v: str) -> str:
        v = v.strip()
        if not USER_ID_RE.match(v):
            raise ValueError("user_id 非法，仅允许字母/数字/._-，长度 1~64")
        return v

    @field_validator("fingerprint")
    @classmethod
    def _validate_fingerprint(cls, v: str) -> str:
        v = v.strip().upper()
        if not FINGERPRINT_RE.match(v):
            raise ValueError("fingerprint 格式非法，应为 AA:BB:...:FF（16字节）")
        return v

    @field_validator("public_key_b64")
    @classmethod
    def _validate_public_key_b64(cls, v: str) -> str:
        v = v.strip()
        # 这里只做模型内校验，具体错误走 HTTPException 在路由层也会再防一层
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("public_key_b64 非法（Base64）")
        if len(raw) != MLKEM768_PUBLIC_KEY_BYTES:
            raise ValueError(
                f"public_key_b64 长度非法，解码后 {len(raw)} 字节，期望 {MLKEM768_PUBLIC_KEY_BYTES}"
            )
        return v


@router.post("/upload")
def upload_public_key(data: PublicKeyUpload, db: Session = Depends(get_db)):
    """
    TOFU（首次使用信任）：
    - 首次上传：创建记录
    - 已存在：允许覆盖（你当前策略），同时返回 changed 标记
    """
    # 双保险：即使绕过模型，也在路由层校验一次
    validate_public_key_b64(data.public_key_b64)

    existing_key: Optional[UserPublicKey] = (
        db.query(UserPublicKey)
        .filter(UserPublicKey.user_id == data.user_id)
        .first()
    )

    changed = False
    if existing_key:
        # 判断是否发生变化（可用于前端提示“公钥轮换”）
        changed = (
            existing_key.public_key_b64 != data.public_key_b64
            or existing_key.fingerprint != data.fingerprint
        )

        existing_key.public_key_b64 = data.public_key_b64
        existing_key.fingerprint = data.fingerprint
    else:
        new_key = UserPublicKey(
            user_id=data.user_id,
            public_key_b64=data.public_key_b64,
            fingerprint=data.fingerprint
        )
        db.add(new_key)
        changed = True

    db.commit()

    return {
        "status": "success",
        "message": "Public key registered (TOFU)",
        "user_id": data.user_id,
        "changed": changed
    }


@router.get("/{user_id}")
def get_public_key(user_id: str, db: Session = Depends(get_db)):
    uid = user_id.strip()
    if not USER_ID_RE.match(uid):
        raise HTTPException(status_code=400, detail="非法 user_id")

    key_record: Optional[UserPublicKey] = (
        db.query(UserPublicKey)
        .filter(UserPublicKey.user_id == uid)
        .first()
    )

    if not key_record:
        raise HTTPException(status_code=404, detail="User public key not found")

    return {
        "user_id": key_record.user_id,
        "public_key_b64": key_record.public_key_b64,
        "fingerprint": key_record.fingerprint
    }