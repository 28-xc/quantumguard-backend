from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, DateTime, BigInteger, CheckConstraint, Index
from app.database import Base


def utcnow() -> datetime:
    # 使用 timezone-aware UTC 时间，避免时区歧义
    return datetime.now(timezone.utc)


class UserPublicKey(Base):
    """TOFU 公钥表：仅存用户抗量子公钥与可视化指纹"""
    __tablename__ = "user_public_keys"

    user_id = Column(String(64), primary_key=True, index=True)      # 例如 'Alice'
    public_key_b64 = Column(String(4096), nullable=False)           # ML-KEM 公钥(Base64)
    fingerprint = Column(String(47), nullable=False)                # 16字节指纹: AA:BB:...:FF
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False
    )


class FileMetadata(Base):
    """文件元数据表：落盘文件索引，不存明文块"""
    __tablename__ = "file_metadata"

    # 保留字符串主键（前端通常用 UUID）
    file_id = Column(String(128), primary_key=True, index=True)

    sender_id = Column(String(64), nullable=False, index=True)
    receiver_id = Column(String(64), nullable=False, index=True)

    total_chunks = Column(Integer, nullable=False)                  # 总分块数
    global_signature = Column(String(1024), nullable=False)         # 全局防篡改签名
    storage_path = Column(String(1024), nullable=False)             # 密文落盘路径

    # 可选元数据（若前端上传则可存）
    file_name = Column(String(512), nullable=True)
    file_size = Column(BigInteger, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("total_chunks > 0", name="ck_file_metadata_total_chunks_positive"),
        CheckConstraint("file_size IS NULL OR file_size >= 0", name="ck_file_metadata_file_size_non_negative"),
        Index("ix_file_metadata_receiver_created_at", "receiver_id", "created_at"),
        Index("ix_file_metadata_sender_created_at", "sender_id", "created_at"),
    )