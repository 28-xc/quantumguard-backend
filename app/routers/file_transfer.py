import os
import re
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.database import get_db, ENCRYPTED_DIR
from app.models import FileMetadata, UserPublicKey

router = APIRouter(prefix="/files", tags=["File Transfer"])

# 与 database 使用同一目录，避免工作目录变化导致路径不一致
STORAGE_DIR = ENCRYPTED_DIR

# 2MB + 12(IV) + 16(GCM Tag)
CHUNK_PLAINTEXT_SIZE = 2 * 1024 * 1024
CHUNK_OVERHEAD = 12 + 16
CHUNK_PHYSICAL_SIZE = CHUNK_PLAINTEXT_SIZE + CHUNK_OVERHEAD

# 简单白名单，防止 file_id 路径注入
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


def _safe_file_id(file_id: str) -> str:
    fid = (file_id or "").strip()
    if not SAFE_ID_RE.match(fid):
        raise HTTPException(status_code=400, detail="非法 file_id")
    return fid


def _safe_storage_path(file_id: str) -> Path:
    """单文件模式遗留：返回 {fid}.enc 路径（用于兼容旧数据）"""
    fid = _safe_file_id(file_id)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return STORAGE_DIR / f"{fid}.enc"


def _chunk_dir(file_id: str) -> Path:
    """按 file_id 的分块目录，每块单独文件避免乱序/空洞导致解密失败"""
    fid = _safe_file_id(file_id)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return STORAGE_DIR / fid


@router.post("/upload_chunk")
async def upload_chunk(
    file_id: str = Form(...),
    chunk_index: int = Form(...),
    file: UploadFile = File(...)
):
    if chunk_index < 0:
        raise HTTPException(status_code=400, detail="chunk_index 必须 >= 0")

    chunk_dir = _chunk_dir(file_id)
    chunk_dir.mkdir(parents=True, exist_ok=True)
    chunk_path = chunk_dir / str(chunk_index)

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="上传分块为空")
    if len(content) > CHUNK_PHYSICAL_SIZE:
        raise HTTPException(status_code=400, detail="分块大小异常，超过最大物理块大小")

    chunk_path.write_bytes(content)
    return {"status": "success", "chunk_index": chunk_index, "written": len(content)}


@router.post("/finalize")
def finalize_upload(
    file_id: str = Form(...),
    sender_id: str = Form(...),
    receiver_id: str = Form(...),
    total_chunks: int = Form(...),
    global_signature: str = Form(...),
    file_name: Optional[str] = Form(None),
    file_size: Optional[int] = Form(None),
    db: Session = Depends(get_db)
):
    fid = _safe_file_id(file_id)

    if not sender_id.strip() or not receiver_id.strip():
        raise HTTPException(status_code=400, detail="sender_id / receiver_id 不能为空")
    if total_chunks <= 0:
        raise HTTPException(status_code=400, detail="total_chunks 必须 > 0")
    if not global_signature.strip():
        raise HTTPException(status_code=400, detail="global_signature 不能为空")

    # 发送方必须已注册，禁止冒用未注册 ID
    sender_exists = db.query(UserPublicKey).filter(UserPublicKey.user_id == sender_id.strip()).first()
    if not sender_exists:
        raise HTTPException(
            status_code=400,
            detail="发送方 ID 未注册，请先完成注册后再发送"
        )
    # 接收方也必须已注册（公钥存在）
    receiver_exists = db.query(UserPublicKey).filter(UserPublicKey.user_id == receiver_id.strip()).first()
    if not receiver_exists:
        raise HTTPException(
            status_code=400,
            detail="接收方 ID 未注册，无法向其发送文件"
        )

    chunk_dir = _chunk_dir(fid)
    if not chunk_dir.exists() or not chunk_dir.is_dir():
        raise HTTPException(status_code=404, detail="密文分块目录未能在磁盘生成")
    for i in range(total_chunks):
        if not (chunk_dir / str(i)).exists():
            raise HTTPException(
                status_code=400,
                detail=f"缺少分块 {i}/{total_chunks}，请确保所有分块上传完成后再 finalize"
            )

    exists = db.query(FileMetadata).filter(FileMetadata.file_id == fid).first()
    if exists:
        raise HTTPException(status_code=409, detail="该 file_id 已存在，禁止重复 finalize")

    new_metadata = FileMetadata(
        file_id=fid,
        sender_id=sender_id.strip(),
        receiver_id=receiver_id.strip(),
        total_chunks=total_chunks,
        global_signature=global_signature.strip(),
        storage_path=str(chunk_dir.resolve()),
        file_name=(file_name or "").strip() or None,
        file_size=file_size if (file_size is not None and file_size >= 0) else None,
    )

    db.add(new_metadata)
    db.commit()

    return {"status": "success", "file_id": fid}


@router.get("/list/{receiver_id}")
def list_receiver_files(
    receiver_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    rid = receiver_id.strip()
    if not rid:
        raise HTTPException(status_code=400, detail="receiver_id 不能为空")

    files = (
        db.query(FileMetadata)
        .filter(FileMetadata.receiver_id == rid)
        .order_by(FileMetadata.created_at.desc())
        .limit(limit)
        .all()
    )

    # 转为可序列化结构，避免 ORM 与 datetime 无法直接 JSON 序列化
    file_list = [
        {
            "file_id": f.file_id,
            "sender_id": f.sender_id,
            "receiver_id": f.receiver_id,
            "total_chunks": f.total_chunks,
            "global_signature": f.global_signature,
            "file_name": f.file_name,
            "file_size": f.file_size,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in files
    ]
    return {"status": "success", "files": file_list}


def _read_chunks_in_order(chunk_dir: Path, total_chunks: int) -> bytes:
    """按 chunk_index 0,1,2,... 顺序读取并拼接为完整密文，保证与加密端一致"""
    parts = []
    for i in range(total_chunks):
        chunk_path = chunk_dir / str(i)
        if not chunk_path.is_file():
            raise FileNotFoundError(f"分块 {i} 缺失")
        parts.append(chunk_path.read_bytes())
    return b"".join(parts)


@router.get("/download/{file_id}")
def download_encrypted_file(file_id: str, db: Session = Depends(get_db)):
    fid = _safe_file_id(file_id)

    file_record = db.query(FileMetadata).filter(FileMetadata.file_id == fid).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="文件不存在")

    path = Path(file_record.storage_path).resolve()
    if not path.exists():
        raise HTTPException(status_code=404, detail="文件不存在或存储路径无效")

    try:
        path.relative_to(STORAGE_DIR)
    except ValueError:
        raise HTTPException(status_code=400, detail="非法存储路径")

    # 新格式：storage_path 为分块目录，按顺序读入并一次性返回（避免流式导致客户端收不全）
    if path.is_dir():
        total = file_record.total_chunks
        if not total or total <= 0:
            raise HTTPException(status_code=500, detail="total_chunks 无效")
        content = _read_chunks_in_order(path, total)
        return Response(
            content=content,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{fid}.enc"'},
        )

    # 兼容旧格式：单文件 .enc
    if not path.is_file():
        raise HTTPException(status_code=404, detail="文件不存在或存储路径无效")
    return FileResponse(
        path=str(path),
        media_type="application/octet-stream",
        filename=f"{fid}.enc",
    )