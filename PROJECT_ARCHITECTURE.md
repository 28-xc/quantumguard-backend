# QuantumGuard Backend Architecture

## 核心设计原则（Zero-Trust）

1. **后端致盲（Server Blindness）**  
   服务器仅负责“密文搬运与索引”，绝不接触以下任何敏感明文要素：  
   - 明文文件内容  
   - 会话对称密钥（AES key）  
   - 用户私钥（ML-KEM private key）

2. **TOFU 模型（Trust On First Use）**  
   公钥交换采用“首次使用信任”：  
   - 首次拉取对方公钥时，前端展示可视化指纹供人工带外核验（电话/IM）  
   - 指纹确认后才允许建立发送会话  
   - 若指纹不一致，立即销毁会话上下文并阻断传输

3. **存储分层，避免 I/O 雪崩**  
   - **磁盘流式落盘（Ciphertext Only）**：分块密文直接写入 `data/encrypted_files/`  
   - **轻量元数据索引（SQLite）**：仅保存必要索引信息（`file_id`、`storage_path`、`total_chunks`、`global_signature`、`sender/receiver` 等）  
   - 数据库不保存分块密文主体，降低写放大和锁竞争

---

## 传输与加密边界

- 前端使用 ML-KEM（FIPS 203）建立共享秘密，再导入 AES-GCM 进行分块加密  
- 每个分块携带独立 IV，结合 AAD（如 `file_id + chunk_index`）进行完整性绑定  
- 后端只接收并保存密文块，不进行解密、不校验明文语义

---

## 数据流（高层）

1. 接收方生成本地密钥对（私钥仅存 IndexedDB）并上传公钥 + 指纹  
2. 发送方拉取接收方公钥，完成人工指纹核验（TOFU）  
3. 发送方分块加密并上传密文块  
4. 后端按块索引写入磁文文件，最终 `finalize` 写入元数据  
5. 接收方下载整包密文并在本地完成解密与验签

---

## 安全约束（建议落地）

- `file_id`、`user_id` 做白名单校验，防路径注入与脏键
- `storage_path` 下载时必须限制在 `data/encrypted_files` 目录内
- CORS 在生产环境使用显式白名单，不使用 `"*"`
- 日志中避免打印公钥原文、密文片段、签名原文等敏感材料
- 关键接口返回统一错误码与最小必要错误信息，避免泄露内部结构

---

## 当前目录建议

```text
quantum-guard-backend/
├─ app/
│  ├─ routers/
│  │  ├─ key_exchange.py
│  │  └─ file_transfer.py
│  ├─ database.py
│  ├─ models.py
│  └─ main.py
└─ data/
   ├─ encrypted_files/
   └─ quantum_guard.db
```

---

## 如何运行

**后端**（在项目根目录 `quantum-guard-backend` 下执行）：

```bash
# 激活虚拟环境（若使用 .venv）
.venv\Scripts\activate   # Windows
# source .venv/bin/activate   # Linux/macOS

# 启动 API 服务（默认 http://127.0.0.1:8000）
python -m app.main
```

**前端**（在项目根目录 `quantum-guard-frontend` 下执行）：

```bash
npm run dev
```

浏览器访问前端地址（Vite 默认 http://localhost:5173），确保 `.env` 中 `VITE_API_BASE_URL=http://127.0.0.1:8000` 与后端一致。
