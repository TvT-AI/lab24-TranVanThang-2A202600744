# Báo cáo Lab 24 — Data Governance & Security

## Phân loại dữ liệu

- PII/định danh trực tiếp: `ho_ten`, `cccd`, `so_dien_thoai`, `email`,
  `dia_chi`, `bac_si_phu_trach`.
- Định danh giả và quasi-identifier: `patient_id`, `ngay_sinh`, `ngay_kham`.
- Dữ liệu sức khỏe nhạy cảm cần bảo vệ dù được giữ làm feature:
  `benh`, `ket_qua_xet_nghiem`.

## Kết quả triển khai

- Custom Presidio recognizers cho CCCD 12 số, số điện thoại Việt Nam, email và
  tên người; có fallback khi máy không cài Vietnamese spaCy model.
- Anonymization thay thế toàn bộ PII trực tiếp, giữ nguyên feature dùng cho model.
- Casbin RBAC và FastAPI áp dụng default-deny cho admin, ML engineer, data analyst
  và intern; OPA bổ sung ràng buộc không export restricted data ra ngoài Việt Nam.
- Envelope encryption dùng DEK ngẫu nhiên theo từng payload và AES-256-GCM; DEK
  được KEK mã hóa, không xuất hiện plaintext trong payload.
- Dữ liệu processed gồm 200 dòng và qua toàn bộ quality checks.

## Verification

- Pytest: **16 passed**.
- PII detection rate trên 50 dòng đầu: **100%**.
- Bandit: **0 medium/high severity findings**.
- Encryption round-trip và kiểm tra tamper detection: **passed**.
