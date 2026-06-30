# NĐ13/2023 Compliance Checklist — MedViet AI Platform

## A. Data Localization
- [ ] Tất cả patient data lưu trên servers đặt tại Việt Nam
- [ ] Backup cũng phải ở trong lãnh thổ VN
- [ ] Log việc transfer data ra ngoài nếu có

## B. Explicit Consent
- [ ] Thu thập consent trước khi dùng data cho AI training
- [ ] Có mechanism để user rút consent (Right to Erasure)
- [ ] Lưu consent record với timestamp

## C. Breach Notification (72h)
- [ ] Có incident response plan
- [ ] Alert tự động khi phát hiện breach
- [ ] Quy trình báo cáo đến cơ quan có thẩm quyền trong 72h

## D. DPO Appointment
- [ ] Đã bổ nhiệm Data Protection Officer
- [ ] DPO có thể liên hệ tại: dpo@medviet.example

## E. Technical Controls (mapping từ requirements)
| NĐ13 Requirement | Technical Control | Status | Owner |
|-----------------|-------------------|--------|-------|
| Data minimization | PII anonymization pipeline (Presidio) | ✅ Done | AI Team |
| Access control | RBAC (Casbin) + ABAC (OPA) | ✅ Done | Platform Team |
| Encryption | AES-256 at rest, TLS 1.3 in transit | 🚧 In Progress | Infra Team |
| Audit logging | CloudTrail + API access logs | ⬜ Todo | Platform Team |
| Breach detection | Anomaly monitoring (Prometheus) | ⬜ Todo | Security Team |

## F. Kế hoạch hoàn thiện technical controls
### Audit logging — Platform Team

- Thêm middleware FastAPI phát sinh `request_id` và ghi log JSON bất biến gồm:
  user/role, resource, action, kết quả allow/deny, status code, timestamp và source IP;
  tuyệt đối không ghi token hoặc giá trị PII.
- Đẩy log qua TLS tới hệ thống tập trung đặt tại Việt Nam (OpenSearch/CloudTrail),
  mã hóa bằng KMS, phân quyền chỉ-đọc cho Security/DPO và bật Object Lock với thời
  hạn lưu 12 tháng.
- Tạo cảnh báo cho các sự kiện quan trọng như nhiều lần 401/403, đọc raw data số
  lượng lớn, thay đổi policy và yêu cầu export; kiểm tra khả năng truy vết hàng quý.

### Breach detection — Security Team

- Xuất metrics từ FastAPI, Casbin, database và hạ tầng sang Prometheus; xây baseline
  theo role cho tần suất truy cập, khối lượng bản ghi và quốc gia đích.
- Alertmanager cảnh báo khi có credential stuffing, quyền bị từ chối tăng đột biến,
  tải raw PII bất thường hoặc export restricted data. Cảnh báo mức critical gửi ngay
  tới SOC và DPO qua PagerDuty, đồng thời mở incident ticket có timestamp.
- Kết nối SIEM để tương quan log API/WAF/database, tự động khóa token đáng ngờ và
  lưu bằng chứng. Runbook quy định triage, containment, đánh giá dữ liệu ảnh hưởng và
  escalation đủ sớm để hoàn tất thông báo vi phạm trong 72 giờ.
