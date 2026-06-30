"""FastAPI endpoints protected by the lab's Casbin RBAC policy."""

from pathlib import Path

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException

from src.access.rbac import get_current_user, require_permission
from src.pii.anonymizer import MedVietAnonymizer

app = FastAPI(title="MedViet Data API", version="1.0.0")
anonymizer = MedVietAnonymizer()
DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "raw" / "patients_raw.csv"


def _read_patients() -> pd.DataFrame:
    if not DATA_FILE.exists():
        raise HTTPException(status_code=503, detail="Patient dataset is unavailable")
    return pd.read_csv(
        DATA_FILE, dtype={"cccd": str, "so_dien_thoai": str}
    )


@app.get("/api/patients/raw")
@require_permission(resource="patient_data", action="read")
async def get_raw_patients(current_user: dict = Depends(get_current_user)):
    """Return the first ten raw patient records (admin only)."""
    return _read_patients().head(10).to_dict(orient="records")


@app.get("/api/patients/anonymized")
@require_permission(resource="training_data", action="read")
async def get_anonymized_patients(current_user: dict = Depends(get_current_user)):
    """Return anonymized patient records for authorized model training."""
    return anonymizer.anonymize_dataframe(_read_patients()).head(10).to_dict(
        orient="records"
    )


@app.get("/api/metrics/aggregated")
@require_permission(resource="aggregated_metrics", action="read")
async def get_aggregated_metrics(current_user: dict = Depends(get_current_user)):
    """Return non-PII patient counts grouped by condition."""
    counts = _read_patients()["benh"].value_counts().sort_index()
    return {
        "total_patients": int(counts.sum()),
        "patients_by_condition": {
            condition: int(count) for condition, count in counts.items()
        },
    }


@app.delete("/api/patients/{patient_id}")
@require_permission(resource="patient_data", action="delete")
async def delete_patient(
    patient_id: str, current_user: dict = Depends(get_current_user)
):
    """Validate a patient deletion request (admin only, demo is non-persistent)."""
    df = _read_patients()
    if patient_id not in set(df["patient_id"].astype(str)):
        raise HTTPException(status_code=404, detail="Patient not found")
    return {"status": "deleted", "patient_id": patient_id}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "MedViet Data API"}
