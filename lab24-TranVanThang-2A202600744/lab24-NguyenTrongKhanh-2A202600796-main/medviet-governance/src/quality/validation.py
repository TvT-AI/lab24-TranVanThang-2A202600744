"""Data quality expectations and lightweight validation reporting."""

from pathlib import Path

import great_expectations.expectations as gxe
import pandas as pd
from great_expectations.core import ExpectationSuite

VALID_CONDITIONS = ["Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"]
IMPORTANT_COLUMNS = ["patient_id", "cccd", "benh", "ket_qua_xet_nghiem"]


def build_patient_expectation_suite() -> ExpectationSuite:
    """Build a reusable Great Expectations suite for patient data."""
    expectations = [
        gxe.ExpectColumnValuesToNotBeNull(column="patient_id"),
        gxe.ExpectColumnValueLengthsToEqual(column="cccd", value=12),
        gxe.ExpectColumnValuesToBeBetween(
            column="ket_qua_xet_nghiem", min_value=0, max_value=50
        ),
        gxe.ExpectColumnValuesToBeInSet(
            column="benh", value_set=VALID_CONDITIONS
        ),
        gxe.ExpectColumnValuesToMatchRegex(
            column="email",
            regex=r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$",
        ),
        gxe.ExpectColumnValuesToBeUnique(column="patient_id"),
    ]
    return ExpectationSuite(name="patient_data_suite", expectations=expectations)


def validate_anonymized_data(filepath: str) -> dict:
    """Validate anonymized output and return an assignment-friendly report."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Anonymized dataset not found: {path}")

    df = pd.read_csv(path, dtype={"cccd": str, "so_dien_thoai": str})
    results = {
        "success": True,
        "failed_checks": [],
        "stats": {"total_rows": len(df), "columns": list(df.columns)},
    }

    missing_columns = [col for col in IMPORTANT_COLUMNS if col not in df.columns]
    if missing_columns:
        results["failed_checks"].append(
            f"Missing required columns: {', '.join(missing_columns)}"
        )
    else:
        raw_path = Path(__file__).resolve().parents[2] / "data" / "raw" / "patients_raw.csv"
        if raw_path.exists():
            raw = pd.read_csv(raw_path, dtype={"cccd": str})
            leaked = set(df["cccd"].dropna()) & set(raw["cccd"].dropna())
            if leaked:
                results["failed_checks"].append(
                    f"Found {len(leaked)} original CCCD value(s) in anonymized data"
                )

        null_counts = df[IMPORTANT_COLUMNS].isna().sum()
        columns_with_nulls = null_counts[null_counts > 0].to_dict()
        if columns_with_nulls:
            results["failed_checks"].append(
                f"Null values in important columns: {columns_with_nulls}"
            )

        invalid_cccd = ~df["cccd"].str.fullmatch(r"\d{12}", na=False)
        if invalid_cccd.any():
            results["failed_checks"].append(
                f"Invalid anonymized CCCD format in {int(invalid_cccd.sum())} row(s)"
            )

        if raw_path.exists() and len(df) != len(raw):
            results["failed_checks"].append(
                f"Row count mismatch: anonymized={len(df)}, original={len(raw)}"
            )

    results["success"] = not results["failed_checks"]
    results["stats"]["failed_check_count"] = len(results["failed_checks"])
    return results
