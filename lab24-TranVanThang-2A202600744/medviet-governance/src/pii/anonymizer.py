"""PII anonymization helpers for text and tabular patient data."""

import secrets
import re

import pandas as pd
from faker import Faker
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .detector import build_vietnamese_analyzer, detect_pii

fake = Faker("vi_VN")


def _fake_cccd() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(12))


def _fake_phone() -> str:
    return f"0{secrets.choice('35789')}" + "".join(
        secrets.choice("0123456789") for _ in range(8)
    )


class MedVietAnonymizer:
    def __init__(self):
        self.analyzer = build_vietnamese_analyzer()
        self.anonymizer = AnonymizerEngine()

    def anonymize_text(self, text: str, strategy: str = "replace") -> str:
        """Anonymize detected PII or generalize dates/ages."""
        if pd.isna(text):
            return text

        text = str(text)
        if strategy == "generalize":
            text = re.sub(
                r"\b\d{1,2}/\d{1,2}/(\d{4})\b",
                lambda match: f"{match.group(1)[:3]}0s",
                text,
            )
            return re.sub(
                r"\b(\d{1,3})(\s*tuổi)\b",
                lambda match: f"{int(match.group(1)) // 10 * 10}-"
                f"{int(match.group(1)) // 10 * 10 + 9}{match.group(2)}",
                text,
                flags=re.IGNORECASE,
            )

        results = detect_pii(text, self.analyzer)
        if not results:
            return text

        if strategy == "replace":
            operators = {
                "PERSON": OperatorConfig("replace", {"new_value": fake.name()}),
                "EMAIL_ADDRESS": OperatorConfig(
                    "replace", {"new_value": fake.email()}
                ),
                "VN_CCCD": OperatorConfig("replace", {"new_value": _fake_cccd()}),
                "VN_PHONE": OperatorConfig("replace", {"new_value": _fake_phone()}),
            }
        elif strategy == "mask":
            operators = {
                "DEFAULT": OperatorConfig(
                    "mask",
                    {"masking_char": "*", "chars_to_mask": 100, "from_end": True},
                )
            }
        elif strategy == "hash":
            operators = {
                "DEFAULT": OperatorConfig("hash", {"hash_type": "sha256"})
            }
        else:
            raise ValueError(
                f"Unsupported anonymization strategy: {strategy!r}. "
                "Use 'replace', 'mask', 'hash', or 'generalize'."
            )

        return self.anonymizer.anonymize(
            text=text, analyzer_results=results, operators=operators
        ).text

    def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return a copy with PII replaced and model features unchanged."""
        df_anon = df.copy()

        if "ho_ten" in df_anon:
            df_anon["ho_ten"] = df_anon["ho_ten"].apply(self.anonymize_text)
        if "email" in df_anon:
            df_anon["email"] = [fake.email() for _ in range(len(df_anon))]
        if "dia_chi" in df_anon:
            df_anon["dia_chi"] = [fake.address() for _ in range(len(df_anon))]
        if "cccd" in df_anon:
            df_anon["cccd"] = [_fake_cccd() for _ in range(len(df_anon))]
        if "so_dien_thoai" in df_anon:
            df_anon["so_dien_thoai"] = [
                _fake_phone() for _ in range(len(df_anon))
            ]
        if "bac_si_phu_trach" in df_anon:
            df_anon["bac_si_phu_trach"] = [
                fake.name() for _ in range(len(df_anon))
            ]
        if "ngay_sinh" in df_anon:
            df_anon["ngay_sinh"] = df_anon["ngay_sinh"].apply(
                lambda value: self.anonymize_text(value, strategy="generalize")
            )

        return df_anon

    def calculate_detection_rate(
        self, original_df: pd.DataFrame, pii_columns: list
    ) -> float:
        """Return the fraction of non-null PII cells detected by Presidio."""
        missing = set(pii_columns) - set(original_df.columns)
        if missing:
            raise ValueError(f"Missing PII columns: {sorted(missing)}")

        total = detected = 0
        for col in pii_columns:
            for value in original_df[col]:
                if pd.isna(value):
                    continue
                total += 1
                if detect_pii(str(value), self.analyzer):
                    detected += 1
        return detected / total if total else 0.0
