import json

import pandas as pd
import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from src.api.main import app
from src.encryption.vault import SimpleVault
from src.quality.validation import build_patient_expectation_suite
from scripts.security_scan import find_secrets


@pytest.fixture
def client():
    return TestClient(app)


def auth(token):
    return {"Authorization": f"Bearer {token}"}


class TestRBACAPI:
    def test_missing_token_is_unauthorized(self, client):
        assert client.get("/api/patients/raw").status_code == 401

    def test_only_admin_reads_raw_data(self, client):
        assert client.get(
            "/api/patients/raw", headers=auth("token-bob")
        ).status_code == 403
        response = client.get(
            "/api/patients/raw", headers=auth("token-alice")
        )
        assert response.status_code == 200
        assert len(response.json()) == 10

    def test_role_specific_resources(self, client):
        assert client.get(
            "/api/patients/anonymized", headers=auth("token-bob")
        ).status_code == 200
        assert client.get(
            "/api/metrics/aggregated", headers=auth("token-carol")
        ).status_code == 200
        assert client.get(
            "/api/metrics/aggregated", headers=auth("token-dave")
        ).status_code == 403

    def test_ml_engineer_cannot_delete(self, client):
        response = client.delete(
            "/api/patients/abc123", headers=auth("token-bob")
        )
        assert response.status_code == 403


class TestEncryption:
    def test_envelope_encryption_round_trip(self, tmp_path):
        vault = SimpleVault(str(tmp_path / "vault.key"))
        original = "Nguyễn Văn A - CCCD: 012345678901"
        payload = vault.encrypt_data(original)

        assert payload["algorithm"] == "AES-256-GCM"
        assert original not in json.dumps(payload)
        assert vault.decrypt_data(payload) == original

    def test_tampering_is_detected(self, tmp_path):
        vault = SimpleVault(str(tmp_path / "vault.key"))
        payload = vault.encrypt_data("sensitive")
        payload["ciphertext"] = payload["ciphertext"][:-2] + "AA"
        with pytest.raises((InvalidTag, ValueError)):
            vault.decrypt_data(payload)

    def test_encrypt_column_preserves_input(self, tmp_path):
        vault = SimpleVault(str(tmp_path / "vault.key"))
        original = pd.DataFrame({"cccd": ["012345678901"]})
        encrypted = vault.encrypt_column(original, "cccd")

        assert original.loc[0, "cccd"] == "012345678901"
        assert encrypted.loc[0, "cccd"] != original.loc[0, "cccd"]


def test_quality_suite_has_all_six_expectations():
    suite = build_patient_expectation_suite()
    assert len(suite.expectations) == 6


def test_secret_scanner_detects_fake_aws_credential():
    # Split the fixture so a repository-level scanner does not flag its own test.
    fake_credential = "AWS_ACCESS_KEY_ID='AKIA" + "IOSFODNN7EXAMPLE'"
    assert "AWS access key" in find_secrets(fake_credential)
