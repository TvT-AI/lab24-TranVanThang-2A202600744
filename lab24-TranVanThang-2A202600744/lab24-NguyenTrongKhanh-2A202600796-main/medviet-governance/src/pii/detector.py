"""Vietnamese PII recognizers used by the MedViet anonymization pipeline."""

from functools import lru_cache

import spacy
from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider, SpacyNlpEngine
from presidio_analyzer.predefined_recognizers import EmailRecognizer


def _build_nlp_engine():
    """Use the Vietnamese NER model when available, otherwise a blank tokenizer.

    ``vi_core_news_lg`` is not distributed with every spaCy installation.  Pattern
    recognizers still work with a blank Vietnamese pipeline, which makes local and
    CI execution deterministic while retaining NER support on configured systems.
    """
    if spacy.util.is_package("vi_core_news_lg"):
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [
                    {"lang_code": "vi", "model_name": "vi_core_news_lg"}
                ],
            }
        )
        return provider.create_engine()

    engine = SpacyNlpEngine(models=[])
    # The English tokenizer is language-agnostic enough for our pattern-based
    # recognizers and avoids making the optional ``pyvi`` package mandatory.
    engine.nlp = {"vi": spacy.blank("en")}
    return engine


@lru_cache(maxsize=1)
def build_vietnamese_analyzer() -> AnalyzerEngine:
    """Build a Presidio analyzer with recognizers tailored to Vietnamese data."""
    cccd_recognizer = PatternRecognizer(
        supported_entity="VN_CCCD",
        supported_language="vi",
        patterns=[
            Pattern(
                name="cccd_pattern",
                regex=r"(?<!\d)\d{12}(?!\d)",
                score=0.9,
            )
        ],
        context=["cccd", "căn cước", "chứng minh", "cmnd"],
    )

    phone_recognizer = PatternRecognizer(
        supported_entity="VN_PHONE",
        supported_language="vi",
        patterns=[
            Pattern(
                name="vn_phone",
                regex=r"(?<!\d)0[35789]\d{8}(?!\d)",
                score=0.85,
            )
        ],
        context=["điện thoại", "sđt", "sdt", "phone", "liên hệ"],
    )

    # The pattern fallback recognizes Vietnamese/Faker names even when the optional
    # NER model is unavailable. It intentionally requires at least two name parts.
    person_recognizer = PatternRecognizer(
        supported_entity="PERSON",
        supported_language="vi",
        patterns=[
            Pattern(
                name="vietnamese_person_name",
                regex=r"(?<![\w@])[^\W\d_]+(?:[ '-][^\W\d_]+){1,7}(?![\w@])",
                score=0.65,
            )
        ],
        context=["bệnh nhân", "họ tên", "bác sĩ", "ông", "bà"],
    )

    analyzer = AnalyzerEngine(
        nlp_engine=_build_nlp_engine(), supported_languages=["vi"]
    )
    analyzer.registry.add_recognizer(cccd_recognizer)
    analyzer.registry.add_recognizer(phone_recognizer)
    analyzer.registry.add_recognizer(person_recognizer)
    analyzer.registry.add_recognizer(EmailRecognizer(supported_language="vi"))
    return analyzer


def detect_pii(text: str, analyzer: AnalyzerEngine) -> list:
    """Detect the PII entities required by this lab in Vietnamese text."""
    if text is None:
        return []
    return analyzer.analyze(
        text=str(text),
        language="vi",
        entities=["PERSON", "EMAIL_ADDRESS", "VN_CCCD", "VN_PHONE"],
    )
