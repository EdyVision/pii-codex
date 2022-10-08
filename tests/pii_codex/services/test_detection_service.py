from typing import List

import pytest
from assertpy import assert_that
from pii_codex.models.analysis import DetectionResultItem, DetectionResult
from pii_codex.models.microsoft_presidio_pii import (
    MSFTPresidioPIIType,
)
from pii_codex.services.analyzers.presidio_analysis import (
    PresidioPIIAnalyzer,
)


@pytest.mark.parametrize(
    "test_input,pii_types,expected_result",
    [
        ("Not", [MSFTPresidioPIIType.PHONE_NUMBER.value], False),
        ("PII", [MSFTPresidioPIIType.EMAIL_ADDRESS.value], False),
        ("example@example.com", [MSFTPresidioPIIType.EMAIL_ADDRESS.value], True),
        (
            "My email is example@example.eu.edu",
            [MSFTPresidioPIIType.EMAIL_ADDRESS.value],
            True,
        ),
        (
            "My phone number is 191-212-456-7890",
            [MSFTPresidioPIIType.PHONE_NUMBER.value],
            False,
        ),  # International number not working
        (
            "My phone number is 305-555-5555",
            [MSFTPresidioPIIType.PHONE_NUMBER.value],
            True,
        ),
        (
            "My phone number is 305-555-5555 and email is example@example.com",
            [
                MSFTPresidioPIIType.PHONE_NUMBER.value,
                MSFTPresidioPIIType.EMAIL_ADDRESS.value,
            ],
            True,
        ),
    ],
)
def test_msft_presidio_analysis_single_item(test_input, pii_types, expected_result):
    presidio_results: List[DetectionResultItem] = PresidioPIIAnalyzer().analyze_item(
        text=test_input,
        entities=pii_types,
    )

    if expected_result:
        assert_that(presidio_results).is_not_empty()
        assert_that(isinstance(presidio_results[0], DetectionResultItem)).is_true()
    else:
        assert_that(presidio_results).is_empty()


def test_msft_presidio_analysis_collection():
    presidio_analyzer = PresidioPIIAnalyzer()

    presidio_results: List[DetectionResult] = presidio_analyzer.analyze_collection(
        texts=[
            "My email is example@example.eu.edu",
            "My phone number is 305-555-5555 and email is example@example.com",
        ],
        entities=presidio_analyzer.get_supported_entities(language_code="en"),
        language_code="en",
    )

    assert_that(presidio_results).is_not_empty()
    assert_that(presidio_results[1].index).is_greater_than(presidio_results[0].index)
    assert_that(
        isinstance(presidio_results[0].detections[0], DetectionResultItem)
    ).is_true()
