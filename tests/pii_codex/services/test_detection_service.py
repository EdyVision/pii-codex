import pytest
from assertpy import assert_that

from pii_codex.models.microsoft_presidio_pii import (
    MSFTPresidioPIIType,
    AnalysisResultList,
)
from pii_codex.services.detection_service import PIIDetectionService


detection_service = PIIDetectionService()


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
def test_msft_presidio_analysis(test_input, pii_types, expected_result):
    presidio_results: AnalysisResultList = detection_service.analyze_with_msft_presidio(
        text=test_input,
        entities=pii_types,
    )

    if expected_result:
        assert_that(presidio_results.analysis_results).is_not_empty()
    else:
        assert_that(presidio_results.analysis_results).is_empty()
