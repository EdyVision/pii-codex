from unittest import mock

import pytest
from assertpy import assert_that

from pii_codex.clients.aws_comprehend import AWSComprehend
from pii_codex.models.common import DetectionResultList, PIIType
from pii_codex.models.microsoft_presidio_pii import (
    MSFTPresidioPIIType,
)
from pii_codex.services.pii_detection import (
    AzurePIIDetectionService,
    AWSComprehendPIIDetectionService,
    PresidioPIIDetectionService,
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
def test_msft_presidio_analysis(test_input, pii_types, expected_result):
    presidio_results: DetectionResultList = PresidioPIIDetectionService().analyze_text(
        text=test_input,
        entities=pii_types,
    )

    if expected_result:
        assert_that(presidio_results.detection_results).is_not_empty()
    else:
        assert_that(presidio_results.detection_results).is_empty()


def test_azure_analysis():
    with pytest.raises(Exception) as ex_info:
        AzurePIIDetectionService().analyze_text(
            text="test_input",
            entities=None,
        )

    assert_that(str(ex_info.value)).is_not_none()
    assert_that(str(ex_info.value)).is_equal_to("Not implemented yet")


@pytest.mark.parametrize(
    "test_input,expected_result,expected_pii",
    [
        ("Not", False, []),
        ("PII", False, []),
        ("example@example.com", True, [PIIType.EMAIL_ADDRESS]),
        ("My email is example@example.eu.edu", True, [PIIType.EMAIL_ADDRESS]),
        ("My phone number is 191-212-456-7890", True, [PIIType.PHONE_NUMBER]),
        (
            "My phone number is 305-555-5555",
            True,
            [PIIType.EMAIL_ADDRESS, PIIType.PHONE_NUMBER],
        ),
        (
            "My phone number is 305-555-5555 and email is example@example.com",
            True,
            [PIIType.EMAIL_ADDRESS, PIIType.PHONE_NUMBER],
        ),
    ],
)
def test_aws_comprehend_analysis(test_input, expected_result, expected_pii):
    AWSComprehend.detect_pii = mock.MagicMock(
        return_value={
            "Entities": [
                {
                    "Score": 0.99,
                    "Type": pii_type.name,
                    "BeginOffset": 123,
                    "EndOffset": 123,
                }
                for pii_type in expected_pii
            ]
        }
        if expected_pii
        else {"Entities": []}
    )
    presidio_results: DetectionResultList = (
        AWSComprehendPIIDetectionService().analyze_text(
            text=test_input,
        )
    )

    if expected_result:
        assert_that(presidio_results.detection_results).is_not_empty()
    else:
        assert_that(presidio_results.detection_results).is_empty()
