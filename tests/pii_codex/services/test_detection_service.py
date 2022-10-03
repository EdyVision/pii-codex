from typing import List

import pytest
from assertpy import assert_that

from pii_codex.models.aws_pii import AWSComprehendPIIType
from pii_codex.models.azure_pii import AzurePIIType
from pii_codex.models.analysis import DetectionResultItem, DetectionResult
from pii_codex.models.microsoft_presidio_pii import (
    MSFTPresidioPIIType,
)
from pii_codex.services.pii_detection import (
    AzurePIIDetectionAdapter,
    AWSComprehendPIIDetectionAdapter,
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
def test_msft_presidio_analysis_single_item(test_input, pii_types, expected_result):
    presidio_results: List[
        DetectionResultItem
    ] = PresidioPIIDetectionService().analyze_item(
        text=test_input,
        entities=pii_types,
    )

    if expected_result:
        assert_that(presidio_results).is_not_empty()
        assert_that(isinstance(presidio_results[0], DetectionResultItem)).is_true()
    else:
        assert_that(presidio_results).is_empty()


def test_msft_presidio_analysis_collection():
    presidio_analyzer = PresidioPIIDetectionService()

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


def test_azure_analysis_single_item_conversion():
    # with pytest.raises(Exception) as ex_info:
    conversion_results = AzurePIIDetectionAdapter().convert_analyzed_item(
        pii_detection={
            "entities": [
                {
                    "text": "My email is example@example.eu.edu",
                    "category": AzurePIIType.EMAIL_ADDRESS.value,
                    "subcategory": None,
                    "length": 22,
                    "offset": 11,
                    "confidence_score": 0.8,
                }
            ]
        }
    )

    assert_that(conversion_results).is_not_none()
    assert_that(isinstance(conversion_results[0], DetectionResultItem)).is_true()


def test_azure_analysis_collection_conversion():
    conversion_results = AzurePIIDetectionAdapter().convert_analyzed_collection(
        pii_detections=[
            {
                "entities": [
                    {
                        "text": "My email is example@example.eu.edu",
                        "category": AzurePIIType.EMAIL_ADDRESS.value,
                        "subcategory": None,
                        "length": 22,
                        "offset": 11,
                        "confidence_score": 0.8,
                    }
                ]
            },
            {
                "entities": [
                    {
                        "text": "My email is example1@example.eu.edu",
                        "category": AzurePIIType.EMAIL_ADDRESS.value,
                        "subcategory": None,
                        "length": 23,
                        "offset": 11,
                        "confidence_score": 0.8,
                    }
                ]
            },
        ]
    )

    assert_that(conversion_results).is_not_empty()
    assert_that(conversion_results[1].index).is_greater_than(
        conversion_results[0].index
    )
    assert_that(
        isinstance(conversion_results[0].detections[0], DetectionResultItem)
    ).is_true()


@pytest.mark.parametrize(
    "expected_result,expected_pii",
    [
        (False, []),
        (False, []),
        (True, [AWSComprehendPIIType.EMAIL_ADDRESS]),
        (
            True,
            [AWSComprehendPIIType.EMAIL_ADDRESS],
        ),
        (
            True,
            [AWSComprehendPIIType.PHONE_NUMBER],
        ),
        (
            True,
            [AWSComprehendPIIType.EMAIL_ADDRESS, AWSComprehendPIIType.PHONE_NUMBER],
        ),
        (
            True,
            [AWSComprehendPIIType.EMAIL_ADDRESS, AWSComprehendPIIType.PHONE_NUMBER],
        ),
    ],
)
def test_aws_comprehend_analysis_single_item_conversion(expected_result, expected_pii):

    conversion_results: List[
        DetectionResultItem
    ] = AWSComprehendPIIDetectionAdapter().convert_analyzed_item(
        pii_detection={
            "Entities": [
                {
                    "Score": 0.99,
                    "Type": pii_type.value,
                    "BeginOffset": 123,
                    "EndOffset": 456,
                }
                for pii_type in expected_pii
            ]
        },
    )

    if expected_result:
        assert_that(conversion_results).is_not_empty()
        assert_that(isinstance(conversion_results[0], DetectionResultItem)).is_true()
    else:
        assert_that(conversion_results).is_empty()


def test_aws_comprehend_analysis_collection_conversion():

    conversion_results: List[
        DetectionResult
    ] = AWSComprehendPIIDetectionAdapter().convert_analyzed_collection(
        pii_detections=[
            {
                "Entities": [
                    {
                        "Score": 0.99,
                        "Type": AWSComprehendPIIType.EMAIL_ADDRESS.value,
                        "BeginOffset": 123,
                        "EndOffset": 456,
                    }
                ]
            },
            {
                "Entities": [
                    {
                        "Score": 0.73,
                        "Type": AWSComprehendPIIType.PHONE_NUMBER.value,
                        "BeginOffset": 456,
                        "EndOffset": 789,
                    }
                ]
            },
        ]
    )

    assert_that(conversion_results).is_not_empty()
    assert_that(conversion_results[1].index).is_greater_than(
        conversion_results[0].index
    )
    assert_that(
        isinstance(conversion_results[0].detections[0], DetectionResultItem)
    ).is_true()
