from typing import List

import pytest
from assertpy import assert_that

from pii_codex.models.analysis import DetectionResultItem, DetectionResult
from pii_codex.models.aws_pii import AWSComprehendPIIType
from pii_codex.services.adapters.detection_adapters.aws_detection_adapter import (
    AWSComprehendPIIDetectionAdapter,
)


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
