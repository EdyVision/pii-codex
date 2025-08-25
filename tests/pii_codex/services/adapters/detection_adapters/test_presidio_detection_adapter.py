from typing import List

from assertpy import assert_that
from presidio_analyzer import RecognizerResult

from pii_codex.models.analysis import DetectionResultItem, DetectionResult
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.services.adapters.detection_adapters.presidio_detection_adapter import (
    PresidioPIIDetectionAdapter,
)


presidio_adapter = PresidioPIIDetectionAdapter()


def test_presidio_analysis_single_item_conversion():
    conversion_results: List[
        DetectionResultItem
    ] = presidio_adapter.convert_analyzed_item(
        pii_detection=[
            RecognizerResult(
                entity_type=MSFTPresidioPIIType.EMAIL_ADDRESS.value,
                start=123,
                end=456,
                score=0.98,
            ),
            RecognizerResult(
                entity_type=MSFTPresidioPIIType.PHONE_NUMBER.value,
                start=123,
                end=456,
                score=0.73,
            ),
        ]
    )

    assert_that(conversion_results).is_not_empty()
    assert_that(isinstance(conversion_results[0], DetectionResultItem)).is_true()


def test_presidio_analysis_collection_conversion():
    conversion_results: List[
        DetectionResult
    ] = presidio_adapter.convert_analyzed_collection(
        pii_detections=[
            [
                RecognizerResult(
                    entity_type=MSFTPresidioPIIType.EMAIL_ADDRESS.value,
                    start=123,
                    end=456,
                    score=0.98,
                ),
                RecognizerResult(
                    entity_type=MSFTPresidioPIIType.PHONE_NUMBER.value,
                    start=123,
                    end=456,
                    score=0.973,
                ),
            ],
            [
                RecognizerResult(
                    entity_type=MSFTPresidioPIIType.US_SOCIAL_SECURITY_NUMBER.value,
                    start=123,
                    end=456,
                    score=0.98,
                ),
                RecognizerResult(
                    entity_type=MSFTPresidioPIIType.PHONE_NUMBER.value,
                    start=123,
                    end=456,
                    score=0.973,
                ),
            ],
        ]
    )

    assert_that(conversion_results).is_not_empty()
    assert_that(conversion_results[1].index).is_greater_than(
        conversion_results[0].index
    )
    assert_that(
        isinstance(conversion_results[0].detections[0], DetectionResultItem)
    ).is_true()
