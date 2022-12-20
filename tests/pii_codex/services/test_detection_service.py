from typing import List

import pytest
from assertpy import assert_that
from presidio_analyzer import RecognizerResult
from pii_codex.config import DEFAULT_LANG
from pii_codex.models.analysis import DetectionResultItem, DetectionResult
from pii_codex.models.microsoft_presidio_pii import (
    MSFTPresidioPIIType,
)
from pii_codex.services.analyzers.presidio_analysis import (
    PresidioPIIAnalyzer,
)


class TestDetectionService:

    presidio_analyzer = PresidioPIIAnalyzer()

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
    def test_msft_presidio_analysis_single_item(
        self, test_input, pii_types, expected_result
    ):
        presidio_results, sanitized_text = self.presidio_analyzer.analyze_item(
            text=test_input,
            entities=pii_types,
        )

        if expected_result:
            assert_that(presidio_results).is_not_empty()
            assert_that(isinstance(presidio_results[0], DetectionResultItem)).is_true()
            assert_that(sanitized_text).is_not_empty()
        else:
            assert_that(presidio_results).is_empty()

    def test_msft_presidio_analysis_collection(self):

        presidio_results = self.presidio_analyzer.analyze_collection(
            texts=[
                "My email is example@example.eu.edu",
                "My phone number is 305-555-5555 and email is example@example.com",
            ],
            entities=self.presidio_analyzer.get_supported_entities(language_code="en"),
            language_code=DEFAULT_LANG,
        )

        assert_that(presidio_results).is_not_empty()
        assert_that(presidio_results[1].index).is_greater_than(
            presidio_results[0].index
        )
        assert_that(
            isinstance(presidio_results[0].detections[0], DetectionResultItem)
        ).is_true()

    def test_presidio_analysis_collection_conversion(self):

        conversion_results: List[
            DetectionResult
        ] = self.presidio_analyzer.convert_analyzed_collection(
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
