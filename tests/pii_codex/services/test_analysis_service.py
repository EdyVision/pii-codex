import pandas as pd
import pytest
from assertpy import assert_that

from pii_codex.models.aws_pii import AWSComprehendPIIType
from pii_codex.models.azure_pii import AzurePIIType
from pii_codex.models.common import (
    AnalysisProviderType,
    PIIType,
)
from pii_codex.models.analysis import (
    AnalysisResultItem,
    AnalysisResult,
    AnalysisResultSet,
    DetectionResult,
    DetectionResultItem,
)
from pii_codex.services.analysis_service import PIIAnalysisService


class TestPIIAnalysisService:
    pii_analysis_service = PIIAnalysisService()

    def test_analyze_item(self):
        results = self.pii_analysis_service.analyze_item(
            text="Here is my contact information: Phone number 555-555-5555 and my email is example123@email.com",
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, AnalysisResult)).is_true()
        assert_that(len(results.analysis)).is_equal_to(
            4
        )  # It counts email as a URL since it contains domain, plus PERSON detection
        assert_that(results.risk_score_mean).is_greater_than(2.5)

    def test_analyze_item_with_metadata(self):
        results = self.pii_analysis_service.analyze_item(
            text="Here is my contact information: Phone number 555-555-5555 and my email is example123@email.com",
            metadata={"location": True},
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, AnalysisResult)).is_true()
        assert_that(len(results.analysis)).is_equal_to(
            5
        )  # It counts email as a URL since it contains domain, plus PERSON detection, plus metadata
        assert_that(results.risk_score_mean).is_equal_to(2.6)

        # Make sure phone and email from above are anonymized
        assert_that(results.sanitized_text).is_equal_to(
            "Here is my contact information: Phone number <REDACTED> and my email is <REDACTED>"
        )

    def test_analyze_item_with_custom_token_replacement(self):
        results = PIIAnalysisService(
            pii_token_replacement_value="<PII_TOKEN>"
        ).analyze_item(
            text="Here is my contact information: Phone number 555-555-5555 and my email is example123@email.com",
            metadata={"location": True},
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, AnalysisResult)).is_true()
        assert_that(len(results.analysis)).is_equal_to(
            5
        )  # It counts email as a URL since it contains domain, plus PERSON detection, plus metadata
        assert_that(results.risk_score_mean).is_equal_to(2.6)

        # Make sure phone and email from above are anonymized
        assert_that(results.sanitized_text).is_equal_to(
            "Here is my contact information: Phone number <PII_TOKEN> and my email is <PII_TOKEN>"
        )

    def test_collection_analysis(self):
        texts_to_analyze = [
            "Hi, my name is Donnie",
            "See you there!",
            "This is cool...",
            "example@example.com",
            "My phone number is 555-555-5555",
            "Oh his work phone number is 777-777-7777",
            "My phone number is 305-555-5555 and email is example@example.com",
        ]
        results = self.pii_analysis_service.analyze_collection(
            texts=texts_to_analyze,
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, AnalysisResultSet)).is_true()
        assert_that(len(results.analyses)).is_equal_to(len(texts_to_analyze))
        assert_that(
            isinstance(results.analyses[1].analysis[0], AnalysisResultItem)
        ).is_true()
        assert_that(results.analyses[1].index).is_greater_than(
            results.analyses[0].index
        )
        assert_that(results.risk_score_mean).is_greater_than(1)
        assert_that(results.detection_count).is_equal_to(
            8
        )  # Emails double as domain detections
        assert_that(
            results.detected_pii_type_frequencies.most_common(1)[0][0]
        ).is_equal_to("PHONE_NUMBER")
        assert_that(results.risk_score_standard_deviation).is_greater_than(0.5)
        assert_that(results.detection_count).is_greater_than(3)
        assert_that(results.risk_score_variance).is_greater_than(0.5)
        assert_that(results.to_dict()).is_not_none()
        assert_that(results.analyses[0].sanitized_text).is_not_empty()

    def test_collection_analysis_with_metadata(self):
        texts_to_analyze = [
            "Hi, my name is Donnie",
            "As a democrat, I promise to uphold....",
            "As a Canadian, I can tell you that....",
            "As a Catholic, I can tell you that....",
            "See you there!",
            "This is cool...",
            "example@example.com",
            "My phone number is 555-555-5555",
            "Oh his work phone number is 777-777-7777",
            "My phone number is 305-555-5555 and email is example@example.com",
        ]

        metadata_to_analyze = [
            {
                "location": True,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            },
            {
                "location": True,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            },
            {
                "location": True,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            },
            {
                "location": True,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            },
            {
                "location": False,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            },
            {
                "location": False,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            },
            {
                "location": True,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            },
            {
                "location": True,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            },
            {
                "location": False,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            },
            {
                "location": True,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            },
        ]

        test_df = pd.DataFrame.from_dict(
            {"text": texts_to_analyze, "metadata": metadata_to_analyze}
        )

        results = self.pii_analysis_service.analyze_collection(
            data=test_df,
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, AnalysisResultSet)).is_true()
        assert_that(len(results.analyses)).is_equal_to(len(texts_to_analyze))
        assert_that(
            isinstance(results.analyses[1].analysis[0], AnalysisResultItem)
        ).is_true()
        assert_that(results.analyses[1].index).is_greater_than(
            results.analyses[0].index
        )
        assert_that(results.risk_score_mean).is_greater_than(1)
        assert_that(results.detection_count).is_greater_than(
            30
        )  # Emails double as domain detections
        assert_that(isinstance(results.detected_pii_types, set)).is_true()
        assert_that(
            results.detected_pii_type_frequencies.most_common(1)[0][0]
        ).is_equal_to("PERSON")
        assert_that(
            results.detected_pii_type_frequencies[
                "NRP"
            ]  # political affiliation, religion, and nationality
        ).is_equal_to(3)
        assert_that(results.risk_score_standard_deviation).is_greater_than(0.12)
        assert_that(results.detection_count).is_greater_than(10)
        assert_that(results.risk_score_variance).is_greater_than(0.02)
        assert_that(results.to_dict()).is_not_none()

    @pytest.mark.parametrize(
        "analysis_provider",
        [AnalysisProviderType.AZURE.name, AnalysisProviderType.AWS.name],
    )
    def test_collection_analysis_with_invalid_provider(self, analysis_provider):
        # Built in analysis providers are open source. This module supports the conversion of AWS and Azure
        # detections to DetectionResults to be later used by the analysis module, but AWS and Azure
        # clients are not integrated with this module.

        pii_analysis_service = PIIAnalysisService(analysis_provider=analysis_provider)
        with pytest.raises(Exception) as execinfo:
            pii_analysis_service.analyze_collection(
                texts=[
                    "Oh his work phone number is 777-777-7777",
                    "My phone number is 305-555-5555 and email is example@example.com",
                ],
            )

        assert_that(execinfo.value.args[0]).is_equal_to(
            "Unsupported operation. Use detection converters followed by analyze_detection_result()."
        )

    @pytest.mark.parametrize(
        "detection_results_list_input",
        [
            (
                [
                    DetectionResult(
                        index=0,
                        detections=[
                            DetectionResultItem(
                                entity_type=PIIType.EMAIL_ADDRESS.name,
                                score=0.99,
                                start=123,
                                end=456,
                            )
                        ],
                    ),
                    DetectionResult(
                        index=1,
                        detections=[
                            DetectionResultItem(
                                entity_type=PIIType.URL.name,
                                score=0.73,
                                start=789,
                                end=1010,
                            )
                        ],
                    ),
                ]
            ),
            (
                [
                    DetectionResult(
                        index=0,
                        detections=[
                            DetectionResultItem(
                                entity_type=AzurePIIType.EMAIL_ADDRESS.name,
                                score=0.99,
                                start=123,
                                end=456,
                            )
                        ],
                    ),
                    DetectionResult(
                        index=1,
                        detections=[
                            DetectionResultItem(
                                entity_type=AzurePIIType.URL.name,
                                score=0.73,
                                start=789,
                                end=1010,
                            )
                        ],
                    ),
                ]
            ),
            (
                [
                    DetectionResult(
                        index=0,
                        detections=[
                            DetectionResultItem(
                                entity_type=AWSComprehendPIIType.EMAIL_ADDRESS.name,
                                score=0.99,
                                start=123,
                                end=456,
                            )
                        ],
                    ),
                    DetectionResult(
                        index=1,
                        detections=[
                            DetectionResultItem(
                                entity_type=AWSComprehendPIIType.URL.name,
                                score=0.73,
                                start=789,
                                end=1010,
                            )
                        ],
                    ),
                ]
            ),
        ],
    )
    def test_analyze_detection_collection(self, detection_results_list_input):
        analysis_result_set: AnalysisResultSet = (
            self.pii_analysis_service.analyze_detection_collection(
                detection_collection=detection_results_list_input,
                collection_name="Test Analysis",
                collection_type="SAMPLE",
            )
        )

        assert_that(analysis_result_set).is_not_none()
        assert_that(len(analysis_result_set.analyses)).is_equal_to(
            len(detection_results_list_input)
        )
        assert_that(
            isinstance(analysis_result_set.analyses[0].analysis[0], AnalysisResultItem)
        ).is_true()
        assert_that(analysis_result_set.risk_score_mean).is_greater_than(1)
        assert_that(analysis_result_set.detection_count).is_equal_to(2)
        assert_that(analysis_result_set.risk_score_variance).is_equal_to(0.5)
        assert_that(analysis_result_set.risk_score_standard_deviation).is_greater_than(
            0.5
        )
        assert_that(
            isinstance(
                PIIType[
                    analysis_result_set.analyses[0].analysis[0].detection.entity_type
                ],
                PIIType,
            )
        ).is_true()

    def test_summarize_analysis_result_items(self):
        result_items = self.pii_analysis_service.analyze_metadata(
            metadata={
                "location": True,
                "url": False,
                "screen_name": True,
                "name": True,
                "user_id": True,
            }
        )

        summarized_result = self.pii_analysis_service.summarize_analysis_result_items(
            analyses=result_items
        )

        assert_that(isinstance(summarized_result, AnalysisResult)).is_true()
