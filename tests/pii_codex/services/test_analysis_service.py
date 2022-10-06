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
from pii_codex.services.pii_analysis import PII_ANALYSIS_SERVICE


class TestPIIAnalysisService:
    def test_analyze_pii_type_with_score(self):
        results = PII_ANALYSIS_SERVICE.analyze_item(
            analysis_provider=AnalysisProviderType.PRESIDIO.name,
            text="Here is my contact information: Phone number 555-555-5555 and my email is example123@email.com",
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, AnalysisResult)).is_true()
        assert_that(len(results.analysis)).is_equal_to(
            3
        )  # It counts email as a URL since it contains domain
        assert_that(results.risk_score_mean).is_greater_than(2.5)

    def test_collection_analysis(self):
        results = PII_ANALYSIS_SERVICE.analyze_collection(
            analysis_provider=AnalysisProviderType.PRESIDIO.name,
            texts=[
                "Not",
                "example@example.com",
                "My phone number is 555-555-5555",
                "Oh his work phone number is 777-777-7777",
                "My phone number is 305-555-5555 and email is example@example.com",
            ],
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, AnalysisResultSet)).is_true()
        assert_that(len(results.analyses)).is_equal_to(5)
        assert_that(
            isinstance(results.analyses[1].analysis[0], AnalysisResultItem)
        ).is_true()
        assert_that(results.analyses[1].index).is_greater_than(
            results.analyses[0].index
        )
        assert_that(results.risk_score_mean).is_greater_than(1)
        assert_that(results.detection_count).is_equal_to(
            7
        )  # Emails double as domain detections
        assert_that(
            results.detected_pii_type_frequencies.most_common(1)[0][0]
        ).is_equal_to("PHONE_NUMBER")
        assert_that(results.risk_score_standard_deviation).is_greater_than(0.5)
        assert_that(results.detection_count).is_greater_than(3)
        assert_that(results.risk_score_variance).is_greater_than(0.5)

    @pytest.mark.parametrize(
        "analysis_provider",
        [AnalysisProviderType.AZURE.name, AnalysisProviderType.AWS.name],
    )
    def test_collection_analysis_with_invalid_provider(self, analysis_provider):
        # Built in analysis providers are open source. This module supports the conversion of AWS and Azure
        # detections to DetectionResults to be later used by the analysis module, but AWS and Azure
        # clients are not integrated with this module.

        with pytest.raises(Exception) as execinfo:
            PII_ANALYSIS_SERVICE.analyze_collection(
                analysis_provider=analysis_provider,
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
            PII_ANALYSIS_SERVICE.analyze_detection_collection(
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
