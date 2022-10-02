import pytest
from assertpy import assert_that
from pii_codex.models.common import (
    AnalysisProviderType,
)
from pii_codex.models.analysis import (
    AnalysisResultItem,
    AnalysisResult,
    AnalysisResultSet,
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
        assert_that(results.mean_risk_score).is_greater_than(2.5)

    @pytest.mark.parametrize(
        "bulk_input",
        [
            (
                [
                    "Not",
                    "example@example.com",
                    "My phone number is 555-555-5555",
                    "Oh his work phone number is 777-777-7777",
                    "My phone number is 305-555-5555 and email is example@example.com",
                ]
            )
        ],
    )
    def test_collection_analysis(self, bulk_input):
        results = PII_ANALYSIS_SERVICE.analyze_collection(
            analysis_provider=AnalysisProviderType.PRESIDIO.name,
            texts=bulk_input,
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
        assert_that(results.mean_risk_score).is_greater_than(1)
        assert_that(results.detection_count).is_equal_to(
            7
        )  # Emails double as domain detections
        assert_that(
            results.detected_pii_type_frequencies.most_common(1)[0][0]
        ).is_equal_to("PHONE_NUMBER")
        assert_that(results.risk_score_standard_deviation).is_greater_than(0.5)
