import pytest
from assertpy import assert_that
from pii_codex.models.common import (
    AnalysisProviderType,
    AnalysisResultList,
    ScoredAnalysisResultList,
    BatchAnalysisResultList,
    AnalysisResult,
    ScoredBatchAnalysisResultList,
)
from pii_codex.services.pii_analysis import PII_ANALYSIS_SERVICE


class TestPIIAnalysisService:
    def test_analyze_pii_type(self):
        results = PII_ANALYSIS_SERVICE.run_analysis(
            analysis_provider=AnalysisProviderType.PRESIDIO.name,
            text="Here is my contact information: Phone number 555-555-5555 and my email is example123@email.com",
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, AnalysisResultList)).is_true()
        assert_that(len(results.analyses)).is_equal_to(
            3
        )  # It counts email as a URL since it contains domain

    def test_analyze_pii_type_with_score(self):
        results = PII_ANALYSIS_SERVICE.run_analysis_and_score(
            analysis_provider=AnalysisProviderType.PRESIDIO.name,
            text="Here is my contact information: Phone number 555-555-5555 and my email is example123@email.com",
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, ScoredAnalysisResultList)).is_true()
        assert_that(len(results.analyses)).is_equal_to(
            3
        )  # It counts email as a URL since it contains domain
        assert_that(results.average_risk_score).is_greater_than(2.5)

    @pytest.mark.parametrize(
        "bulk_input",
        [
            (
                [
                    "Not",
                    "example@example.com",
                    "My phone number is 191-212-456-7890",
                    "My phone number is 305-555-5555 and email is example@example.com",
                ]
            )
        ],
    )
    def test_batch_analysis(self, bulk_input):
        results = PII_ANALYSIS_SERVICE.run_batch_analysis(
            analysis_provider=AnalysisProviderType.PRESIDIO.name,
            texts=bulk_input,
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, BatchAnalysisResultList)).is_true()
        assert_that(len(results.batched_analyses)).is_equal_to(4)
        assert_that(
            isinstance(results.batched_analyses[1].analyses[0], AnalysisResult)
        ).is_true()
        assert_that(results.batched_analyses[1].index).is_greater_than(
            results.batched_analyses[0].index
        )

    @pytest.mark.parametrize(
        "bulk_input",
        [
            (
                [
                    "Not",
                    "example@example.com",
                    "My phone number is 555-555-5555",
                    "My phone number is 305-555-5555 and email is example@example.com",
                ]
            )
        ],
    )
    def test_scored_batch_analysis(self, bulk_input):
        results = PII_ANALYSIS_SERVICE.run_batch_analysis_and_score(
            analysis_provider=AnalysisProviderType.PRESIDIO.name,
            texts=bulk_input,
        )

        assert_that(results).is_not_none()
        assert_that(isinstance(results, ScoredBatchAnalysisResultList)).is_true()
        assert_that(len(results.batched_analyses)).is_equal_to(4)
        assert_that(
            isinstance(results.batched_analyses[1].analyses[0], AnalysisResult)
        ).is_true()
        assert_that(results.batched_analyses[1].index).is_greater_than(
            results.batched_analyses[0].index
        )
        assert_that(results.average_risk_score).is_greater_than(1)
