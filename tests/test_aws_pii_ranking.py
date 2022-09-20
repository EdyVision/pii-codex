from pii_codex.models.common import PIIType, RiskLevel, RiskAssessment
from pii_codex.services.ranking_service import AmazonPIIRanker
from assertpy import assert_that


class TestAmazonPIIRanking:
    ranker = None

    def setup(self):
        self.ranker = AmazonPIIRanker()

    def test_aws_pii_rank_single(self):
        risk_assessment: RiskAssessment = self.ranker.assess_pii_token(
            detected_pii_type=PIIType.US_SOCIAL_SECURITY_NUMBER.name
        )
        assert_that(risk_assessment.risk_level).is_equal_to(RiskLevel.LEVEL_THREE)
        assert_that(risk_assessment.pii_type_detected).is_equal_to(
            PIIType.US_SOCIAL_SECURITY_NUMBER.name
        )

    # def test_aws_pii_rank_list(self):
    #     risk_assessment_list = self.ranker.rank_pii_tokens(
    #         detected_pii_types=[PIIType.SSN.name, PIIType.PHONE.name]
    #     )
    #     assert_that(risk_assessment_list.average_rank).is_equal_to(2.5)
