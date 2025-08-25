from assertpy import assert_that
from pii_codex.models.common import PIIType
from pii_codex.models.analysis import RiskAssessment
from pii_codex.services.assessment_service import PIIAssessmentService
from pii_codex.utils.statistics_util import get_mean


class TestPIIAssessmentService:
    pii_assessment_service = PIIAssessmentService()

    def test_assess_pii_type(self):
        risk_assessment: RiskAssessment = self.pii_assessment_service.assess_pii_type(
            detected_pii_type=PIIType.US_SOCIAL_SECURITY_NUMBER.name
        )
        assert_that(risk_assessment.risk_level).is_equal_to(3)
        assert_that(risk_assessment.pii_type_detected).is_equal_to(
            PIIType.US_SOCIAL_SECURITY_NUMBER.name
        )

    def test_assess_pii_type_list(self):
        # PII types with same ratings
        risk_assessment_list = self.pii_assessment_service.assess_pii_type_list(
            detected_pii_types=[
                PIIType.US_SOCIAL_SECURITY_NUMBER.name,
                PIIType.PHONE_NUMBER.name,
            ]
        )
        assert_that(isinstance(risk_assessment_list[0], RiskAssessment))
        assert_that(
            get_mean([assessment.risk_level for assessment in risk_assessment_list])
        ).is_equal_to(3.0)

        # PII types with different ratings
        risk_assessment_list = self.pii_assessment_service.assess_pii_type_list(
            detected_pii_types=[
                PIIType.US_SOCIAL_SECURITY_NUMBER.name,
                PIIType.RACE.name,
            ]
        )
        assert_that(isinstance(risk_assessment_list[0], RiskAssessment))
        assert_that(
            get_mean([assessment.risk_level for assessment in risk_assessment_list])
        ).is_equal_to(2.5)
