from typing import List

from ..models.common import RiskAssessment, RiskAssessmentList
from ..utils.pii_mapping_util import (
    map_pii_type,
    calculate_average_risk_score,
)


class BasePIIRanker:
    def assess_pii_token(self, detected_pii_type: str) -> RiskAssessment:
        return map_pii_type(detected_pii_type)

    def rank_pii_tokens(self, detected_pii_types: List[str]) -> RiskAssessmentList:
        ranked_pii: RiskAssessment = []

        for pii_type in detected_pii_types:
            ranked_pii.append(map_pii_type(pii_type))

        return RiskAssessmentList(
            risk_assessments=ranked_pii,
            average_risk_score=calculate_average_risk_score(ranked_pii),
        )


class AmazonPIIRanker(BasePIIRanker):
    def assess_pii_token(self, detected_pii_type: str) -> RiskAssessment:
        return map_pii_type(detected_pii_type)

    def rank_pii_tokens(self, detected_pii_types: List[str]) -> RiskAssessmentList:
        ranked_pii: RiskAssessment = []

        for pii_type in detected_pii_types:
            ranked_pii.append(map_pii_type(pii_type))

        return RiskAssessmentList(
            risk_assessments=ranked_pii,
            average_risk_score=calculate_average_risk_score(ranked_pii),
        )


class AzurePIIRanker(BasePIIRanker):
    def assess_pii_token(self, detected_pii_type: str) -> RiskAssessment:
        return map_pii_type(detected_pii_type)

    def rank_pii_tokens(self, detected_pii_types: List[str]) -> RiskAssessmentList:
        ranked_pii: RiskAssessment = []

        for pii_type in detected_pii_types:
            ranked_pii.append(map_pii_type(pii_type))

        return RiskAssessmentList(
            risk_assessments=ranked_pii,
            average_risk_score=calculate_average_risk_score(ranked_pii),
        )
