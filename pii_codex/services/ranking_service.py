from typing import List

import numpy as np

from ..models.common import RiskAssessment, RiskAssessmentList
from ..utils.pii_mapping_util import map_pii_type


class PIIRanker:
    def assess_pii_token(self, detected_pii_type: str) -> RiskAssessment:
        return map_pii_type(detected_pii_type)

    def rank_pii_types(self, detected_pii_types: List[str]) -> RiskAssessmentList:
        ranked_pii: RiskAssessment = []

        for pii_type in detected_pii_types:
            ranked_pii.append(map_pii_type(pii_type))

        return RiskAssessmentList(
            risk_assessments=ranked_pii,
            average_risk_score=self.calculate_risk_assessment_score_average(ranked_pii),
        )

    @staticmethod
    def calculate_risk_assessment_score_average(
        risk_assessments: List[RiskAssessment],
    ) -> int:
        """
        Returns the average risk score per token
        @param risk_assessments:
        @return:
        """
        return np.mean(
            [
                risk_assessment.risk_assessment.risk_level
                for risk_assessment in risk_assessments
            ]
        )


class AmazonPIIRanker(PIIRanker):
    def assess_pii_token(self, detected_pii_type: str) -> RiskAssessment:
        return map_pii_type(detected_pii_type)

    def rank_pii_types(self, detected_pii_types: List[str]) -> RiskAssessmentList:
        ranked_pii: RiskAssessment = []

        for pii_type in detected_pii_types:
            ranked_pii.append(map_pii_type(pii_type))

        return RiskAssessmentList(
            risk_assessments=ranked_pii,
            average_risk_score=super().calculate_risk_assessment_score_average(
                ranked_pii
            ),
        )


class AzurePIIRanker(PIIRanker):
    def assess_pii_token(self, detected_pii_type: str) -> RiskAssessment:
        return map_pii_type(detected_pii_type)

    def rank_pii_types(self, detected_pii_types: List[str]) -> RiskAssessmentList:
        ranked_pii: RiskAssessment = []

        for pii_type in detected_pii_types:
            ranked_pii.append(map_pii_type(pii_type))

        return RiskAssessmentList(
            risk_assessments=ranked_pii,
            average_risk_score=super().calculate_risk_assessment_score_average(
                ranked_pii
            ),
        )
