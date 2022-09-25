from typing import List

import numpy as np

from ..models.common import RiskAssessment, AnalysisResult, ScoredBatchAnalysisResult
from ..utils.pii_mapping_util import map_pii_type


class PIIAssessmentService:
    @staticmethod
    def assess_pii_type(detected_pii_type: str) -> RiskAssessment:
        """
        Assesses a singular detected PII type given a type name string from commmon.PIIType enum
        @param detected_pii_type: type name strings from commmon.PIIType enum
        @return: RiskAssessment
        """
        return map_pii_type(detected_pii_type)

    @staticmethod
    def assess_pii_type_list(detected_pii_types: List[str]) -> List[RiskAssessment]:
        """
        Assesses a list of detected PII types given an array of type name strings from commmon.PIIType enum
        @param detected_pii_types: array type name strings from commmon.PIIType
        enum (e.g. ["PHONE_NUMBER", "US_SOCIAL_SECURITY_NUMBER"])
        @return: List[RiskAssessment]
        """
        ranked_pii: RiskAssessment = []

        for pii_type in detected_pii_types:
            ranked_pii.append(map_pii_type(pii_type))

        return ranked_pii

    @staticmethod
    def assess_and_score_pii_type_list(
        detected_pii_types: List[str],
    ) -> List[RiskAssessment]:
        """
        Assesses a list of detected PII types given an array of type name strings from commmon.PIIType enum
        @param detected_pii_types: array type name strings from commmon.PIIType
        enum (e.g. ["PHONE_NUMBER", "US_SOCIAL_SECURITY_NUMBER"])
        @return: List[RiskAssessment]
        """
        ranked_pii: RiskAssessment = []

        for pii_type in detected_pii_types:
            ranked_pii.append(map_pii_type(pii_type))

        return ranked_pii

    @staticmethod
    def calculate_risk_assessment_score_average(
        risk_assessments: List[RiskAssessment],
    ) -> float:
        """
        Returns the average risk score per token
        @param risk_assessments:
        @return: float
        """
        return np.mean([assessment.risk_level for assessment in risk_assessments])

    @staticmethod
    def calculate_analysis_score_average(analyses: List[AnalysisResult]) -> float:
        """
        Returns the average risk score per token assessment in AnalysisResult list
        @param analyses: List[AnalysisResult]
        @return: float
        """
        return np.mean([analysis.risk_assessment.risk_level for analysis in analyses])

    @staticmethod
    def calculate_batch_score_average(
        scored_analyses: List[ScoredBatchAnalysisResult],
    ) -> float:
        """
        Returns the average risk score for batch analysis assessments with individual score averages

        @param scored_analyses: List[ScoredBatchAnalysisResult]
        @return: float
        """
        return np.mean([analysis.average_risk_score for analysis in scored_analyses])


PII_ASSESSMENT_SERVICE = PIIAssessmentService()
