from typing import List, Tuple
from collections import Counter
from itertools import chain

from ..models.analysis import RiskAssessment, AnalysisResult
from ..utils.pii_mapping_util import map_pii_type
from ..utils.statistics_util import get_mean, get_sum


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
        return get_mean([assessment.risk_level for assessment in risk_assessments])

    @staticmethod
    def get_detected_pii_count(analyses: List[AnalysisResult]) -> float:
        """
        Returns the count of detected PII for analyses performed on a collection

        @param analyses: List[ScoredAnalysisResult]
        @return: float
        """
        return get_sum(
            [
                len(analysis.analysis)
                for analysis in analyses
                if analysis.get_detected_types()
            ]
        )

    @staticmethod
    def get_detected_pii_types(
        analyses: List[AnalysisResult],
    ) -> Tuple[List[str], Counter]:
        """
        Returns the list of detected PII types and their frequencies for analyses performed on a collection

        @param analyses: List[ScoredAnalysisResult]
        @return: Tuple[List[str], Counter]
        """
        flattened_list_of_detections = list(
            chain.from_iterable(
                [analysis.get_detected_types() for analysis in analyses]
            )
        )

        return list(set(flattened_list_of_detections)), Counter(
            flattened_list_of_detections
        )
