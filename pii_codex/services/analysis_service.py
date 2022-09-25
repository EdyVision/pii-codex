from typing import List

from pii_codex.models.common import (
    AnalysisProviderType,
    AnalysisResultList,
    AnalysisResult,
    DetectionResultList,
)
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.services.detection_service import PII_DETECTION_SERVICE
from pii_codex.services.ranking_service import PIIRanker


class PIIAnalysisService:
    @staticmethod
    def run_analysis(
        analysis_provider: str, text: str, language_code: str = "en"
    ) -> AnalysisResultList:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param analysis_provider: AnalysisProviderType str
        @param text: input text to analyze
        @param language_code: "en" is default value
        @return: AnalysisResultList
        """

        analysis_results: List[AnalysisResult] = []

        if analysis_provider.upper() == AnalysisProviderType.AZURE_ANALYSIS.name:
            raise Exception("Operation not supported in this version")
        elif (
            analysis_provider.upper()
            == AnalysisProviderType.MICROSOFT_PRESIDIO_ANALYSIS.name
        ):
            detections: DetectionResultList = (
                PII_DETECTION_SERVICE.analyze_with_msft_presidio(
                    entities=[pii_type.name for pii_type in MSFTPresidioPIIType],
                    text=text,
                    language_code=language_code,
                )
            )
        elif (
            analysis_provider.upper()
            == AnalysisProviderType.AWS_COMPREHEND_ANALYSIS.name
        ):
            detections: DetectionResultList = (
                PII_DETECTION_SERVICE.analyze_with_aws_comprehend(
                    text=text, language_code=language_code
                )
            )
        else:
            raise Exception(
                "Unsupported operation. Available operations are: ",
                [analyzer.value for analyzer in AnalysisProviderType],
            )

        for detection in detections.detection_results:
            analysis_results.append(
                AnalysisResult(
                    detection=detection,
                    risk_assessment=PIIRanker().assess_pii_token(
                        detected_pii_type=detection.entity_type.upper()
                    ),
                )
            )

        return AnalysisResultList(analysis_results=analysis_results)
