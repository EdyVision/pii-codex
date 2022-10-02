from typing import List

from pii_codex.models.common import (
    AnalysisProviderType,
    RiskLevel,
)
from pii_codex.models.analysis import (
    DetectionResult,
    AnalysisResultItem,
    AnalysisResult,
    AnalysisResultSet,
)
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.services.pii_detection import (
    PresidioPIIDetectionService,
    AWSComprehendPIIDetectionService,
    AzurePIIDetectionService,
)
from pii_codex.services.pii_assessment import PII_ASSESSMENT_SERVICE
from pii_codex.utils.statistics_util import (
    get_population_standard_deviation,
    get_mean,
    get_standard_deviation, get_variance,
)


class PIIAnalysisService:
    def analyze_item(
        self, analysis_provider: str, text: str, language_code: str = "en"
    ) -> AnalysisResult:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param analysis_provider: AnalysisProviderType str
        @param text: input text to analyze
        @param language_code: "en" is default value
        @return: AnalysisResult
        """

        analysis = self._perform_analysis(
            analysis_provider=analysis_provider, text=text, language_code=language_code
        )

        return AnalysisResult(
            index=0,
            analysis=analysis,
            mean_risk_score=get_mean(
                [item.risk_assessment.risk_level for item in analysis]
            ),
        )

    def analyze_collection(
        self,
        analysis_provider: str,
        texts: List[str],
        language_code: str = "en",
        collection_name: str = None,
        collection_type: str = "population",
    ) -> AnalysisResultSet:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param analysis_provider: str - AnalysisProviderType name
        @param texts: List[str] - input texts to analyze
        @param language_code: str - "en" is default value
        @param collection_name: str - name of population or collection
        @param collection_type: str - population or sample
        @return: AnalysisResultList
        """

        analysis_set: List[AnalysisResult] = []
        for i, text in enumerate(texts):
            analysis = self._perform_analysis(
                analysis_provider=analysis_provider,
                text=text,
                language_code=language_code,
            )
            analysis_set.append(
                AnalysisResult(
                    index=i,
                    analysis=analysis,
                    mean_risk_score=get_mean(
                        [analysis.risk_assessment.risk_level for analysis in analysis]
                    )
                    if analysis
                    else float(RiskLevel.LEVEL_ONE.value),
                )
            )

        (
            detected_types,
            detected_type_frequencies,
        ) = PII_ASSESSMENT_SERVICE.get_detected_pii_types(analysis_set)

        collection_mean_risk_scores = [
            analysis.mean_risk_score for analysis in analysis_set
        ]

        return AnalysisResultSet(
            collection_name=collection_name,
            analyses=analysis_set,
            mean_risk_score=get_mean(collection_mean_risk_scores),
            risk_scores=collection_mean_risk_scores,
            risk_score_standard_deviation=get_standard_deviation(
                collection_mean_risk_scores, collection_type
            ),
            risk_score_variance=get_variance(
                collection_mean_risk_scores, collection_type
            ),
            detection_count=PII_ASSESSMENT_SERVICE.get_detected_pii_count(analysis_set),
            detected_pii_type_frequencies=detected_type_frequencies,
            detected_pii_types=detected_types,
        )

    @staticmethod
    def _perform_analysis(
        analysis_provider: str, text: str, language_code: str = "en"
    ) -> List[AnalysisResultItem]:
        """
        Transforms detections into AnalysisResult objects

        @param analysis_provider: AnalysisProviderType str
        @param text: input text to analyze
        @param language_code: "en" is default value
        @return: List[AnalysisResult]
        """

        if analysis_provider.upper() == AnalysisProviderType.AZURE.name:
            detections: List[DetectionResult] = AzurePIIDetectionService().analyze_item(
                text=text,
                language_code=language_code,
            )
        elif analysis_provider.upper() == AnalysisProviderType.PRESIDIO.name:
            detections: List[
                DetectionResult
            ] = PresidioPIIDetectionService().analyze_item(
                entities=[pii_type.name for pii_type in MSFTPresidioPIIType],
                text=text,
                language_code=language_code,
            )
        elif analysis_provider.upper() == AnalysisProviderType.AWS.name:
            detections: List[
                DetectionResult
            ] = AWSComprehendPIIDetectionService().analyze_item(
                text=text, language_code=language_code
            )
        else:
            raise Exception(
                "Unsupported operation. Available operations are: ",
                [analyzer.value for analyzer in AnalysisProviderType],
            )

        return [
            AnalysisResultItem(
                detection=detection,
                risk_assessment=PII_ASSESSMENT_SERVICE.assess_pii_type(
                    detected_pii_type=detection.entity_type.upper()
                ),
            )
            for detection in detections
        ]


PII_ANALYSIS_SERVICE = PIIAnalysisService()
