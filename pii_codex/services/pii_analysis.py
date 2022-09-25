from typing import List

from pii_codex.models.common import (
    AnalysisProviderType,
    AnalysisResultList,
    AnalysisResult,
    DetectionResultList,
    ScoredAnalysisResultList,
    BatchAnalysisResultList,
    BatchAnalysisResult,
    ScoredBatchAnalysisResultList,
    ScoredBatchAnalysisResult,
    RiskLevel,
)
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.services.pii_detection import (
    PresidioPIIDetectionService,
    AWSComprehendPIIDetectionService,
    AzurePIIDetectionService,
)
from pii_codex.services.pii_assessment import PII_ASSESSMENT_SERVICE


class PIIAnalysisService:
    def run_analysis(
        self, analysis_provider: str, text: str, language_code: str = "en"
    ) -> AnalysisResultList:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param analysis_provider: AnalysisProviderType str
        @param text: input text to analyze
        @param language_code: string "en" is default value
        @return: AnalysisResultList
        """

        return AnalysisResultList(
            analyses=self._perform_analysis(
                analysis_provider=analysis_provider,
                text=text,
                language_code=language_code,
            )
        )

    def run_batch_analysis(
        self, analysis_provider: str, texts: List[str], language_code: str = "en"
    ) -> BatchAnalysisResultList:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param analysis_provider: AnalysisProviderType str
        @param texts: List[str] - input texts to analyze
        @param language_code: string "en" is default value
        @return: AnalysisResultList
        """

        batch: List[BatchAnalysisResult] = []
        for i, text in enumerate(texts):
            batch.append(
                BatchAnalysisResult(
                    index=i,
                    analyses=self._perform_analysis(
                        analysis_provider=analysis_provider,
                        text=text,
                        language_code=language_code,
                    ),
                )
            )

        return BatchAnalysisResultList(batched_analyses=batch)

    def run_analysis_and_score(
        self, analysis_provider: str, text: str, language_code: str = "en"
    ) -> ScoredAnalysisResultList:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param analysis_provider: AnalysisProviderType str
        @param text: input text to analyze
        @param language_code: "en" is default value
        @return: ScoredAnalysisResultList
        """

        analyses = self._perform_analysis(
            analysis_provider=analysis_provider, text=text, language_code=language_code
        )

        return ScoredAnalysisResultList(
            analyses=analyses,
            average_risk_score=PII_ASSESSMENT_SERVICE.calculate_analysis_score_average(
                analyses
            ),
        )

    def run_batch_analysis_and_score(
        self, analysis_provider: str, texts: List[str], language_code: str = "en"
    ) -> ScoredBatchAnalysisResultList:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param analysis_provider: str - AnalysisProviderType name
        @param texts: List[str] - input texts to analyze
        @param language_code: str - "en" is default value
        @return: AnalysisResultList
        """

        batch: List[BatchAnalysisResult] = []
        for i, text in enumerate(texts):
            analyses = self._perform_analysis(
                analysis_provider=analysis_provider,
                text=text,
                language_code=language_code,
            )
            batch.append(
                ScoredBatchAnalysisResult(
                    index=i,
                    analyses=analyses,
                    average_risk_score=PII_ASSESSMENT_SERVICE.calculate_analysis_score_average(
                        analyses
                    )
                    if analyses
                    else float(RiskLevel.LEVEL_ONE.value),
                )
            )

        return ScoredBatchAnalysisResultList(
            batched_analyses=batch,
            average_risk_score=PII_ASSESSMENT_SERVICE.calculate_batch_score_average(
                batch
            ),
        )

    @staticmethod
    def _perform_analysis(
        analysis_provider: str, text: str, language_code: str = "en"
    ) -> List[AnalysisResult]:
        """
        Transforms detections into AnalysisResult objects

        @param analysis_provider: AnalysisProviderType str
        @param text: input text to analyze
        @param language_code: "en" is default value
        @return: List[AnalysisResult]
        """

        if analysis_provider.upper() == AnalysisProviderType.AZURE.name:
            detections: DetectionResultList = AzurePIIDetectionService().analyze_text(
                text=text,
                language_code=language_code,
            )
        elif analysis_provider.upper() == AnalysisProviderType.PRESIDIO.name:
            detections: DetectionResultList = (
                PresidioPIIDetectionService().analyze_text(
                    entities=[pii_type.name for pii_type in MSFTPresidioPIIType],
                    text=text,
                    language_code=language_code,
                )
            )
        elif analysis_provider.upper() == AnalysisProviderType.AWS.name:
            detections: DetectionResultList = (
                AWSComprehendPIIDetectionService().analyze_text(
                    text=text, language_code=language_code
                )
            )
        else:
            raise Exception(
                "Unsupported operation. Available operations are: ",
                [analyzer.value for analyzer in AnalysisProviderType],
            )

        return [
            AnalysisResult(
                detection=detection,
                risk_assessment=PII_ASSESSMENT_SERVICE.assess_pii_type(
                    detected_pii_type=detection.entity_type.upper()
                ),
            )
            for detection in detections.detection_results
        ]


PII_ANALYSIS_SERVICE = PIIAnalysisService()
