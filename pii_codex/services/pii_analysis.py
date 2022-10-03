# pylint: disable=too-many-arguments
from typing import List

from pii_codex.models.common import (
    AnalysisProviderType,
    RiskLevel,
)
from pii_codex.models.analysis import (
    DetectionResultItem,
    AnalysisResultItem,
    AnalysisResult,
    AnalysisResultSet,
    DetectionResult,
)
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.services.pii_detection import (
    PresidioPIIDetectionService,
)
from pii_codex.services.pii_assessment import PII_ASSESSMENT_SERVICE
from pii_codex.utils.statistics_util import (
    get_mean,
    get_standard_deviation,
    get_variance,
)


class PIIAnalysisService:
    def analyze_item(
        self, analysis_provider: str, text: str, language_code: str = "en"
    ) -> AnalysisResult:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param analysis_provider: AnalysisProviderType str - only PRESIDIO supported
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

    def analyze_detected_collection(
        self,
        detection_collection: List[DetectionResult],
        collection_name: str = None,
        collection_type: str = "population",
    ) -> AnalysisResultSet:
        """
        Transforms a set of Detection Results to an AnalysisResultSet with RiskAssessments for all detections
        found for every string/document. Each analysis result is provided an index to aid in tracking the
        string/document transformed.

        @param detection_collection: List[DetectionResult] - Set of detection results
        @param collection_name: str - name of collection
        @param collection_type: str - population(default) or sample
        @return: AnalysisResultList
        """

        analysis_set: List[AnalysisResult] = []
        for i, detection_result in enumerate(detection_collection):
            analysis_set.append(
                self.analyze_detection_result(
                    detection_result=detection_result, index=i
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

    def analyze_detection_result(
        self, detection_result: DetectionResult, index: int = 0
    ) -> AnalysisResult:
        """
        Transforms a Detection Result to an AnalysisResult with RiskAssessments for all detections
        found in a string/document.

        @param detection_result:
        @param index: (Optional) the current index of the detection result to transform
        @return: AnalysisResult
        """
        detection_analyses = [
            self.analyze_detection_result_item(detection_result_item=detection)
            for detection in detection_result.detections
        ]
        return AnalysisResult(
            index=index,
            analysis=detection_analyses,
            mean_risk_score=get_mean(
                [analysis.risk_assessment.risk_level for analysis in detection_analyses]
            ),
        )

    @staticmethod
    def analyze_detection_result_item(
        detection_result_item: DetectionResultItem,
    ) -> AnalysisResultItem:
        """
        Transforms a Detection Result Item to an AnalysisResultItem with its associated RiskAssessment for the singular
        detection within a string/document.

        @param detection_result_item:
        @return:  AnalysisResultItem
        """
        return AnalysisResultItem(
            detection=detection_result_item,
            risk_assessment=PII_ASSESSMENT_SERVICE.assess_pii_type(
                detected_pii_type=detection_result_item.entity_type.upper()
            ),
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

        if analysis_provider.upper() == AnalysisProviderType.PRESIDIO.name:
            detections: List[
                DetectionResultItem
            ] = PresidioPIIDetectionService().analyze_item(
                entities=[pii_type.name for pii_type in MSFTPresidioPIIType],
                text=text,
                language_code=language_code,
            )
        elif (
            analysis_provider.upper() == AnalysisProviderType.AZURE.name
            or analysis_provider.upper() == AnalysisProviderType.AWS.name
        ):
            raise Exception(
                "Unsupported operation. Use detection converters followed by analyze_detection_result()."
            )
        else:
            raise Exception(
                "Unsupported operation. Only the Presidio analyzer is supported at this time."
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
