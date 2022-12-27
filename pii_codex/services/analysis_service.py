# pylint: disable=too-many-arguments
from typing import List, Optional, Tuple
import pandas as pd

from ..config import PII_MAPPER, DEFAULT_ANALYSIS_MODE, DEFAULT_TOKEN_REPLACEMENT_VALUE
from ..models.common import (
    AnalysisProviderType,
    RiskLevel,
)
from ..models.analysis import (
    DetectionResultItem,
    AnalysisResultItem,
    AnalysisResult,
    AnalysisResultSet,
    DetectionResult,
    RiskAssessment,
)
from ..models.microsoft_presidio_pii import MSFTPresidioPIIType
from ..services.analyzers.presidio_analysis import (
    PresidioPIIAnalyzer,
)
from ..services.assessment_service import PIIAssessmentService
from ..utils.statistics_util import (
    get_mean,
    get_standard_deviation,
    get_variance,
    get_mode,
    get_median,
)

from ..utils.logging import timed_operation


class PIIAnalysisService:
    def __init__(
        self,
        pii_token_replacement_value: str = DEFAULT_TOKEN_REPLACEMENT_VALUE,
        analysis_provider: str = AnalysisProviderType.PRESIDIO.name,
    ):
        self._analysis_provider = analysis_provider
        self._language_code = "en"
        self._pii_assessment_service = PIIAssessmentService()
        self._analyzer = (
            PresidioPIIAnalyzer(pii_token_replacement_value=pii_token_replacement_value)
            if analysis_provider == AnalysisProviderType.PRESIDIO.name
            else None
        )

    @timed_operation
    def analyze_item(
        self,
        text: str,
        metadata: dict = None,
        language_code: str = "en",
    ) -> AnalysisResult:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param text: input text to analyze
        @param language_code: "en" is default value
        @param metadata: dict - {
                                    "location": True
                                }
        @return: AnalysisResult
        """

        analysis, sanitized_text = self._perform_text_analysis(
            text=text, language_code=language_code
        )

        if metadata is not None:
            # Retrieve analyses for metadata entries
            analysis.extend(self.analyze_metadata(metadata=metadata))

        return AnalysisResult(
            index=0,
            analysis=analysis,
            sanitized_text=sanitized_text,
            risk_score_mean=get_mean(
                [item.risk_assessment.risk_level for item in analysis]
            ),
        )

    @timed_operation
    def analyze_collection(
        self,
        texts: Optional[List[str]] = None,
        data: Optional[pd.DataFrame] = None,
        language_code: str = "en",
        collection_name: str = "",
        collection_type: str = "population",
    ) -> AnalysisResultSet:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param texts: List[str] - input texts to analyze
        @param data: dataframe - dataframe of text and metadata where text is a string and metadata is a dict
        @param language_code: str - "en" is default value
        @param collection_name: str - name of population or collection
        @param collection_type: str - population or sample
        @return: AnalysisResultList
        """

        # Will raise exceptions or invalid input
        self._validate_data(texts, data)
        self._language_code = language_code

        analysis_set: List[AnalysisResult] = []

        if data is not None:
            data = data.reset_index()

            analysis_set = [
                self._analyze_data_collection_row(idx, collection_entry)
                for idx, collection_entry in data.iterrows()
            ]

        if texts:

            analysis_set = [
                self._analyze_text_collection_item(idx, collection_entry)
                for idx, collection_entry in enumerate(texts)
            ]

        return self._build_analysis_result_set(
            collection_name=collection_name,
            collection_type=collection_type,
            analysis_set=analysis_set,
        )

    def _analyze_data_collection_row(self, idx, collection_row):
        """
        Parallelized task to process dataframe
        @param idx:
        @param collection_row:
        @return:
        """
        analysis, sanitized_text = self._perform_text_analysis(
            language_code=self._language_code,
            text=collection_row["text"],
        )

        if collection_row["metadata"] is not None:
            # Perform analyses for metadata entries
            analysis.extend(self.analyze_metadata(metadata=collection_row["metadata"]))

        return self._format_result_set_item(
            analysis_items=analysis, sanitized_text=sanitized_text, index=idx
        )

    def _analyze_text_collection_item(self, idx, text):
        """
        Parallelized task to text array
        @param idx:
        @param text:
        @return:
        """

        analysis, sanitized_text = self._perform_text_analysis(
            language_code=self._language_code,
            text=text,
        )

        return self._format_result_set_item(
            analysis_items=analysis,
            sanitized_text=sanitized_text,
            index=idx,
        )

    @timed_operation
    def analyze_detection_collection(
        self,
        detection_collection: List[DetectionResult],
        collection_name: str = "",
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

        return self._build_analysis_result_set(
            collection_name=collection_name,
            collection_type=collection_type,
            analysis_set=analysis_set,
        )

    @timed_operation
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
            risk_score_mean=get_mean(
                [analysis.risk_assessment.risk_level for analysis in detection_analyses]
            ),
        )

    @timed_operation
    def analyze_detection_result_item(
        self,
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
            risk_assessment=self._pii_assessment_service.assess_pii_type(
                detected_pii_type=detection_result_item.entity_type.upper()
            ),
        )

    def _perform_text_analysis(
        self, text: str, language_code: str = "en"
    ) -> Tuple[List[AnalysisResultItem], str]:
        """
        Transforms detections into AnalysisResult objects

        @param text: input text to analyze
        @param language_code: "en" is default value
        @return: Tuple[List[AnalysisResult], str]
        """

        if self._analysis_provider.upper() == AnalysisProviderType.PRESIDIO.name:
            detections, sanitized_text = self._analyzer.analyze_item(  # type: ignore
                entities=[pii_type.value for pii_type in MSFTPresidioPIIType],
                text=text,
                language_code=language_code,
            )
        elif (
            self._analysis_provider.upper() == AnalysisProviderType.AZURE.name
            or self._analysis_provider.upper() == AnalysisProviderType.AWS.name
        ):
            raise Exception(
                "Unsupported operation. Use detection converters followed by analyze_detection_result()."
            )
        else:
            raise Exception(
                "Unsupported operation. Only the Presidio analyzer is supported at this time."
            )

        return (
            [
                AnalysisResultItem(
                    detection=detection,
                    risk_assessment=self._pii_assessment_service.assess_pii_type(
                        detected_pii_type=detection.entity_type.upper()
                    ),
                )
                for detection in detections
            ]
            if detections
            else [AnalysisResultItem(detection=None, risk_assessment=RiskAssessment())]
        ), sanitized_text

    @timed_operation
    def analyze_metadata(self, metadata: dict):
        """
        Create an analysis result item per metadata entry

        @param metadata:
        @return:
        """
        analysis_result_items: List[AnalysisResultItem] = []
        for key, value in metadata.items():
            if value is True:
                metadata_pii_mapping = (
                    PII_MAPPER.convert_metadata_type_to_common_pii_type(key)
                )
                if metadata_pii_mapping:
                    # Run analyses on supported metadata types only
                    detection = DetectionResultItem(
                        entity_type=metadata_pii_mapping.name
                    )
                    analysis_result_items.append(
                        AnalysisResultItem(
                            detection=detection,
                            risk_assessment=self._pii_assessment_service.assess_pii_type(
                                detected_pii_type=detection.entity_type.upper()
                            ),
                        )
                    )

        return analysis_result_items

    @staticmethod
    def summarize_analysis_result_items(
        analyses: List[AnalysisResultItem], index=0
    ) -> AnalysisResult:
        """
        Summarize analysis result items into a singular AnalysisResult object

        @param analyses:
        @param index:
        @return:
        """
        return AnalysisResult(
            index=index,
            analysis=analyses,
            risk_score_mean=get_mean(
                [analysis.risk_assessment.risk_level for analysis in analyses]
            ),
        )

    def _build_analysis_result_set(
        self,
        analysis_set: List[AnalysisResult],
        collection_name: str = "",
        collection_type: str = DEFAULT_ANALYSIS_MODE,
    ):
        (
            detected_types,
            detected_type_frequencies,
        ) = self._pii_assessment_service.get_detected_pii_types(analysis_set)

        collection_risk_score_means = [
            analysis.risk_score_mean for analysis in analysis_set
        ]

        return AnalysisResultSet(
            collection_name=collection_name,
            analyses=analysis_set,
            risk_score_mean=get_mean(collection_risk_score_means),
            risk_scores=collection_risk_score_means,
            risk_score_standard_deviation=get_standard_deviation(
                collection_risk_score_means, collection_type
            ),
            risk_score_variance=get_variance(
                collection_risk_score_means, collection_type
            ),
            risk_score_mode=get_mode(collection_risk_score_means),
            risk_score_median=get_median(collection_risk_score_means),
            detection_count=self._pii_assessment_service.get_detected_pii_count(
                analysis_set
            ),
            detected_pii_type_frequencies=detected_type_frequencies,
            detected_pii_types=detected_types,
        )

    @staticmethod
    def _format_result_set_item(
        analysis_items: List[AnalysisResultItem],
        sanitized_text: str = "",
        index: int = 0,
    ) -> AnalysisResult:
        """
        Formats the analysis items for a single row in a collection to an AnalysisResult object
        @param analysis_items:
        @param index:
        @return:
        """
        return AnalysisResult(
            index=index,
            analysis=analysis_items,
            sanitized_text=sanitized_text,
            risk_score_mean=get_mean(
                [analysis.risk_assessment.risk_level for analysis in analysis_items]
            )
            if analysis_items
            else float(RiskLevel.LEVEL_ONE.value),
        )

    @staticmethod
    def _validate_data(texts, data):
        """
        Validates text and data types and shapes passed in for collection analyses
        @param texts:
        @param data:
        @return:
        """
        if texts and data is not None:
            raise Exception("Cannot supply both 'texts' and 'data' params.")

        if texts and not isinstance(texts, list):
            raise Exception("'texts' param must be a list of strings.")

        if data is not None and isinstance(data, pd.DataFrame):
            if not "text" in data and not "metadata" in data:
                raise Exception(
                    "Data shape error. 'text' and 'metadata' columns are required."
                )

        if data is not None and not isinstance(data, pd.DataFrame):
            raise Exception("Data param must be a dataframe.")
