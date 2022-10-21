# pylint: disable=too-many-arguments
import multiprocessing
from typing import List, Optional
from multiprocessing import Pool
import pandas as pd

from pii_codex.config import PII_MAPPER, DEFAULT_ANALYSIS_MODE
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
    RiskAssessment,
)
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.services.analyzers.presidio_analysis import (
    PresidioPIIAnalyzer,
)
from pii_codex.services.assessment_service import PIIAssessmentService
from pii_codex.utils.statistics_util import (
    get_mean,
    get_standard_deviation,
    get_variance,
    get_mode,
    get_median,
)

from pii_codex.utils.logging import timed_operation


class PIIAnalysisService:

    pii_assessment_service = PIIAssessmentService()
    _analysis_provider = AnalysisProviderType.PRESIDIO.name  # Default to presidio
    _language_code = "en"  # default to English

    @timed_operation
    def analyze_item(
        self,
        analysis_provider: str,
        text: str,
        metadata: dict = None,
        language_code: str = "en",
    ) -> AnalysisResult:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param analysis_provider: AnalysisProviderType str - only PRESIDIO supported
        @param text: input text to analyze
        @param language_code: "en" is default value
        @param metadata: dict - {
                                    "location": True
                                }
        @return: AnalysisResult
        """

        analysis: List[AnalysisResultItem] = self._perform_text_analysis(
            analysis_provider=analysis_provider, text=text, language_code=language_code
        )

        if metadata is not None:
            # Retrieve analyses for metadata entries
            analysis.extend(self.analyze_metadata(metadata=metadata))

        return AnalysisResult(
            index=0,
            analysis=analysis,
            risk_score_mean=get_mean(
                [item.risk_assessment.risk_level for item in analysis]
            ),
        )

    @timed_operation
    def analyze_collection(
        self,
        texts: Optional[List[str]] = None,
        data: Optional[pd.DataFrame] = None,
        analysis_provider: str = AnalysisProviderType.PRESIDIO.name,
        language_code: str = "en",
        collection_name: str = "",
        collection_type: str = "population",
    ) -> AnalysisResultSet:
        """
        Runs an analysis given an analysis provider, text, and language code. This method defaults
        to all entity types when using presidio analyzer. Will return an AnalysisResultList object.

        @param analysis_provider: str - AnalysisProviderType name
        @param texts: List[str] - input texts to analyze
        @param data: dataframe - dataframe of text and metadata where text is a string and metadata is a dict
        @param language_code: str - "en" is default value
        @param collection_name: str - name of population or collection
        @param collection_type: str - population or sample
        @return: AnalysisResultList
        """

        # Will raise exceptions or invalid input
        self._validate_data(texts, data)
        self._analysis_provider = analysis_provider
        self._language_code = language_code

        analysis_set: List[AnalysisResult] = []
        multiprocessing.cpu_count()

        # Set the pool processes to the CPI count divided by 2 (we don't max out in case other processes are running)
        # Star map used due to need for ordered results
        with Pool(processes=int(multiprocessing.cpu_count() / 2)) as worker_pool:
            if data is not None:
                data = data.reset_index()
                analysis_set = worker_pool.starmap(
                    self._analyze_data_collection, data.iterrows()
                )

            if texts:
                analysis_set = worker_pool.starmap(
                    self._analyze_text_collection, enumerate(texts)
                )

        return self._build_analysis_result_set(
            collection_name=collection_name,
            collection_type=collection_type,
            analysis_set=analysis_set,
        )

    def _analyze_data_collection(self, idx, collection):
        """
        Parallelized task to process dataframe
        @param idx:
        @param collection:
        @return:
        """
        analysis = self._perform_text_analysis(
            analysis_provider=self._analysis_provider,
            language_code=self._language_code,
            text=collection["text"],
        )

        if collection["metadata"] is not None:
            # Perform analyses for metadata entries
            analysis.extend(self.analyze_metadata(metadata=collection["metadata"]))

        return self._format_result_set_item(analysis, idx)

    def _analyze_text_collection(self, idx, text):
        """
        Parallelized task to text array
        @param idx:
        @param text:
        @return:
        """

        return self._format_result_set_item(
            self._perform_text_analysis(
                analysis_provider=self._analysis_provider,
                language_code=self._language_code,
                text=text,
            ),
            idx,
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
            risk_assessment=self.pii_assessment_service.assess_pii_type(
                detected_pii_type=detection_result_item.entity_type.upper()
            ),
        )

    def _perform_text_analysis(
        self, analysis_provider: str, text: str, language_code: str = "en"
    ) -> List[AnalysisResultItem]:
        """
        Transforms detections into AnalysisResult objects

        @param analysis_provider: AnalysisProviderType str
        @param text: input text to analyze
        @param language_code: "en" is default value
        @return: List[AnalysisResult]
        """

        if analysis_provider.upper() == AnalysisProviderType.PRESIDIO.name:
            detections: List[DetectionResultItem] = PresidioPIIAnalyzer().analyze_item(
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

        return (
            [
                AnalysisResultItem(
                    detection=detection,
                    risk_assessment=self.pii_assessment_service.assess_pii_type(
                        detected_pii_type=detection.entity_type.upper()
                    ),
                )
                for detection in detections
            ]
            if detections
            else [AnalysisResultItem(detection=None, risk_assessment=RiskAssessment())]
        )

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
                            risk_assessment=self.pii_assessment_service.assess_pii_type(
                                detected_pii_type=detection.entity_type.upper()
                            ),
                        )
                    )

        return analysis_result_items

    def _build_analysis_result_set(
        self,
        analysis_set: List[AnalysisResult],
        collection_name: str = "",
        collection_type: str = DEFAULT_ANALYSIS_MODE,
    ):
        (
            detected_types,
            detected_type_frequencies,
        ) = self.pii_assessment_service.get_detected_pii_types(analysis_set)

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
            detection_count=self.pii_assessment_service.get_detected_pii_count(
                analysis_set
            ),
            detected_pii_type_frequencies=detected_type_frequencies,
            detected_pii_types=detected_types,
        )

    @staticmethod
    def _format_result_set_item(
        analysis_items: List[AnalysisResultItem], index: int = 0
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
