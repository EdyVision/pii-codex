from typing import List

from pii_codex.config import PII_MAPPER
from pii_codex.models.analysis import DetectionResultItem, DetectionResult
from pii_codex.services.adapters.detection_adapters.detection_adapter_base import (
    BasePIIDetectionAdapter,
)


class PresidioPIIDetectionAdapter(BasePIIDetectionAdapter):

    """
    Intended for those that are using their own pre-detected result set from Presidio
    """

    def convert_analyzed_item(self, pii_detection) -> List[DetectionResultItem]:
        """
        Converts a single Presidio analysis attempt into a collection of DetectionResultItem objects. One string
        analysis by Presidio returns an array of RecognizerResult objects.

        @param pii_detection: RecognizerResult from presidio analyzer
        @return: List[DetectionResultItem]
        """

        return [
            DetectionResultItem(
                entity_type=PII_MAPPER.convert_msft_presidio_pii_to_common_pii_type(
                    result.entity_type
                ).name,
                score=result.score,
                start=result.start,
                end=result.end,
            )
            for result in pii_detection
        ]

    def convert_analyzed_collection(self, pii_detections) -> List[DetectionResult]:
        """
        Converts a collection of Presidio analysis results to a collection of DetectionResult. A collection of Presidio
        analysis results ends up being a 2D array.

        @param pii_detections: List[List[RecognizerResult]] - list of individual analyses from Presidio

        """

        detection_results: List[DetectionResult] = []
        for i, detection in enumerate(pii_detections):
            # Return results in formatted Analysis Result List object
            detection_results.append(
                DetectionResult(
                    index=i,
                    detections=self.convert_analyzed_item(pii_detection=detection),
                )
            )

        return detection_results
