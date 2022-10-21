from typing import List

from pii_codex.config import PII_MAPPER
from pii_codex.models.analysis import DetectionResultItem, DetectionResult
from pii_codex.services.adapters.detection_adapters.detection_adapter_base import (
    BasePIIDetectionAdapter,
)
from pii_codex.utils.pii_mapping_util import PIIMapper


class AzurePIIDetectionAdapter(BasePIIDetectionAdapter):

    pii_mapper = PIIMapper()

    def convert_analyzed_item(self, pii_detection: dict):
        """
        Converts a detection result into a collection of DetectionResultItem

        @param pii_detection: dict
        @return: List[DetectionResultItem]
        """
        return [
            DetectionResultItem(
                entity_type=PII_MAPPER.convert_azure_pii_to_common_pii_type(
                    entity["category"]
                ).name,
                score=entity["confidence_score"],
                start=entity["offset"],
                end=entity["offset"] + entity["length"],
            )
            for entity in pii_detection["entities"]
        ]

    def convert_analyzed_collection(
        self, pii_detections: List[dict]
    ) -> List[DetectionResult]:
        """
        Converts a collection of detection results to a collection of DetectionResult.

        @param pii_detections: List[dict]
        @return: List[DetectionResultItem]
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
