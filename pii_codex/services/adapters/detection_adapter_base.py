from typing import List

from pii_codex.models.analysis import DetectionResultItem, DetectionResult


class BasePIIDetectionAdapter:
    def convert_analyzed_item(self, pii_detection) -> List[DetectionResultItem]:
        """
        Converts a detection result into a collection of DetectionResultItem

        @param pii_detection: dict
        @return: List[DetectionResultItem]
        """
        raise Exception("Not implemented yet")

    def convert_analyzed_collection(self, pii_detections) -> List[DetectionResult]:
        """
        Converts a collection of detection results to a collection of DetectionResult.

        @param pii_detections: List[dict]
        @return: List[DetectionResult]
        """
        raise Exception("Not implemented yet")
