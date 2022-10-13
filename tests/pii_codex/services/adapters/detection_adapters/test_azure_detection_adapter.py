from assertpy import assert_that

from pii_codex.models.analysis import DetectionResultItem
from pii_codex.models.azure_pii import AzurePIIType
from pii_codex.services.adapters.detection_adapters.azure_detection_adapter import (
    AzurePIIDetectionAdapter,
)


def test_azure_analysis_single_item_conversion():
    # with pytest.raises(Exception) as ex_info:
    conversion_results = AzurePIIDetectionAdapter().convert_analyzed_item(
        pii_detection={
            "entities": [
                {
                    "text": "My email is example@example.eu.edu",
                    "category": AzurePIIType.EMAIL_ADDRESS.value,
                    "subcategory": None,
                    "length": 22,
                    "offset": 11,
                    "confidence_score": 0.8,
                }
            ]
        }
    )

    assert_that(conversion_results).is_not_none()
    assert_that(isinstance(conversion_results[0], DetectionResultItem)).is_true()


def test_azure_analysis_collection_conversion():
    conversion_results = AzurePIIDetectionAdapter().convert_analyzed_collection(
        pii_detections=[
            {
                "entities": [
                    {
                        "text": "My email is example@example.eu.edu",
                        "category": AzurePIIType.EMAIL_ADDRESS.value,
                        "subcategory": None,
                        "length": 22,
                        "offset": 11,
                        "confidence_score": 0.8,
                    }
                ]
            },
            {
                "entities": [
                    {
                        "text": "My email is example1@example.eu.edu",
                        "category": AzurePIIType.EMAIL_ADDRESS.value,
                        "subcategory": None,
                        "length": 23,
                        "offset": 11,
                        "confidence_score": 0.8,
                    }
                ]
            },
        ]
    )

    assert_that(conversion_results).is_not_empty()
    assert_that(conversion_results[1].index).is_greater_than(
        conversion_results[0].index
    )
    assert_that(
        isinstance(conversion_results[0].detections[0], DetectionResultItem)
    ).is_true()
