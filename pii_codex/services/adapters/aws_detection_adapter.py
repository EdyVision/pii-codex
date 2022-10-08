from typing import List

from pii_codex.models.analysis import DetectionResultItem, DetectionResult
from pii_codex.services.adapters.detection_adapter_base import BasePIIDetectionAdapter
from pii_codex.utils.pii_mapping_util import (
    convert_aws_comprehend_pii_to_common_pii_type,
)


class AWSComprehendPIIDetectionAdapter(BasePIIDetectionAdapter):
    def convert_analyzed_item(self, pii_detection: dict) -> List[DetectionResultItem]:
        """
        Converts an AWS Comprehend detect_pii() result into a collection of DetectionResultItem

        @param pii_detection: dict from AWS Comprehend detect_pii {
            'Entities': [
                {
                    'Score': ...,
                    'Type': 'BANK_ACCOUNT_NUMBER'|'BANK_ROUTING'|'CREDIT_DEBIT_NUMBER'|'CREDIT_DEBIT_CVV'|
                    'CREDIT_DEBIT_EXPIRY'|'PIN'|'EMAIL'|'ADDRESS'|'NAME'|'PHONE'|'SSN'|'DATE_TIME'|'PASSPORT_NUMBER'|
                    'DRIVER_ID'|'URL'|'AGE'|'USERNAME'|'PASSWORD'|'AWS_ACCESS_KEY'|'AWS_SECRET_KEY'|'IP_ADDRESS'|
                    'MAC_ADDRESS'|'ALL'|'LICENSE_PLATE'|'VEHICLE_IDENTIFICATION_NUMBER'|'UK_NATIONAL_INSURANCE_NUMBER'|
                    'CA_SOCIAL_INSURANCE_NUMBER'|'US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER'|
                    'UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER'|'IN_PERMANENT_ACCOUNT_NUMBER'|'IN_NREGA'|
                    'INTERNATIONAL_BANK_ACCOUNT_NUMBER'|'SWIFT_CODE'|'UK_NATIONAL_HEALTH_SERVICE_NUMBER'|
                    'CA_HEALTH_NUMBER'|'IN_AADHAAR'|'IN_VOTER_NUMBER',
                    'BeginOffset': 123,
                    'EndOffset': 123
                },
            ]
        }
        @return: List[DetectionResultItem]
        """

        return [
            DetectionResultItem(
                entity_type=convert_aws_comprehend_pii_to_common_pii_type(
                    result["Type"]
                ).name,
                score=result["Score"],
                start=result["BeginOffset"],
                end=result["EndOffset"],
            )
            for result in pii_detection["Entities"]
        ]

    def convert_analyzed_collection(
        self, pii_detections: List[dict]
    ) -> List[DetectionResult]:
        """
        Converts a collection of AWS Comprehend detect_pii() results to a collection of DetectionResult.

        @param pii_detections: List[dict] of response from AWS Comprehend detect_pii - [{
            'Entities': [
                {
                    'Score': ...,
                    'Type': 'BANK_ACCOUNT_NUMBER'|'BANK_ROUTING'|'CREDIT_DEBIT_NUMBER'|'CREDIT_DEBIT_CVV'|
                    'CREDIT_DEBIT_EXPIRY'|'PIN'|'EMAIL'|'ADDRESS'|'NAME'|'PHONE'|'SSN'|'DATE_TIME'|'PASSPORT_NUMBER'|
                    'DRIVER_ID'|'URL'|'AGE'|'USERNAME'|'PASSWORD'|'AWS_ACCESS_KEY'|'AWS_SECRET_KEY'|'IP_ADDRESS'|
                    'MAC_ADDRESS'|'ALL'|'LICENSE_PLATE'|'VEHICLE_IDENTIFICATION_NUMBER'|'UK_NATIONAL_INSURANCE_NUMBER'|
                    'CA_SOCIAL_INSURANCE_NUMBER'|'US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER'|
                    'UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER'|'IN_PERMANENT_ACCOUNT_NUMBER'|'IN_NREGA'|
                    'INTERNATIONAL_BANK_ACCOUNT_NUMBER'|'SWIFT_CODE'|'UK_NATIONAL_HEALTH_SERVICE_NUMBER'|
                    'CA_HEALTH_NUMBER'|'IN_AADHAAR'|'IN_VOTER_NUMBER',
                    'BeginOffset': 123,
                    'EndOffset': 123
                },
            ]
        }]

        """

        detection_results: List[DetectionResultItem] = []
        for i, detection in enumerate(pii_detections):
            # Return results in formatted Analysis Result List object
            detection_results.append(
                DetectionResult(
                    index=i,
                    detections=self.convert_analyzed_item(pii_detection=detection),
                )
            )

        return detection_results
