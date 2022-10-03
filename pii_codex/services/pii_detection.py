# pylint: disable=broad-except,unused-argument
import logging
from typing import List
from presidio_analyzer import AnalyzerEngine

from ..models.analysis import DetectionResultItem, DetectionResult
from ..utils.pii_mapping_util import (
    convert_aws_comprehend_pii_to_common_pii_type,
    convert_azure_pii_to_common_pii_type,
)


class BasePIIDetectionAdapter:
    def convert_analyzed_item(self, pii_detection: dict) -> List[DetectionResultItem]:
        """
        Converts a detection result into a collection of DetectionResultItem

        @param pii_detection: dict
        @return: List[DetectionResultItem]
        """
        raise Exception("Not implemented yet")

    def convert_analyzed_collection(
        self, pii_detections: List[dict]
    ) -> List[DetectionResult]:
        """
        Converts a collection of detection results to a collection of DetectionResult.

        @param pii_detections: List[dict]
        @return: List[DetectionResult]
        """
        raise Exception("Not implemented yet")


class AzurePIIDetectionAdapter(BasePIIDetectionAdapter):
    def convert_analyzed_item(self, pii_detection: dict):
        """
        Converts a detection result into a collection of DetectionResultItem

        @param pii_detection: dict
        @return: List[DetectionResultItem]
        """
        return [
            DetectionResultItem(
                entity_type=convert_azure_pii_to_common_pii_type(entity["category"]),
                score=entity["confidence_score"],
                start=entity["offset"],
                end=entity["offset"] + entity["length"],
            )
            for entity in pii_detection["entities"]
        ]

    def convert_analyzed_collection(
        self, pii_detections: List[dict]
    ) -> List[DetectionResultItem]:
        """
        Converts a collection of detection results to a collection of DetectionResult.

        @param pii_detections: List[dict]
        @return: List[DetectionResultItem]
        """
        # super().convert_analyzed_collection(pii_detections=pii_detections)
        detection_results: List[DetectionResultItem] = []
        for i, result in enumerate(pii_detections):
            # Return results in formatted Analysis Result List object
            detections = []
            for entity in result["entities"]:
                detections.append(
                    DetectionResultItem(
                        entity_type=convert_azure_pii_to_common_pii_type(
                            entity["category"]
                        ).name,
                        score=entity["confidence_score"],
                        start=entity["offset"],
                        end=entity["offset"] + entity["length"],
                    )
                )

            detection_results.append(DetectionResult(index=i, detections=detections))

        return detection_results


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

        # Return results in formatted Analysis Result List object
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
        for i, result in enumerate(pii_detections):
            # Return results in formatted Analysis Result List object
            detections = []
            for entity in result["Entities"]:
                detections.append(
                    DetectionResultItem(
                        entity_type=convert_aws_comprehend_pii_to_common_pii_type(
                            entity["Type"]
                        ).name,
                        score=entity["Score"],
                        start=entity["BeginOffset"],
                        end=entity["EndOffset"],
                    )
                )

            detection_results.append(DetectionResult(index=i, detections=detections))

        return detection_results


class PresidioPIIDetectionService:

    analyzer = AnalyzerEngine()

    def get_supported_entities(self, language_code="en") -> List[str]:
        """
        Retrieves a list of supported entities, this will narrow down what is available for a given language

        :param language_code: str - defaults to "en"
        :return: List[str]
        """
        return self.analyzer.get_supported_entities(language=language_code)

    def analyze_item(
        self, text: str, language_code: str = "en", entities: List[str] = None
    ) -> List[DetectionResultItem]:
        """
        Uses Microsoft Presidio (spaCy module) to analyze given a set of entities to analyze the provided text against.
        Will log an error if the identifier or entity recognizer is not added to Presidio's base recognizers or
        a custom recognizer created.

        @param language_code: str "en" is default
        @param entities: str - List[MSFTPresidioPIIType.name]
        @param text: str
        @return: List[DetectionResultItem]
        """

        detections = []

        if not entities:
            entities = self.get_supported_entities(language_code)

        try:
            # Engine Setup - spaCy model setup and PII recognizers
            detections = self.analyzer.analyze(
                text=text, entities=entities, language=language_code
            )

        except Exception as ex:
            logging.error(ex.with_traceback())

        # Return analyzer results in formatted Analysis Result List object
        return [
            DetectionResultItem(
                entity_type=result.entity_type,
                score=result.score,
                start=result.start,
                end=result.end,
            )
            for result in detections
        ]

    def analyze_collection(
        self, texts: List[str], language_code: str = "en", entities: List[str] = None
    ) -> List[DetectionResult]:
        """
        Uses Microsoft Presidio (spaCy module) to analyze given a set of entities to analyze the provided text against.
        Will log an error if the identifier or entity recognizer is not added to Presidio's base recognizers or
        a custom recognizer created.

        @param language_code: str "en" is default
        @param entities: List[MSFTPresidioPIIType.name] defaults to all possible entities for selected language
        @param texts: List[str]
        @return: List[DetectionResult]
        """

        detection_results = []
        try:
            if not entities:
                entities = self.get_supported_entities(language_code)

            # Engine Setup - spaCy model setup and PII recognizers
            for i, text in enumerate(texts):
                text_analysis = self.analyzer.analyze(
                    text=text, entities=entities, language=language_code
                )

                # Every analysis by the analyzer will have a set of detections within
                detections = [
                    DetectionResultItem(
                        entity_type=result.entity_type,  # Have Presidio type converted to common type???
                        score=result.score,
                        start=result.start,
                        end=result.end,
                    )
                    for result in text_analysis
                ]
                detection_results.append(
                    DetectionResult(index=i, detections=detections)
                )

            # Return analyzer results in formatted Analysis Result List object

        except Exception as ex:
            logging.error(ex.with_traceback())

        return detection_results
