# pylint: disable=broad-except,unused-argument
import logging
from typing import List
from presidio_analyzer import AnalyzerEngine

from ..models.analysis import DetectionResult
from ..clients.aws_comprehend import AWSComprehend


class BasePIIDetectionService:
    def analyze_item(
        self, text: str, language_code: str = "en", entities: List[str] = None
    ) -> List[DetectionResult]:
        """
        Analyzes a string given the text and language code.

        @param language_code: str "en" is default
        @param text: str
        @param entities:
        @return: List[DetectionResult]
        """
        raise Exception("Not implemented yet")

    def analyze_collection(
        self, texts: List[str], language_code: str = "en", entities: List[str] = None
    ) -> List[DetectionResult]:
        """
        Uses Microsoft Presidio (spaCy module) to analyze given a set of entities to analyze the provided text against.
        Will log an error if the identifier or entity recognizer is not added to Presidio's base recognizers or
        a custom recognizer created.

        @param language_code: str "en" is default
        @param texts: List[str]
        @param entities:
        @return: List[DetectionResult]
        """
        raise Exception("Not implemented yet")


class AzurePIIDetectionService(BasePIIDetectionService):
    def analyze_item(
        self, text: str, language_code: str = "en", entities: List[str] = None
    ):
        """
        Analyzes a string using Azure given the text and language.

        @param language_code: str "en" is default
        @param text: str
        @param entities: Ignored for Azure
        @return: List[DetectionResult]
        """
        super().analyze_item(text, language_code=language_code, entities=entities)

    def analyze_collection(
        self, texts: List[str], language_code: str = "en", entities: List[str] = None
    ) -> List[DetectionResult]:
        """
        Analyzes a string using Azuregiven the text and language.

        @param language_code: str "en" is default
        @param texts: List[str]
        @param entities: Ignored for Azure
        @return: List[DetectionResult]
        """
        super().analyze_collection(
            texts=texts, language_code=language_code, entities=entities
        )


class AWSComprehendPIIDetectionService(BasePIIDetectionService):
    def analyze_item(
        self, text: str, language_code: str = "en", entities: List[str] = None
    ) -> List[DetectionResult]:
        """
        Analyzes a string using AWS Comprehend given the text and language.

        @param language_code: str "en" is default
        @param text: str
        @param entities: Ignored for AWS Comprehend
        @return: List[DetectionResult]
        """

        try:
            detections = AWSComprehend().detect_pii(
                text=text, language_code=language_code
            )

        except Exception as ex:
            logging.error(ex.with_traceback())
            return None

        # Return analyzer results in formatted Analysis Result List object
        return [
            DetectionResult(
                entity_type=result["Type"],
                score=result["Score"],
                start=result["BeginOffset"],
                end=result["EndOffset"],
            )
            for result in detections["Entities"]
        ]


class PresidioPIIDetectionService(BasePIIDetectionService):

    analyzer = AnalyzerEngine()

    def get_supported_entities(self, language_code="en") -> List[str]:
        """
        Retrieves a list of supported entities, this will narrow down what is available for a given langauge

        :param language_code: str - defaults to "en"
        :return:
        """
        return self.analyzer.get_supported_entities(language=language_code)

    def analyze_item(
        self, text: str, language_code: str = "en", entities: List[str] = None
    ) -> List[DetectionResult]:
        """
        Uses Microsoft Presidio (spaCy module) to analyze given a set of entities to analyze the provided text against.
        Will log an error if the identifier or entity recognizer is not added to Presidio's base recognizers or
        a custom recognizer created.

        @param language_code: str "en" is default
        @param entities: str - List[MSFTPresidioPIIType.name]
        @param text: str
        @return: List[DetectionResult]
        """

        detections = []
        try:
            # Engine Setup - spaCy model setup and PII recognizers
            detections = self.analyzer.analyze(
                text=text, entities=entities, language=language_code
            )

        except Exception as ex:
            logging.error(ex.with_traceback())

        # Return analyzer results in formatted Analysis Result List object
        return [
            DetectionResult(
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
        @param entities: str - List[MSFTPresidioPIIType.name]
        @param texts: List[str]
        @return: List[DetectionResult]
        """

        analysis = []
        try:
            # Engine Setup - spaCy model setup and PII recognizers
            for text in texts:
                text_analysis = self.analyzer.analyze(
                    text=text, entities=entities, language=language_code
                )
                analysis.extend(text_analysis)

            # Return analyzer results in formatted Analysis Result List object

        except Exception as ex:
            logging.error(ex.with_traceback())

        return [
            DetectionResult(
                entity_type=result.entity_type,
                score=result.score,
                start=result.start,
                end=result.end,
            )
            for result in analysis
        ]
