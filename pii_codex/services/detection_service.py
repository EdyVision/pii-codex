# pylint: disable=broad-except
import logging
from typing import List
from presidio_analyzer import AnalyzerEngine

from ..models.common import DetectionResult, DetectionResultList
from ..clients.aws_comprehend import AWS_COMPREHEND


class PIIDetectionService:
    @staticmethod
    def analyze_with_msft_presidio(
        entities: List[str], text: str, language_code: str = "en"
    ) -> DetectionResultList:
        """
        Uses Microsoft Presidio (spaCy module) to analyze given a set of entities to analyze the provided text against.
        Will log an error if the identifier or entity recognizer is not added to Presidio's base recognizers or
        a custom recognizer created.
        :param language_code:
        :param entities:
        :param text:
        :return:
        """

        # Engine Setup - spaCy model setup and PII recognizers
        analyzer = AnalyzerEngine()
        analysis = []

        try:
            analysis = analyzer.analyze(
                text=text, entities=entities, language=language_code
            )
        except Exception as ex:
            logging.error(ex.with_traceback())

        # Return analyzer results in formatted Analysis Result List object
        return DetectionResultList(
            detection_results=[
                DetectionResult(
                    entity_type=result.entity_type,
                    score=result.score,
                    start=result.start,
                    end=result.end,
                )
                for result in analysis
            ]
        )

    @staticmethod
    def analyze_with_aws_comprehend(
        text: str, language_code: str = "en"
    ) -> DetectionResultList:
        """
        Uses AWS Comprehend to analyze given the text and language.

        :param language_code:
        :param text:
        :return:
        """

        try:
            analysis = AWS_COMPREHEND.detect_pii(text=text, language_code=language_code)

            # Return analyzer results in formatted Analysis Result List object
            return DetectionResultList(
                detection_results=[
                    DetectionResult(
                        entity_type=result["Type"],
                        score=result["Score"],
                        start=result["BeginOffset"],
                        end=result["EndOffset"],
                    )
                    for result in analysis
                ]
            )

        except Exception as ex:
            logging.error(ex.with_traceback())
            return None
