# pylint: disable=broad-except
import logging
from typing import List
from presidio_analyzer import AnalyzerEngine
from pii_codex.models.microsoft_presidio_pii import AnalysisResultList, AnalysisResult


class PIIDetectionService:
    @staticmethod
    def analyze_with_msft_presidio(
        entities: List[str], text: str
    ) -> AnalysisResultList:
        """
        Uses Microsoft Presidio (spaCy module) to analyze given a set of entities to analyze the provided text against.
        Will log an error if the identifier or entity recognizer is not added to Presidio's base recognizers or
        a custom recognizer created.
        :param entities:
        :param text:
        :return:
        """

        # Engine Setup - spaCy model setup and PII recognizers
        analyzer = AnalyzerEngine()
        analysis = []

        try:
            analysis = analyzer.analyze(text=text, entities=entities, language="en")
        except Exception as ex:
            logging.error(ex.with_traceback())

        # Return analyzer results in formatted Analysis Result List object
        return AnalysisResultList(
            analysis_results=[
                AnalysisResult(
                    entity_type=result.entity_type,
                    score=result.score,
                    recognizer_name=result.RECOGNIZER_NAME_KEY,
                    start=result.start,
                    end=result.end,
                )
                for result in analysis
            ]
        )
