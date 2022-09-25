from __future__ import annotations

from enum import Enum
from json import JSONEncoder
from typing import List

import strawberry

# All listed PII Types from Milne et al (2018) and a few others along with
# models used for PII categorization for DHS, NIST, HIPAA, and the risk
# assessment models for reporting.


@strawberry.enum
class AnalysisProviderType(Enum):
    AZURE: str = "AZURE"
    AWS: str = "AWS"
    PRESIDIO: str = "PRESIDIO"


@strawberry.enum
class RiskLevel(Enum):
    LEVEL_ONE: int = 1  # Not-Identifiable
    LEVEL_TWO: int = 2  # Semi-Identifiable
    LEVEL_THREE: int = 3  # Identifiable


@strawberry.enum
class RiskLevelDefinition(Enum):
    LEVEL_ONE: str = "Non-Identifiable"  # Default if no entities were detected, risk level is set to this
    LEVEL_TWO: str = "Semi-Identifiable"
    LEVEL_THREE: str = "Identifiable"  # Level associated with Directly PII, PHI, and Standalone PII info types


@strawberry.type
class RiskAssessment:
    pii_type_detected: str = None
    risk_level: int = RiskLevel.LEVEL_ONE.value
    risk_level_definition: str = (
        RiskLevelDefinition.LEVEL_ONE.value
    )  # Default if it's not semi or fully identifiable
    cluster_membership_type: str = None
    hipaa_category: str = None
    dhs_category: str = None
    nist_category: str = None


@strawberry.type
class RiskAssessmentList:
    risk_assessments: List[RiskAssessment]
    average_risk_score: float


@strawberry.type
class DetectionResult:
    entity_type: str
    score: float
    start: int
    end: int


@strawberry.type
class DetectionResultList:
    detection_results: List[DetectionResult]


@strawberry.type
class AnalysisResult:
    detection: DetectionResult
    risk_assessment: RiskAssessment

    def to_dict(self):
        return {
            "riskAssessment": self.risk_assessment.__dict__,
            "detection": self.detection.__dict__,
        }

    def to_flattened_dict(self):
        assessment = self.risk_assessment.__dict__.copy()
        assessment.update(self.detection.__dict__)
        return assessment


@strawberry.type
class AnalysisResultList:
    analyses: List[AnalysisResult]

    def to_dict(self):
        return {"analyses": [item.to_flattened_dict() for item in self.analyses]}


@strawberry.type
class BatchAnalysisResult:
    index: int
    analyses: List[AnalysisResult]

    def to_dict(self):
        return {
            "analyses": [item.to_flattened_dict() for item in self.analyses],
            "index": self.index,
        }


@strawberry.type
class ScoredBatchAnalysisResult:
    index: int
    analyses: List[AnalysisResult]
    average_risk_score: float

    def to_dict(self):
        return {
            "analyses": [item.to_flattened_dict() for item in self.analyses],
            "index": self.index,
            "averageRiskScore": self.average_risk_score,
        }


@strawberry.type
class BatchAnalysisResultList:
    batched_analyses: List[BatchAnalysisResult]

    def to_dict(self):
        return {
            "batched_analyses": [item.to_flattened_dict() for item in self.analyses]
        }


@strawberry.type
class ScoredAnalysisResultList:
    analyses: List[AnalysisResult]
    average_risk_score: float

    def to_dict(self):
        return {
            "analyses": [item.to_flattened_dict() for item in self.analyses],
            "averageRiskScore": self.average_risk_score,
        }


@strawberry.type
class ScoredBatchAnalysisResultList:
    batched_analyses: List[ScoredBatchAnalysisResult]
    average_risk_score: float

    def to_dict(self):
        return {
            "batchedAnalyses": [item.to_dict() for item in self.batched_analyses],
            "averageRiskScore": self.average_risk_score,
        }


class AnalysisEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__


@strawberry.enum
class PIIType(Enum):
    PHONE_NUMBER: str = "PHONE"
    WORK_PHONE_NUMBER: str = "PHONE"
    EMAIL_ADDRESS: str = "EMAIL"
    ABA_ROUTING_NUMBER: str = "ABA_ROUTING_NUMBER"
    IP_ADDRESS: str = "IP_ADDRESS"
    DATE: str = "DATE"
    ADDRESS: str = "ADDRESS"
    HOME_ADDRESS: str = "ADDRESS"
    WORK_ADDRESS: str = "ADDRESS"
    AGE: str = "AGE"
    PERSON: str = "PERSON"
    CREDIT_CARD_NUMBER: str = "CREDIT_CARD_NUMBER"
    CREDIT_SCORE: str = "CREDIT_SCORE"
    CRYPTO: str = "CRYPTO"
    URL: str = "URL"
    DATE_TIME: str = "DATE_TIME"
    LOCATION: str = "LOCATION"
    ZIPCODE: str = "ZIPCODE"
    RACE: str = "RACE"
    HEIGHT: str = "HEIGHT"
    WEIGHT: str = "WEIGHT"
    GENDER: str = "GENDER"
    HOMETOWN: str = "HOMETOWN"
    SCREEN_NAME: str = "SCREEN_NAME"
    MARITAL_STATUS: str = "MARITAL_STATUS"
    NUMBER_OF_CHILDREN: str = "NUMBER_OF_CHILDREN"
    RELIGION: str = "RELIGION"
    COUNTRY_OF_CITIZENSHIP: str = "COUNTRY_OF_CITIZENSHIP"
    VOICE_PRINT: str = "VOICE_PRINT"
    FINGERPRINT: str = "FINGERPRINT"
    DNA_PROFILE: str = "DNA_PROFILE"
    PICTURE_FACE: str = "PICTURE_FACE"
    HANDWRITING_SAMPLE: str = "HANDWRITING_SAMPLE"
    MOTHERS_MAIDEN_NAME: str = "MOTHERS_MAIDEN_NAME"
    DIGITAL_SIGNATURE: str = "DIGITAL_SIGNATURE"
    HEALTH_INSURANCE_ID: str = "HEALTH_INSURANCE_ID"
    SHOPPING_BEHAVIOR: str = "SHOPPING_BEHAVIOR"
    POLITICAL_AFFILIATION: str = "POLITICAL_AFFILIATION"
    SEXUAL_PREFERENCE: str = "SEXUAL_PREFERENCE"
    SOCIAL_NETWORK_PROFILE: str = "SOCIAL_NETWORK_PROFILE"
    JOB_TITLE: str = "JOB_TITLE"
    INCOME_LEVEL: str = "INCOME_LEVEL"
    OCCUPATION: str = "OCCUPATION"
    DOCUMENTS: str = "DOCUMENTS"
    MEDICAL_LICENSE: str = "MEDICAL_LICENSE"
    LICENSE_PLATE_NUMBER: str = "LICENSE_PLATE_NUMBER"
    SECURITY_ACCESS_CODES: str = "SECURITY_ACCESS_CODES"
    PASSWORD: str = "PASSWORD"
    US_SOCIAL_SECURITY_NUMBER: str = "US_SOCIAL_SECURITY_NUMBER"
    US_BANK_ACCOUNT_NUMBER: str = "US_BANK_ACCOUNT_NUMBER"
    US_DRIVERS_LICENSE_NUMBER: str = "US_DRIVERS_LICENSE_NUMBER"
    US_PASSPORT_NUMBER: str = "US_PASSPORT_NUMBER"
    US_INDIVIDUAL_TAXPAYER_IDENTIFICATION: str = "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION"
    INTERNATIONAL_BANKING_ACCOUNT_NUMBER: str = "INTERNATIONAL_BANKING_ACCOUNT_NUMBER"
    SWIFT_CODE: str = "SWIFTCode"


@strawberry.enum
class NISTCategory(Enum):
    LINKABLE: str = "Linkable"
    DIRECTLY_PII: str = "Directly PII"


@strawberry.enum
class DHSCategory(Enum):
    NOT_MENTIONED: str = "Not Mentioned"
    LINKABLE: str = "Linkable"
    STAND_ALONE_PII: str = "Stand Alone PII"


@strawberry.enum
class HIPAACategory(Enum):
    NON_PHI: str = "Not Protected Health Information"
    PHI: str = "Protected Health Information"


@strawberry.enum
class ClusterMembershipType(Enum):
    BASIC_DEMOGRAPHICS: str = "Basic Demographics"
    PERSONAL_PREFERENCES: str = "Personal Preferences"
    CONTACT_INFORMATION: str = "Contact Information"
    COMMUNITY_INTERACTION: str = "Community Interaction"
    FINANCIAL_INFORMATION: str = "Financial Information"
    SECURE_IDENTIFIERS: str = "Secure Identifiers"
