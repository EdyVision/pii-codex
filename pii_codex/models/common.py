from __future__ import annotations

from enum import Enum

# All listed PII Types from Milne et al (2018) and a few others along with
# models used for PII categorization for DHS, NIST, and HIPAA


class AnalysisProviderType(Enum):
    AZURE: str = "AZURE"
    AWS: str = "AWS"
    PRESIDIO: str = "PRESIDIO"


class RiskLevel(Enum):
    LEVEL_ONE: int = 1  # Not-Identifiable
    LEVEL_TWO: int = 2  # Semi-Identifiable
    LEVEL_THREE: int = 3  # Identifiable


class RiskLevelDefinition(Enum):
    LEVEL_ONE: str = "Non-Identifiable"  # Default if no entities were detected, risk level is set to this
    LEVEL_TWO: str = "Semi-Identifiable"
    LEVEL_THREE: str = "Identifiable"  # Level associated with Directly PII, PHI, and Standalone PII info types


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
    USUK_PASSPORT_NUMBER: str = "USUK_PASSPORT_NUMBER"
    US_INDIVIDUAL_TAXPAYER_IDENTIFICATION: str = "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION"
    INTERNATIONAL_BANKING_ACCOUNT_NUMBER: str = "INTERNATIONAL_BANKING_ACCOUNT_NUMBER"
    SWIFT_CODE: str = "SWIFTCode"


class NISTCategory(Enum):
    LINKABLE: str = "Linkable"
    DIRECTLY_PII: str = "Directly PII"


class DHSCategory(Enum):
    NOT_MENTIONED: str = "Not Mentioned"
    LINKABLE: str = "Linkable"
    STAND_ALONE_PII: str = "Stand Alone PII"


class HIPAACategory(Enum):
    NON_PHI: str = "Not Protected Health Information"
    PHI: str = "Protected Health Information"


class ClusterMembershipType(Enum):
    BASIC_DEMOGRAPHICS: str = "Basic Demographics"
    PERSONAL_PREFERENCES: str = "Personal Preferences"
    CONTACT_INFORMATION: str = "Contact Information"
    COMMUNITY_INTERACTION: str = "Community Interaction"
    FINANCIAL_INFORMATION: str = "Financial Information"
    SECURE_IDENTIFIERS: str = "Secure Identifiers"
