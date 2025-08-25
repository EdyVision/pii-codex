from __future__ import annotations

from enum import Enum

# All listed PII Types from Milne et al (2018) and a few others along with
# models used for PII categorization for DHS, NIST, and HIPAA


class AnalysisProviderType(Enum):
    """
    Analysis Provider Types - software and cloud service APIs providing PII detection results
    """

    AZURE = "AZURE"
    AWS = "AWS"
    PRESIDIO = "PRESIDIO"


class RiskLevel(Enum):
    """
    Numerical values assigned to the levels on the continuum presented by Schwartz and Solove (2011)
    """

    LEVEL_ONE = 1  # Not-Identifiable
    LEVEL_TWO = 2  # Semi-Identifiable
    LEVEL_THREE = 3  # Identifiable


class RiskLevelDefinition(Enum):
    """
    Levels on the continuum presented by Schwartz and Solove (2011)
    """

    LEVEL_ONE = "Non-Identifiable"  # Default if no entities were detected, risk level is set to this
    LEVEL_TWO = "Semi-Identifiable"
    LEVEL_THREE = "Identifiable"  # Level associated with Directly PII, PHI, and Standalone PII info types


class MetadataType(Enum):
    """
    Common metadata types associated with social media posts and other online platforms
    """

    SCREEN_NAME = "screen_name"
    NAME = "name"
    LOCATION = "location"
    URL = "url"
    USER_ID = "user_id"


class PIIType(Enum):
    """
    Commonly observed PII types across services and software
    """

    PHONE_NUMBER = "PHONE"
    WORK_PHONE_NUMBER = "PHONE"
    EMAIL_ADDRESS = "EMAIL"
    ABA_ROUTING_NUMBER = "ABA_ROUTING_NUMBER"
    IP_ADDRESS = "IP_ADDRESS"
    DATE = "DATE"
    ADDRESS = "ADDRESS"
    HOME_ADDRESS = "ADDRESS"
    WORK_ADDRESS = "ADDRESS"
    AGE = "AGE"
    PERSON = "PERSON"
    CREDIT_CARD_NUMBER = "CREDIT_CARD_NUMBER"
    CREDIT_SCORE = "CREDIT_SCORE"
    CRYPTO = "CRYPTO"
    URL = "URL"
    DATE_TIME = "DATE_TIME"
    LOCATION = "LOCATION"
    ZIPCODE = "ZIPCODE"
    RACE = "RACE"
    HEIGHT = "HEIGHT"
    WEIGHT = "WEIGHT"
    GENDER = "GENDER"
    HOMETOWN = "HOMETOWN"
    SCREEN_NAME = "SCREEN_NAME"
    MARITAL_STATUS = "MARITAL_STATUS"
    NUMBER_OF_CHILDREN = "NUMBER_OF_CHILDREN"
    COUNTRY_OF_CITIZENSHIP = "COUNTRY_OF_CITIZENSHIP"
    VOICE_PRINT = "VOICE_PRINT"
    FINGERPRINT = "FINGERPRINT"
    DNA_PROFILE = "DNA_PROFILE"
    PICTURE_FACE = "PICTURE_FACE"
    HANDWRITING_SAMPLE = "HANDWRITING_SAMPLE"
    MOTHERS_MAIDEN_NAME = "MOTHERS_MAIDEN_NAME"
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    HEALTH_INSURANCE_ID = "HEALTH_INSURANCE_ID"
    SHOPPING_BEHAVIOR = "SHOPPING_BEHAVIOR"
    SEXUAL_PREFERENCE = "SEXUAL_PREFERENCE"
    SOCIAL_NETWORK_PROFILE = "SOCIAL_NETWORK_PROFILE"
    JOB_TITLE = "JOB_TITLE"
    INCOME_LEVEL = "INCOME_LEVEL"
    OCCUPATION = "OCCUPATION"
    DOCUMENTS = "DOCUMENTS"
    MEDICAL_LICENSE = "MEDICAL_LICENSE"
    LICENSE_PLATE_NUMBER = "LICENSE_PLATE_NUMBER"
    SECURITY_ACCESS_CODES = "SECURITY_ACCESS_CODES"
    PASSWORD = "PASSWORD"
    US_SOCIAL_SECURITY_NUMBER = "US_SOCIAL_SECURITY_NUMBER"
    US_BANK_ACCOUNT_NUMBER = "US_BANK_ACCOUNT_NUMBER"
    US_DRIVERS_LICENSE_NUMBER = "US_DRIVERS_LICENSE_NUMBER"
    US_PASSPORT_NUMBER = "US_PASSPORT_NUMBER"
    US_INDIVIDUAL_TAXPAYER_IDENTIFICATION = "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION"
    INTERNATIONAL_BANKING_ACCOUNT_NUMBER = "INTERNATIONAL_BANKING_ACCOUNT_NUMBER"
    SWIFT_CODE = "SWIFTCode"
    NRP = "NRP"  # A person's nationality, religion, or political group
    # Australian PII types
    AU_BUSINESS_NUMBER = "AU_BUSINESS_NUMBER"
    AU_COMPANY_NUMBER = "AU_COMPANY_NUMBER"
    AU_MEDICAL_ACCOUNT_NUMBER = "AU_MEDICAL_ACCOUNT_NUMBER"
    AU_TAX_FILE_NUMBER = "AU_TAX_FILE_NUMBER"


class NISTCategory(Enum):
    """
    Information Categories presented by NIST as noted in Milne et al., 2016
    """

    LINKABLE = "Linkable"
    DIRECTLY_PII = "Directly PII"


class DHSCategory(Enum):
    """
    Information Categories presented by DHS as noted in Milne et al., 2016
    """

    NOT_MENTIONED = "Not Mentioned"
    LINKABLE = "Linkable"
    STAND_ALONE_PII = "Stand Alone PII"


class HIPAACategory(Enum):
    """
    Information Categories presented by HIPAA guidelines
    """

    NON_PHI = "Not Protected Health Information"
    PHI = "Protected Health Information"


class ClusterMembershipType(Enum):
    """
    Information Cluster Memberships presented by Milne et al., 2016
    """

    BASIC_DEMOGRAPHICS = "Basic Demographics"
    PERSONAL_PREFERENCES = "Personal Preferences"
    CONTACT_INFORMATION = "Contact Information"
    COMMUNITY_INTERACTION = "Community Interaction"
    FINANCIAL_INFORMATION = "Financial Information"
    SECURE_IDENTIFIERS = "Secure Identifiers"
