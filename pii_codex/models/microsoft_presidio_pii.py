from __future__ import annotations

from enum import Enum

# PII Types associated with Microsoft Presidio Analyzer
# Supported Entities: https://microsoft.github.io/presidio/supported_entities/


class MSFTPresidioPIIType(Enum):
    PHONE_NUMBER: str = "PHONE_NUMBER"
    EMAIL_ADDRESS: str = "EMAIL_ADDRESS"
    ABA_ROUTING_NUMBER: str = "ABA_ROUTING_NUMBER"
    IP_ADDRESS: str = "IP_ADDRESS"
    DATE: str = "DATE_TIME"
    ADDRESS: str = "ADDRESS"
    AGE: str = "AGE"
    PERSON: str = "PERSON"
    CREDIT_CARD_NUMBER: str = "CREDIT_CARD"
    CRYPTO: str = "CRYPTO"
    URL: str = "URL"
    DATE_TIME: str = "DATE_TIME"
    LOCATION: str = "LOCATION"
    MEDICAL_LICENSE: str = "MEDICAL_LICENSE"
    US_SOCIAL_SECURITY_NUMBER: str = "US_SSN"
    US_BANK_ACCOUNT_NUMBER: str = "US_BANK_NUMBER"
    US_DRIVERS_LICENSE_NUMBER: str = "US_DRIVER_LICENSE"
    US_PASSPORT_NUMBER: str = "US_PASSPORT"
    US_INDIVIDUAL_TAXPAYER_IDENTIFICATION: str = "US_ITIN"
    INTERNATIONAL_BANKING_ACCOUNT_NUMBER: str = "IBAN_CODE"
    UK_NATIONAL_HEALTH_NUMBER: str = "UK_NHS"
    AU_BUSINESS_NUMBER: str = "AU_ABN"
    AU_COMPANY_NUMBER: str = "AU_ACN"
    AU_MEDICAL_ACCOUNT_NUMBER: str = "AU_MEDICARE"
    AU_TAX_FILE_NUMBER: str = "AU_TFN"
    ES_TAX_IDENTIFICATION_NUMBER: str = "ES_NIF"
    SG_NATIONAL_REGISTRATION_IDENTITY_CARD_NUMBER: str = "SG_NRIC_FIN"
