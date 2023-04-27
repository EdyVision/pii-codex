from __future__ import annotations

from enum import Enum


# PII Types and Models as expanded in research
# Research Page:
# AWS Comprehend PII Docs: https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html


class AWSComprehendPIIType(Enum):
    """
    AWS Comprehend-Supported PII types
    """

    EMAIL_ADDRESS: str = "EMAIL"
    ADDRESS: str = "ADDRESS"
    PERSON: str = "NAME"
    PHONE_NUMBER: str = "PHONE"
    DATE: str = "DATE_TIME"
    URL: str = "URL"
    AGE: str = "AGE"
    USERNAME: str = "USERNAME"
    PASSWORD: str = "PASSWORD"
    CREDIT_DEBIT_NUMBER: str = "CREDIT_DEBIT_NUMBER"
    CREDIT_DEBIT_CVV: str = "CREDIT_DEBIT_CVV"
    CREDIT_DEBIT_EXPIRY: str = "CREDIT_DEBIT_EXPIRY"
    PIN: str = "PIN"
    US_DRIVERS_LICENSE_NUMBER: str = "DRIVER_ID"
    LICENSE_PLATE_NUMBER: str = "LICENSE_PLATE"
    VEHICLE_IDENTIFICATION_NUMBER: str = "VEHICLE_IDENTIFICATION_NUMBER"
    INTERNATIONAL_BANKING_ACCOUNT_NUMBER: str = "INTERNATIONAL_BANK_ACCOUNT_NUMBER"
    SWIFT_CODE: str = "SWIFT_CODE"
    CRYPTO: str = "CRYPTO_WALLET_ADDRESS"
    IP_ADDRESS: str = "IP_ADDRESS"
    IPV6_ADDRESS: str = "IPV6_ADDRESS"
    MAC_ADDRESS: str = "MAC_ADDRESS"
    AWS_ACCESS_KEY: str = "AWS_ACCESS_KEY"
    AWS_SECRET_KEY: str = "AWS_SECRET_KEY"
    US_PASSPORT_NUMBER: str = "PASSPORT_NUMBER"
    US_SOCIAL_SECURITY_NUMBER: str = "SSN"
    US_BANK_ACCOUNT_NUMBER: str = "BANK_ACCOUNT_NUMBER"
    ABA_ROUTING_NUMBER: str = "BANK_ROUTING"
    US_INDIVIDUAL_TAXPAYER_IDENTIFICATION: str = "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION"
    UK_NATIONAL_HEALTH_SERVICE_NUMBER: str = "UK_NATIONAL_HEALTH_SERVICE_NUMBER"
    UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER: str = "UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER"
    UK_NATIONAL_INSURANCE_NUMBER: str = "UK_NATIONAL_INSURANCE_NUMBER"
    CA_HEALTH_NUMBER: str = "CA_HEALTH_NUMBER"
    CA_SOCIAL_INSURANCE_NUMBER: str = "CA_SOCIAL_INSURANCE_NUMBER"
    IN_AADHAAR: str = "IN_AADHAAR"
    IN_VOTER_NUMBER: str = "IN_VOTER_NUMBER"
    IN_PERMANENT_ACCOUNT_NUMBER: str = "IN_PERMANENT_ACCOUNT_NUMBER"
    IN_NREGA: str = "IN_NREGA"
    ALL: str = "ALL"
