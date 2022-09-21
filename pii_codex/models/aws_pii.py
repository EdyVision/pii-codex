from __future__ import annotations

from enum import Enum

import strawberry
from dataclasses_json import dataclass_json, LetterCase

# PII Types and Models as expanded in research
# Research Page:
# AWS Comprehend PII Docs: https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html


@dataclass_json(letter_case=LetterCase.CAMEL)
@strawberry.enum
class AWSPIIType(Enum):
    EMAIL: str = "Email"
    ADDRESS: str = "Address"
    NAME: str = "Name"
    PHONE: str = "PhoneNumber"
    DATE_TIME: str = "DateTime"
    URL: str = "URL"
    AGE: str = "Age"
    USERNAME: str = "Username"
    PASSWORD: str = "Password"
    CREDIT_DEBIT_NUMBER: str = "CreditDebitNumber"
    CREDIT_DEBIT_CVV: str = "CreditDebitCVV"
    CREDIT_DEBIT_EXPIRY: str = "CreditDebitExpiration"
    PIN: str = "PIN"
    DRIVER_ID: str = "DriverID"
    LICENSE_PLATE: str = "LicensePlate"
    VEHICLE_IDENTIFICATION_NUMBER: str = "VehicleIdentificationNumber"
    INTERNATIONAL_BANK_ACCOUNT_NUMBER: str = "InternationalBankAccountNumber"
    SWIFT_CODE: str = "SwiftCode"
    CRYPTO_WALLET_ADDRESS: str = "CryptoWalletAddress"
    IP_ADDRESS: str = "IPAddress"
    IPV6_ADDRESS: str = "IPv6Address"
    MAC_ADDRESS: str = "MACAddress"
    AWS_ACCESS_KEY: str = "AWSAccessKey"
    AWS_SECRET_KEY: str = "AWSSecretKey"
    PASSPORT_NUMBER: str = "PassportNumber"
    SSN: str = "SocialSecurityNumber"
    BANK_ACCOUNT_NUMBER: str = "BankAccountNumber"
    BANK_ROUTING: str = "BankRouting"
    US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER: str = "USIndividualTaxIdentificationNumber"
    UK_NATIONAL_HEALTH_SERVICE_NUMBER: str = "UKNationalHealthServiceNumber"
    UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER: str = "UKUniqueTaxpayerReferenceNumber"
    UK_NATIONAL_INSURANCE_NUMBER: str = "UKNationalInsuranceNumber"
    CA_HEALTH_NUMBER: str = "CAHealthNumber"
    CA_SOCIAL_INSURANCE_NUMBER: str = "CASocialInsuranceNumber"
    IN_AADHAAR: str = "INAADHAAR"
    IN_VOTER_NUMBER: str = "INVoterNumber"
    IN_PERMANENT_ACCOUNT_NUMBER: str = "INPermanentAccountNumber"
    IN_NREGA: str = "INNREGA"
    ALL: str = "All"
