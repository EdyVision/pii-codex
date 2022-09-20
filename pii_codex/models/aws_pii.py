from __future__ import annotations

from enum import Enum

import strawberry
from dataclasses_json import dataclass_json, LetterCase

"""
PII Types and Models as expanded in research
Research Page:
AWS Comprehend PII Docs: https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html
"""


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


@dataclass_json(letter_case=LetterCase.CAMEL)
@strawberry.enum
class AWSPIITypeDef(Enum):
    EMAIL: str = "An email address, such as example@email.com."
    ADDRESS: str = "A physical address, such as '100 Main Street, Anytown, USA' or 'Suite #12, Building 123'. An address can include information such as the street, building, location, city, state, country, county, zip code, precinct, and neighborhood."
    NAME: str = "An individual's name. This entity type does not include titles, such as Dr., Mr., Mrs., or Miss. Amazon Comprehend does not apply this entity type to names that are part of organizations or addresses. For example, Amazon Comprehend recognizes the 'John Doe Organization' as an organization, and it recognizes 'Jane Doe Street' as an address."
    PHONE: str = "A phone number. This entity type also includes fax and pager numbers."
    DATE_TIME: str = "A date can include a year, month, day, day of week, or time of day. For example, Amazon Comprehend recognizes 'January 19, 2020' or '11 am' as dates. Amazon Comprehend will recognize partial dates, date ranges, and date intervals. It will also recognize decades, such as 'the 1990s'."
    URL: str = "A web address, such as www.example.com."
    AGE: str = "An individual's age, including the quantity and unit of time. For example, in the phrase 'I am 40 years old,' Amazon Comprehend recognizes '40 years' as an age."
    USERNAME: str = "A user name that identifies an account, such as a login name, screen name, nick name, or handle."
    PASSWORD: str = "An alphanumeric string that is used as a password, such as '*very20special#pass*'."
    CREDIT_DEBIT_NUMBER: str = "The number for a credit or debit card. These numbers can vary from 13 to 16 digits in length. However, Amazon Comprehend also recognizes credit or debit card numbers when only the last four digits are present."
    CREDIT_DEBIT_CVV: str = "A three-digit card verification code (CVV) that is present on VISA, MasterCard, and Discover credit and debit cards. For American Express credit or debit cards, the CVV is a four-digit numeric code."
    CREDIT_DEBIT_EXPIRY: str = "The expiration date for a credit or debit card. This number is usually four digits long and is often formatted as month/year or MM/YY. Amazon Comprehend recognizes expiration dates such as 01/21, 01/2021, and Jan 2021."
    PIN: str = "A four-digit personal identification number (PIN) with which you can access your bank account."
    DRIVER_ID: str = "The number assigned to a driver's license, which is an official document permitting an individual to operate one or more motorized vehicles on a public road. A driver's license number consists of alphanumeric characters."
    LICENSE_PLATE: str = "A license plate for a vehicle is issued by the state or country where the vehicle is registered. The format for passenger vehicles is typically five to eight digits, consisting of upper-case letters and numbers. The format varies depending on the location of the issuing state or country."
    VEHICLE_IDENTIFICATION_NUMBER: str = "A Vehicle Identification Number (VIN) uniquely identifies a vehicle. VIN content and format are defined in the ISO 3779 specification. Each country has specific codes and formats for VINs."
    INTERNATIONAL_BANK_ACCOUNT_NUMBER: str = (
        "An International Bank Account Number has specific formats in each country."
    )
    SWIFT_CODE: str = "A SWIFT code is a standard format of Bank Identifier Code (BIC) used to specify a particular bank or branch. Banks use these codes for money transfers such as international wire transfers. SWIFT codes consist of eight or 11 characters. The 11-digit codes refer to specific branches, while eight-digit codes (or 11-digit codes ending in 'XXX') refer to the head or primary office."
    CRYPTO_WALLET_ADDRESS: str = "Crypto Wallet Address"
    IP_ADDRESS: str = "An IPv4 address, such as 198.51.100.0."
    IPV6_ADDRESS: str = (
        "An IPv6 Address, such as 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    )
    MAC_ADDRESS: str = "A media access control (MAC) address is a unique identifier assigned to a network interface controller (NIC)."
    AWS_ACCESS_KEY: str = "A unique identifier that's associated with a secret access key; you use the access key ID and secret access key to sign programmatic AWS requests cryptographically."
    AWS_SECRET_KEY: str = "A unique identifier that's associated with an access key. You use the access key ID and secret access key to sign programmatic AWS requests cryptographically."
    PASSPORT_NUMBER: str = "A US passport number. Passport numbers range from six to nine alphanumeric characters."
    SSN: str = "A US Social Security Number (SSN) is a nine-digit number that is issued to US citizens, permanent residents, and temporary working residents. Amazon Comprehend also recognizes Social Security Numbers when only the last four digits are present."
    BANK_ACCOUNT_NUMBER: str = "A US bank account number, which is typically 10 to 12 digits long. Amazon Comprehend also recognizes bank account numbers when only the last four digits are present."
    BANK_ROUTING: str = "A US bank account routing number. These are typically nine digits long, but Amazon Comprehend also recognizes routing numbers when only the last four digits are present."
    US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER: str = "A US Individual Taxpayer Identification Number (ITIN) is a nine-digit number that starts with a '9' and contain a '7' or '8' as the fourth digit. An ITIN can be formatted with a space or a dash after the third and forth digits."
    UK_NATIONAL_HEALTH_SERVICE_NUMBER: str = "A UK National Health Service Number is a 10-17 digit number, such as 485 777 3456. The current system formats the 10-digit number with spaces after the third and sixth digits. The final digit is an error-detecting checksum."
    UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER: str = "A UK Unique Taxpayer Reference (UTR) is a 10-digit number that identifies a taxpayer or a business."
    UK_NATIONAL_INSURANCE_NUMBER: str = "A UK National Insurance Number (NINO) provides individuals with access to National Insurance (social security) benefits. It is also used for some purposes in the UK tax system."
    CA_HEALTH_NUMBER: str = "A Canadian Health Service Number is a 10-digit unique identifier, required for individuals to access healthcare benefits."
    CA_SOCIAL_INSURANCE_NUMBER: str = "A Canadian Social Insurance Number (SIN) is a nine-digit unique identifier, required for individuals to access government programs and benefits. The SIN is formatted as three groups of three digits, such as 123-456-789."
    IN_AADHAAR: str = "An Indian Aadhaar is a 12-digit unique identification number issued by the Indian government to the residents of India. The Aadhaar format has a space or hyphen after the fourth and eighth digit."
    IN_VOTER_NUMBER: str = (
        "An Indian Voter ID consists of three letters followed by seven numbers."
    )
    IN_PERMANENT_ACCOUNT_NUMBER: str = "An Indian Permanent Account Number is a 10-digit unique alphanumeric number issued by the Income Tax Department."
    IN_NREGA: str = "An Indian National Rural Employment Guarantee Act (NREGA) number consists of two letters followed by 14 numbers."
    ALL: str = "All PII Types"
