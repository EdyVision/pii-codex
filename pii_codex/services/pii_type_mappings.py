"""
PII Type Mappings - Structured data for fast lookups
This replaces the CSV-based approach with direct Python structures
"""

from typing import Dict, NamedTuple, Optional

from pii_codex.models.common import (
    RiskLevel,
    ClusterMembershipType,
    NISTCategory,
    DHSCategory,
    HIPAACategory,
)
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.models.azure_pii import AzureDetectionType
from pii_codex.models.aws_pii import AWSComprehendPIIType


class PIIMapping(NamedTuple):
    """Structure for PII type mapping data"""

    information_type: str
    pii_type: str
    cluster_membership_type: ClusterMembershipType
    nist_category: NISTCategory
    dhs_category: DHSCategory
    hipaa_category: HIPAACategory
    risk_level: RiskLevel
    # Provider-specific enum references
    presidio_enum: Optional[MSFTPresidioPIIType] = None
    azure_enum: Optional[AzureDetectionType] = None
    aws_enum: Optional[AWSComprehendPIIType] = None


# PII Type Mappings Dictionary
PII_TYPE_MAPPINGS: Dict[str, PIIMapping] = {
    "PLACE_OF_BIRTH": PIIMapping(
        information_type="Place of Birth",
        pii_type="PLACE_OF_BIRTH",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct place of birth type
        azure_enum=None,  # Azure doesn't have a direct place of birth type
        aws_enum=None,  # AWS doesn't have a direct place of birth type
    ),
    "RACE": PIIMapping(
        information_type="Race",
        pii_type="RACE",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct race type
        azure_enum=None,  # Azure doesn't have a direct race type
        aws_enum=None,  # AWS doesn't have a direct race type
    ),
    "HEIGHT": PIIMapping(
        information_type="Height",
        pii_type="HEIGHT",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct height type
        azure_enum=None,  # Azure doesn't have a direct height type
        aws_enum=None,  # AWS doesn't have a direct height type
    ),
    "WEIGHT": PIIMapping(
        information_type="Weight",
        pii_type="WEIGHT",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct weight type
        azure_enum=None,  # Azure doesn't have a direct weight type
        aws_enum=None,  # AWS doesn't have a direct weight type
    ),
    "MARITAL_STATUS": PIIMapping(
        information_type="Marital Status",
        pii_type="MARITAL_STATUS",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct marital status type
        azure_enum=None,  # Azure doesn't have a direct marital status type
        aws_enum=None,  # AWS doesn't have a direct marital status type
    ),
    "COUNTRY_OF_CITIZENSHIP": PIIMapping(
        information_type="Country of Citizenship",
        pii_type="COUNTRY_OF_CITIZENSHIP",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct country of citizenship type
        azure_enum=None,  # Azure doesn't have a direct country of citizenship type
        aws_enum=None,  # AWS doesn't have a direct country of citizenship type
    ),
    "SHOPPING_BEHAVIOR": PIIMapping(
        information_type="Shopping Behavior",
        pii_type="SHOPPING_BEHAVIOR",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct shopping behavior type
        azure_enum=None,  # Azure doesn't have a direct shopping behavior type
        aws_enum=None,  # AWS doesn't have a direct shopping behavior type
    ),
    "ZIPCODE": PIIMapping(
        information_type="Zipcode",
        pii_type="ZIPCODE",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct zipcode type
        azure_enum=None,  # Azure doesn't have a direct zipcode type
        aws_enum=None,  # AWS doesn't have a direct zipcode type
    ),
    "NUMBER_OF_CHILDREN": PIIMapping(
        information_type="Number of Children",
        pii_type="NUMBER_OF_CHILDREN",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct number of children type
        azure_enum=None,  # Azure doesn't have a direct number of children type
        aws_enum=None,  # AWS doesn't have a direct number of children type
    ),
    "JOB_TITLE": PIIMapping(
        information_type="Job Title",
        pii_type="JOB_TITLE",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct job title type
        azure_enum=None,  # Azure doesn't have a direct job title type
        aws_enum=None,  # AWS doesn't have a direct job title type
    ),
    "HOMETOWN": PIIMapping(
        information_type="Hometown",
        pii_type="HOMETOWN",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct hometown type
        azure_enum=None,  # Azure doesn't have a direct hometown type
        aws_enum=None,  # AWS doesn't have a direct hometown type
    ),
    "INCOME_LEVEL": PIIMapping(
        information_type="Income Level",
        pii_type="INCOME_LEVEL",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct income level type
        azure_enum=None,  # Azure doesn't have a direct income level type
        aws_enum=None,  # AWS doesn't have a direct income level type
    ),
    "OCCUPATION": PIIMapping(
        information_type="Occupation",
        pii_type="OCCUPATION",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct occupation type
        azure_enum=None,  # Azure doesn't have a direct occupation type
        aws_enum=None,  # AWS doesn't have a direct occupation type
    ),
    "GENDER": PIIMapping(
        information_type="Gender",
        pii_type="GENDER",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct gender type
        azure_enum=None,  # Azure doesn't have a direct gender type
        aws_enum=None,  # AWS doesn't have a direct gender type
    ),
    "DATE": PIIMapping(
        information_type="Birth Date",
        pii_type="DATE",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=MSFTPresidioPIIType.DATE,
        azure_enum=AzureDetectionType.DATE,
        aws_enum=AWSComprehendPIIType.DATE,
    ),
    "SCREEN_NAME": PIIMapping(
        information_type="Online Screen Name",
        pii_type="SCREEN_NAME",
        cluster_membership_type=ClusterMembershipType.PERSONAL_PREFERENCES,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=None,  # Presidio doesn't have a direct screen name type
        azure_enum=None,  # Azure doesn't have a direct screen name type
        aws_enum=AWSComprehendPIIType.USERNAME,
    ),
    "NRP": PIIMapping(
        information_type="Nationality, Religion, Political Affiliation",
        pii_type="NRP",
        cluster_membership_type=ClusterMembershipType.PERSONAL_PREFERENCES,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=MSFTPresidioPIIType.NRP,
        azure_enum=None,  # Azure doesn't have a direct NRP type
        aws_enum=None,  # AWS doesn't have a direct NRP type
    ),
    "SEXUAL_PREFERENCE": PIIMapping(
        information_type="Sexual Preference",
        pii_type="SEXUAL_PREFERENCE",
        cluster_membership_type=ClusterMembershipType.PERSONAL_PREFERENCES,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct sexual preference type
        azure_enum=None,  # Azure doesn't have a direct sexual preference type
        aws_enum=None,  # AWS doesn't have a direct sexual preference type
    ),
    "EMAIL_ADDRESS": PIIMapping(
        information_type="Email Address",
        pii_type="EMAIL_ADDRESS",
        cluster_membership_type=ClusterMembershipType.PERSONAL_PREFERENCES,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.EMAIL_ADDRESS,
        azure_enum=AzureDetectionType.EMAIL_ADDRESS,
        aws_enum=AWSComprehendPIIType.EMAIL_ADDRESS,
    ),
    "VOICE_PRINT": PIIMapping(
        information_type="Voice Print",
        pii_type="VOICE_PRINT",
        cluster_membership_type=ClusterMembershipType.CONTACT_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=None,  # Presidio doesn't have a direct voice print type
        azure_enum=None,  # Azure doesn't have a direct voice print type
        aws_enum=None,  # AWS doesn't have a direct voice print type
    ),
    "IP_ADDRESS": PIIMapping(
        information_type="IP Address",
        pii_type="IP_ADDRESS",
        cluster_membership_type=ClusterMembershipType.CONTACT_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.IP_ADDRESS,
        azure_enum=AzureDetectionType.IP_ADDRESS,
        aws_enum=AWSComprehendPIIType.IP_ADDRESS,
    ),
    "PHONE_NUMBER": PIIMapping(
        information_type="Home Phone Number, Cell Phone Number",
        pii_type="PHONE_NUMBER",
        cluster_membership_type=ClusterMembershipType.CONTACT_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.PHONE_NUMBER,
        azure_enum=AzureDetectionType.PHONE_NUMBER,
        aws_enum=AWSComprehendPIIType.PHONE_NUMBER,
    ),
    "ADDRESS": PIIMapping(
        information_type="Address",
        pii_type="ADDRESS",
        cluster_membership_type=ClusterMembershipType.CONTACT_INFORMATION,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=MSFTPresidioPIIType.ADDRESS,
        azure_enum=AzureDetectionType.ADDRESS,
        aws_enum=AWSComprehendPIIType.ADDRESS,
    ),
    "WORK_ADDRESS": PIIMapping(
        information_type="Work Address",
        pii_type="WORK_ADDRESS",
        cluster_membership_type=ClusterMembershipType.CONTACT_INFORMATION,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct work address type
        azure_enum=None,  # Azure doesn't have a direct work address type
        aws_enum=None,  # AWS doesn't have a direct work address type
    ),
    "WORK_CONTACT_INFORMATION": PIIMapping(
        information_type="Work Contact Information",
        pii_type="WORK_CONTACT_INFORMATION",
        cluster_membership_type=ClusterMembershipType.CONTACT_INFORMATION,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct work contact information type
        azure_enum=None,  # Azure doesn't have a direct work contact information type
        aws_enum=None,  # AWS doesn't have a direct work contact information type
    ),
    "WORK_PHONE_NUMBER": PIIMapping(
        information_type="Work Phone Number",
        pii_type="WORK_PHONE_NUMBER",
        cluster_membership_type=ClusterMembershipType.CONTACT_INFORMATION,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct work phone number type
        azure_enum=None,  # Azure doesn't have a direct work phone number type
        aws_enum=None,  # AWS doesn't have a direct work phone number type
    ),
    "FAMILY_FRIEND_CONTACT_INFORMATION": PIIMapping(
        information_type="Family/Friend's Contact Information",
        pii_type="FAMILY_FRIEND_CONTACT_INFORMATION",
        cluster_membership_type=ClusterMembershipType.COMMUNITY_INTERACTION,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct family/friend contact information type
        azure_enum=None,  # Azure doesn't have a direct family/friend contact information type
        aws_enum=None,  # AWS doesn't have a direct family/friend contact information type
    ),
    "SOCIAL_NETWORK_PROFILE": PIIMapping(
        information_type="Social Network Profile",
        pii_type="SOCIAL_NETWORK_PROFILE",
        cluster_membership_type=ClusterMembershipType.COMMUNITY_INTERACTION,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct social network profile type
        azure_enum=None,  # Azure doesn't have a direct social network profile type
        aws_enum=None,  # AWS doesn't have a direct social network profile type
    ),
    "PICTURE_FACE": PIIMapping(
        information_type="Picture Face",
        pii_type="PICTURE_FACE",
        cluster_membership_type=ClusterMembershipType.COMMUNITY_INTERACTION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=None,  # Presidio doesn't have a direct picture face type
        azure_enum=None,  # Azure doesn't have a direct picture face type
        aws_enum=None,  # AWS doesn't have a direct picture face type
    ),
    "MOTHERS_MAIDEN_NAME": PIIMapping(
        information_type="Mother's Maiden Name",
        pii_type="MOTHERS_MAIDEN_NAME",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=None,  # Presidio doesn't have a direct mother's maiden name type
        azure_enum=None,  # Azure doesn't have a direct mother's maiden name type
        aws_enum=None,  # AWS doesn't have a direct mother's maiden name type
    ),
    "HANDWRITING_SAMPLE": PIIMapping(
        information_type="Handwriting Sample",
        pii_type="HANDWRITING_SAMPLE",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct handwriting sample type
        azure_enum=None,  # Azure doesn't have a direct handwriting sample type
        aws_enum=None,  # AWS doesn't have a direct handwriting sample type
    ),
    "US_DRIVERS_LICENSE_NUMBER": PIIMapping(
        information_type="Driver's License Number",
        pii_type="US_DRIVERS_LICENSE_NUMBER",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.US_DRIVERS_LICENSE_NUMBER,
        azure_enum=AzureDetectionType.US_DRIVERS_LICENSE_NUMBER,
        aws_enum=AWSComprehendPIIType.US_DRIVERS_LICENSE_NUMBER,
    ),
    "VEHICLE_REGISTRATION_NUMBER": PIIMapping(
        information_type="Vehicle Registration Number",
        pii_type="VEHICLE_REGISTRATION_NUMBER",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=None,  # Presidio doesn't have a direct vehicle registration number type
        azure_enum=None,  # Azure doesn't have a direct vehicle registration number type
        aws_enum=None,  # AWS doesn't have a direct vehicle registration number type
    ),
    "LICENSE_PLATE_NUMBER": PIIMapping(
        information_type="License Plate Number",
        pii_type="LICENSE_PLATE_NUMBER",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=None,  # Presidio doesn't have a direct license plate type
        azure_enum=None,  # Azure doesn't have a direct license plate type
        aws_enum=AWSComprehendPIIType.LICENSE_PLATE_NUMBER,
    ),
    "CREDIT_CARD_NUMBER": PIIMapping(
        information_type="Credit Card Number",
        pii_type="CREDIT_CARD_NUMBER",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.CREDIT_CARD_NUMBER,
        azure_enum=AzureDetectionType.CREDIT_CARD_NUMBER,
        aws_enum=AWSComprehendPIIType.CREDIT_DEBIT_NUMBER,
    ),
    "CREDIT_SCORE": PIIMapping(
        information_type="Credit Score",
        pii_type="CREDIT_SCORE",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct credit score type
        azure_enum=None,  # Azure doesn't have a direct credit score type
        aws_enum=None,  # AWS doesn't have a direct credit score type
    ),
    "ABA_ROUTING_NUMBER": PIIMapping(
        information_type="American Bankers Association Routing Number (Financial Accounts)",
        pii_type="ABA_ROUTING_NUMBER",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.ABA_ROUTING_NUMBER,
        azure_enum=AzureDetectionType.ABA_ROUTING_NUMBER,
        aws_enum=AWSComprehendPIIType.ABA_ROUTING_NUMBER,
    ),
    "INTERNATIONAL_BANKING_ACCOUNT_NUMBER": PIIMapping(
        information_type="International Banking Account Number (Financial Accounts)",
        pii_type="INTERNATIONAL_BANKING_ACCOUNT_NUMBER",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.INTERNATIONAL_BANKING_ACCOUNT_NUMBER,
        azure_enum=AzureDetectionType.INTERNATIONAL_BANKING_ACCOUNT_NUMBER,
        aws_enum=AWSComprehendPIIType.INTERNATIONAL_BANKING_ACCOUNT_NUMBER,
    ),
    "US_BANK_ACCOUNT_NUMBER": PIIMapping(
        information_type="United States Bank Account Number (Financial Accounts)",
        pii_type="US_BANK_ACCOUNT_NUMBER",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.US_BANK_ACCOUNT_NUMBER,
        azure_enum=AzureDetectionType.US_BANK_ACCOUNT_NUMBER,
        aws_enum=AWSComprehendPIIType.US_BANK_ACCOUNT_NUMBER,
    ),
    "DIGITAL_SIGNATURE": PIIMapping(
        information_type="Digital Signature",
        pii_type="DIGITAL_SIGNATURE",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct digital signature type
        azure_enum=None,  # Azure doesn't have a direct digital signature type
        aws_enum=None,  # AWS doesn't have a direct digital signature type
    ),
    "MEDICAL_HISTORY": PIIMapping(
        information_type="Medical History",
        pii_type="MEDICAL_HISTORY",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct medical history type
        azure_enum=None,  # Azure doesn't have a direct medical history type
        aws_enum=None,  # AWS doesn't have a direct medical history type
    ),
    "DNA_PROFILE": PIIMapping(
        information_type="DNA Profile",
        pii_type="DNA_PROFILE",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct DNA profile type
        azure_enum=None,  # Azure doesn't have a direct DNA profile type
        aws_enum=None,  # AWS doesn't have a direct DNA profile type
    ),
    "FINGERPRINT": PIIMapping(
        information_type="Fingerprint",
        pii_type="FINGERPRINT",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=None,  # Presidio doesn't have a direct fingerprint type
        azure_enum=None,  # Azure doesn't have a direct fingerprint type
        aws_enum=None,  # AWS doesn't have a direct fingerprint type
    ),
    "HOME_ADDRESS": PIIMapping(
        information_type="Home Address",
        pii_type="HOME_ADDRESS",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=None,  # Presidio doesn't have a direct home address type
        azure_enum=None,  # Azure doesn't have a direct home address type
        aws_enum=None,  # AWS doesn't have a direct home address type
    ),
    "US_SOCIAL_SECURITY_NUMBER": PIIMapping(
        information_type="Social Security Number",
        pii_type="US_SOCIAL_SECURITY_NUMBER",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.US_SOCIAL_SECURITY_NUMBER,
        azure_enum=AzureDetectionType.US_SOCIAL_SECURITY_NUMBER,
        aws_enum=AWSComprehendPIIType.US_SOCIAL_SECURITY_NUMBER,
    ),
    "LOCATION": PIIMapping(
        information_type="GPS Location",
        pii_type="LOCATION",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=MSFTPresidioPIIType.LOCATION,
        azure_enum=None,  # Azure doesn't have a direct location type
        aws_enum=None,  # AWS doesn't have a direct location type
    ),
    "SECURITY_ACCESS_CODES": PIIMapping(
        information_type="Security/Access Codes",
        pii_type="SECURITY_ACCESS_CODES",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct security access codes type
        azure_enum=None,  # Azure doesn't have a direct security access codes type
        aws_enum=None,  # AWS doesn't have a direct security access codes type
    ),
    "PASSWORD": PIIMapping(
        information_type="Passwords",
        pii_type="PASSWORD",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct password type
        azure_enum=None,  # Azure doesn't have a direct password type
        aws_enum=AWSComprehendPIIType.PASSWORD,
    ),
    "HEALTH_INSURANCE_ID": PIIMapping(
        information_type="Health Insurance ID",
        pii_type="HEALTH_INSURANCE_ID",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.NOT_MENTIONED,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=None,  # Presidio doesn't have a direct health insurance type
        azure_enum=None,  # Azure doesn't have a direct health insurance type
        aws_enum=None,  # AWS doesn't have a direct health insurance type
    ),
    "US_PASSPORT_NUMBER": PIIMapping(
        information_type="Passport Number",
        pii_type="US_PASSPORT_NUMBER",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.US_PASSPORT_NUMBER,
        azure_enum=AzureDetectionType.USUK_PASSPORT_NUMBER,
        aws_enum=AWSComprehendPIIType.US_PASSPORT_NUMBER,
    ),
    "AGE": PIIMapping(
        information_type="Age",
        pii_type="AGE",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=MSFTPresidioPIIType.AGE,
        azure_enum=AzureDetectionType.AGE,
        aws_enum=AWSComprehendPIIType.AGE,
    ),
    "PERSON": PIIMapping(
        information_type="Person",
        pii_type="PERSON",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.PERSON,
        azure_enum=AzureDetectionType.PERSON,
        aws_enum=AWSComprehendPIIType.PERSON,
    ),
    "CRYPTO": PIIMapping(
        information_type="Crypto (Financial Accounts)",
        pii_type="CRYPTO",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=MSFTPresidioPIIType.CRYPTO,
        azure_enum=None,  # Azure doesn't have a direct crypto type
        aws_enum=AWSComprehendPIIType.CRYPTO,
    ),
    "URL": PIIMapping(
        information_type="URL",
        pii_type="URL",
        cluster_membership_type=ClusterMembershipType.COMMUNITY_INTERACTION,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=MSFTPresidioPIIType.URL,
        azure_enum=AzureDetectionType.URL,
        aws_enum=AWSComprehendPIIType.URL,
    ),
    "DATE_TIME": PIIMapping(
        information_type="Date",
        pii_type="DATE_TIME",
        cluster_membership_type=ClusterMembershipType.BASIC_DEMOGRAPHICS,
        nist_category=NISTCategory.LINKABLE,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=MSFTPresidioPIIType.DATE_TIME,
        azure_enum=AzureDetectionType.DATE,
        aws_enum=AWSComprehendPIIType.DATE,
    ),
    "MEDICAL_LICENSE": PIIMapping(
        information_type="Medical License",
        pii_type="MEDICAL_LICENSE",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.NON_PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.MEDICAL_LICENSE,
        azure_enum=None,  # Azure doesn't have a direct medical license type
        aws_enum=None,  # AWS doesn't have a direct medical license type
    ),
    "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION": PIIMapping(
        information_type="United States Individual Taxpayer Identification",
        pii_type="US_INDIVIDUAL_TAXPAYER_IDENTIFICATION",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.US_INDIVIDUAL_TAXPAYER_IDENTIFICATION,
        azure_enum=AzureDetectionType.US_INDIVIDUAL_TAXPAYER_IDENTIFICATION,
        aws_enum=AWSComprehendPIIType.US_INDIVIDUAL_TAXPAYER_IDENTIFICATION,
    ),
    "AU_BUSINESS_NUMBER": PIIMapping(
        information_type="Australian Business Number",
        pii_type="AU_BUSINESS_NUMBER",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.AU_BUSINESS_NUMBER,
        azure_enum=AzureDetectionType.AU_BUSINESS_NUMBER,
        aws_enum=None,  # AWS doesn't have Australian business number types
    ),
    "AU_COMPANY_NUMBER": PIIMapping(
        information_type="Australian Company Number",
        pii_type="AU_COMPANY_NUMBER",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.AU_COMPANY_NUMBER,
        azure_enum=AzureDetectionType.AU_COMPANY_NUMBER,
        aws_enum=None,  # AWS doesn't have Australian company number types
    ),
    "AU_MEDICAL_ACCOUNT_NUMBER": PIIMapping(
        information_type="Australian Medicare Number",
        pii_type="AU_MEDICAL_ACCOUNT_NUMBER",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.AU_MEDICAL_ACCOUNT_NUMBER,
        azure_enum=AzureDetectionType.AU_MEDICAL_ACCOUNT_NUMBER,
        aws_enum=None,  # AWS doesn't have a direct AU medical account type
    ),
    "AU_TAX_FILE_NUMBER": PIIMapping(
        information_type="Australian Tax File Number",
        pii_type="AU_TAX_FILE_NUMBER",
        cluster_membership_type=ClusterMembershipType.SECURE_IDENTIFIERS,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.STAND_ALONE_PII,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_THREE,
        presidio_enum=MSFTPresidioPIIType.AU_TAX_FILE_NUMBER,
        azure_enum=AzureDetectionType.AU_TAX_FILE_NUMBER,
        aws_enum=None,  # AWS doesn't have a direct AU tax file type
    ),
    "SWIFT_CODE": PIIMapping(
        information_type="Swift Code (Financial)",
        pii_type="SWIFT_CODE",
        cluster_membership_type=ClusterMembershipType.FINANCIAL_INFORMATION,
        nist_category=NISTCategory.DIRECTLY_PII,
        dhs_category=DHSCategory.LINKABLE,
        hipaa_category=HIPAACategory.PHI,
        risk_level=RiskLevel.LEVEL_TWO,
        presidio_enum=None,  # Presidio doesn't have a direct SWIFT code type
        azure_enum=AzureDetectionType.SWIFT_CODE,
        aws_enum=AWSComprehendPIIType.SWIFT_CODE,
    ),
}


def get_pii_mapping(pii_type: str) -> PIIMapping:
    """
    Get PII mapping by PII type

    @param pii_type: The PII type to look up
    @return: PIIMapping object
    @raises: KeyError if PII type not found
    """
    return PII_TYPE_MAPPINGS[pii_type]


def get_all_pii_types() -> list:
    """
    Get all available PII types

    @return: List of all PII types
    """
    return list(PII_TYPE_MAPPINGS.keys())


def get_pii_types_by_risk_level(risk_level: RiskLevel) -> list:
    """
    Get PII types by risk level

    @param risk_level: The risk level to filter by
    @return: List of PII types with the specified risk level
    """
    return [
        pii_type
        for pii_type, mapping in PII_TYPE_MAPPINGS.items()
        if mapping.risk_level == risk_level
    ]


def get_pii_types_by_hipaa_category(hipaa_category: HIPAACategory) -> list:
    """
    Get PII types by HIPAA category

    @param hipaa_category: The HIPAA category to filter by
    @return: List of PII types with the specified HIPAA category
    """
    return [
        pii_type
        for pii_type, mapping in PII_TYPE_MAPPINGS.items()
        if mapping.hipaa_category == hipaa_category
    ]
