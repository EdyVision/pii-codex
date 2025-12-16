# pylint: disable=broad-except, unused-variable, no-else-return
from typing import Optional

from pii_codex.models.aws_pii import AWSComprehendPIIType
from pii_codex.models.azure_pii import AzureDetectionType
from pii_codex.models.common import (
    RiskLevel,
    PIIType,
    MetadataType,
    RiskLevelDefinition,
)
from pii_codex.models.analysis import RiskAssessment
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType

from pii_codex.services.pii_type_mappings import get_pii_mapping


class PIIMapper:
    """
    Class to map PII types listed as Common Types, Azure Types, AWS Comprehend Types, and Presidio Types
    """

    def __init__(self):
        # No need to load CSV anymore - using Python structure
        pass

    def map_pii_type(self, pii_type: str) -> RiskAssessment:
        """
        Maps the PII Type to a full RiskAssessment including categories it belongs to, risk level, and
        its location in the text. This cross-references some of the types listed by Milne et al. (2016)

        @param pii_type:
        @return:
        """

        try:
            mapping = get_pii_mapping(pii_type)

            # Get the risk level definition string based on the risk level
            risk_level_to_definition = {
                RiskLevel.LEVEL_ONE: RiskLevelDefinition.LEVEL_ONE.value,
                RiskLevel.LEVEL_TWO: RiskLevelDefinition.LEVEL_TWO.value,
                RiskLevel.LEVEL_THREE: RiskLevelDefinition.LEVEL_THREE.value,
            }
            risk_level_definition = risk_level_to_definition[mapping.risk_level]

            return RiskAssessment(
                pii_type_detected=pii_type,
                risk_level=mapping.risk_level.value,
                risk_level_definition=risk_level_definition,
                cluster_membership_type=mapping.cluster_membership_type.value,
                hipaa_category=mapping.hipaa_category.value,
                dhs_category=mapping.dhs_category.value,
                nist_category=mapping.nist_category.value,
            )
        except KeyError:
            raise Exception(
                f"An error occurred while processing the detected entity {pii_type}"
            )

    @classmethod
    def convert_common_pii_to_msft_presidio_type(
        cls, pii_type: PIIType
    ) -> MSFTPresidioPIIType:
        """
        Converts a common PII Type to a MSFT Presidio Type
        @param pii_type:
        @return:
        """

        try:
            converted_type = MSFTPresidioPIIType[pii_type.name]
        except Exception as ex:
            raise Exception(
                "The current version does not support this PII Type conversion."
            )

        return converted_type

    @classmethod
    def convert_common_pii_to_azure_pii_type(
        cls, pii_type: PIIType
    ) -> AzureDetectionType:
        """
        Converts a common PII Type to an Azure PII Type
        @param pii_type:
        @return:
        """
        try:
            return AzureDetectionType[pii_type.name]
        except Exception as ex:
            raise Exception(
                "The current version does not support this PII Type conversion."
            )

    @classmethod
    def convert_common_pii_to_aws_comprehend_type(
        cls,
        pii_type: PIIType,
    ) -> AWSComprehendPIIType:
        """
        Converts a common PII Type to an AWS PII Type
        @param pii_type:
        @return:
        """
        try:
            return AWSComprehendPIIType[pii_type.name]
        except Exception as ex:
            raise Exception(
                "The current version does not support this PII Type conversion."
            )

    @classmethod
    def convert_azure_pii_to_common_pii_type(cls, pii_type: str) -> PIIType:
        """
        Converts an Azure PII Type to a common PII Type
        @param pii_type:
        @return:
        """
        try:
            if pii_type == AzureDetectionType.USUK_PASSPORT_NUMBER.value:
                # Special case, map to USUK for all US and UK Passport types
                return PIIType.US_PASSPORT_NUMBER

            return PIIType[AzureDetectionType(pii_type).name]
        except Exception as ex:
            raise Exception(
                "The current version does not support this PII Type conversion."
            )

    @classmethod
    def convert_aws_comprehend_pii_to_common_pii_type(
        cls,
        pii_type: str,
    ) -> PIIType:
        """
        Converts an AWS PII Type to a common PII Type
        @param pii_type: str from AWS Comprehend (maps to value of AWSComprehendPIIType)
        @return:
        """
        try:
            return PIIType[AWSComprehendPIIType(pii_type).name]
        except Exception as ex:
            raise Exception(
                "The current version does not support this PII Type conversion."
            )

    @classmethod
    def convert_msft_presidio_pii_to_common_pii_type(
        cls,
        pii_type: str,
    ) -> PIIType:
        """
        Converts a Microsoft Presidio PII Type to a common PII Type
        @param pii_type: str from Presidio (maps to value of PIIType)
        @return:
        """
        try:
            # Handle specific cases where Presidio returns different values than enum names
            if pii_type == "US_SSN":
                return PIIType.US_SOCIAL_SECURITY_NUMBER
            if pii_type == "US_BANK_NUMBER":
                return PIIType.US_BANK_ACCOUNT_NUMBER
            if pii_type == "AU_MEDICARE":
                return PIIType.AU_MEDICAL_ACCOUNT_NUMBER
            if pii_type == "DATE":
                return PIIType.DATE_TIME

            # For everything else, use the original approach that was working
            return PIIType[MSFTPresidioPIIType(pii_type).name]

        except Exception as ex:
            raise Exception(
                f"The current version does not support this PII Type conversion: {pii_type}. Error: {str(ex)}"
            )

    @classmethod
    def convert_metadata_type_to_common_pii_type(
        cls, metadata_type: str
    ) -> Optional[PIIType]:
        """
        Converts metadata type str entry to common PII type
        @param metadata_type:
        @return: PIIType
        """

        try:
            if metadata_type.lower() == "name":
                return PIIType.PERSON

            if metadata_type.lower() == "user_id":
                # If dealing with public data, user_id can be used to pull down
                # social network profile
                return PIIType.SOCIAL_NETWORK_PROFILE

            return PIIType[MetadataType(metadata_type.lower()).name]
        except Exception as ex:
            raise Exception(
                "The current version does not support this Metadata to PII Type conversion."
            )
