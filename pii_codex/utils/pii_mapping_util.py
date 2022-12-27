# pylint: disable=broad-except, unused-variable
from typing import Optional

from pii_codex.models.aws_pii import AWSComprehendPIIType
from pii_codex.models.azure_pii import AzurePIIType
from pii_codex.models.common import (
    RiskLevel,
    ClusterMembershipType,
    HIPAACategory,
    DHSCategory,
    NISTCategory,
    PIIType,
    MetadataType,
    RiskLevelDefinition,
)
from pii_codex.models.analysis import RiskAssessment
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType

from pii_codex.utils.file_util import open_pii_type_mapping_csv


class PIIMapper:
    def __init__(self):
        self._pii_mapping_data_frame = open_pii_type_mapping_csv("v1")

    def map_pii_type(self, pii_type: str) -> RiskAssessment:
        """
        Maps the PII Type to a full RiskAssessment including categories it belongs to, risk level, and
        its location in the text.

        @param pii_type:
        @return:
        """

        information_detail_lookup = self._pii_mapping_data_frame[
            self._pii_mapping_data_frame.PII_Type == pii_type
        ]

        # Retrieve the risk_level name by the value of the risk definition enum entry
        if information_detail_lookup.empty:
            raise Exception(
                f"An error occurred while processing the detected entity {pii_type}"
            )

        risk_level_definition = RiskLevelDefinition(
            information_detail_lookup.Risk_Level.item()
        )

        return RiskAssessment(
            pii_type_detected=pii_type,
            risk_level=RiskLevel[risk_level_definition.name].value,
            risk_level_definition=risk_level_definition.value,
            cluster_membership_type=ClusterMembershipType(
                information_detail_lookup.Cluster_Membership_Type.item()
            ).value,
            hipaa_category=HIPAACategory[
                information_detail_lookup.HIPAA_Protected_Health_Information_Category.item()
            ].value,
            dhs_category=DHSCategory(
                information_detail_lookup.DHS_Category.item()
            ).value,
            nist_category=NISTCategory(
                information_detail_lookup.NIST_Category.item()
            ).value,
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
    def convert_common_pii_to_azure_pii_type(cls, pii_type: PIIType) -> AzurePIIType:
        """
        Converts a common PII Type to an Azure PII Type
        @param pii_type:
        @return:
        """
        try:
            return AzurePIIType[pii_type.name]
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
            if pii_type == AzurePIIType.USUK_PASSPORT_NUMBER.value:
                # Special case, map to USUK for all US and UK Passport types
                return PIIType.US_PASSPORT_NUMBER

            return PIIType[AzurePIIType(pii_type).name]
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
            return PIIType[MSFTPresidioPIIType(pii_type).name]
        except Exception as ex:
            raise Exception(
                "The current version does not support this PII Type conversion."
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
