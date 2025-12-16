# pylint: disable=broad-except, line-too-long
from assertpy import assert_that
import pytest

from pii_codex.config import PII_MAPPER
from pii_codex.models.aws_pii import AWSComprehendPIIType
from pii_codex.models.azure_pii import AzureDetectionType
from pii_codex.models.common import (
    PIIType,
    ClusterMembershipType,
    DHSCategory,
    NISTCategory,
    HIPAACategory,
    RiskLevel,
    RiskLevelDefinition,
)
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.services.pii_type_mappings import PII_TYPE_MAPPINGS
import pii_codex.utils.pii_mapping_util as util_module


class TestPIIMappingUtil:
    # region PII MAPPING AND CONVERSION FUNCTIONS
    @pytest.mark.parametrize(
        "pii_type",
        [pii_type.name for pii_type in PIIType],
    )
    def test_map_pii_type(self, pii_type):
        """
        Requires the type mapping to be in the associated version file in pii_codex/data/
        """
        if pii_type is not PIIType.DOCUMENTS.name:
            mapped_pii = PII_MAPPER.map_pii_type(pii_type)
            assert_that(mapped_pii.risk_level).is_greater_than(1)
            assert_that(
                isinstance(
                    ClusterMembershipType(mapped_pii.cluster_membership_type),
                    ClusterMembershipType,
                )
            ).is_true()
            assert_that(
                isinstance(DHSCategory(mapped_pii.dhs_category), DHSCategory)
            ).is_true()
            assert_that(
                isinstance(NISTCategory(mapped_pii.nist_category), NISTCategory)
            ).is_true()
            assert_that(
                isinstance(HIPAACategory(mapped_pii.hipaa_category), HIPAACategory)
            ).is_true()

    @pytest.mark.parametrize(
        "pii_type",
        PIIType,
    )
    def test_convert_common_pii_to_msft_presidio_type(self, pii_type):
        try:
            converted_pii = PII_MAPPER.convert_common_pii_to_msft_presidio_type(
                pii_type
            )
            assert_that(isinstance(converted_pii, MSFTPresidioPIIType)).is_true()
        except Exception as ex:
            assert_that(ex.args[0]).contains(
                "The current version does not support this PII Type conversion."
            )

    @pytest.mark.parametrize(
        "pii_type",
        PIIType,
    )
    def test_convert_common_pii_to_azure_pii_type(self, pii_type):
        try:
            converted_pii = PII_MAPPER.convert_common_pii_to_azure_pii_type(pii_type)
            assert_that(isinstance(converted_pii, AzureDetectionType)).is_true()
        except Exception as ex:
            assert_that(ex.args[0]).contains(
                "The current version does not support this PII Type conversion."
            )

    @pytest.mark.parametrize(
        "pii_type",
        AzureDetectionType,
    )
    def test_convert_azure_pii_to_common_pii_type(self, pii_type):
        try:
            converted_pii = PII_MAPPER.convert_azure_pii_to_common_pii_type(pii_type)
            assert_that(isinstance(converted_pii, PIIType)).is_true()
        except Exception as ex:
            assert_that(ex.args[0]).contains(
                "The current version does not support this PII Type conversion."
            )

    @pytest.mark.parametrize(
        "pii_type",
        AWSComprehendPIIType,
    )
    def test_convert_aws_pii_to_common_pii_type(self, pii_type):
        try:
            converted_pii = PII_MAPPER.convert_aws_comprehend_pii_to_common_pii_type(
                pii_type
            )
            assert_that(isinstance(converted_pii, PIIType)).is_true()
        except Exception as ex:
            assert_that(ex.args[0]).contains(
                "The current version does not support this PII Type conversion."
            )

    @pytest.mark.parametrize(
        "pii_type",
        PIIType,
    )
    def test_convert_common_pii_to_aws_comprehend_type(self, pii_type):
        try:
            converted_pii = PII_MAPPER.convert_common_pii_to_aws_comprehend_type(
                pii_type
            )
            assert_that(isinstance(converted_pii, AWSComprehendPIIType)).is_true()
        except Exception as ex:
            assert_that(ex.args[0]).contains(
                "The current version does not support this PII Type conversion."
            )

    def test_convert_metadata_to_pii_failure(self):
        with pytest.raises(Exception) as execinfo:
            PII_MAPPER.convert_metadata_type_to_common_pii_type("other_type")

        assert_that(str(execinfo.value)).contains(
            "The current version does not support this Metadata to PII Type conversion."
        )

    def test_convert_msft_presidio_pii_to_common_pii_type_failure(self):
        with pytest.raises(Exception) as execinfo:
            PII_MAPPER.convert_msft_presidio_pii_to_common_pii_type("other_type")

        assert_that(str(execinfo.value)).contains(
            "The current version does not support this PII Type conversion: other_type. Error: 'other_type' is not a valid MSFTPresidioPIIType"
        )

    def test_pii_mapping_enum_consistency(self):
        """Test that all PII mappings have consistent enum references"""
        for mapping in PII_TYPE_MAPPINGS.values():
            # Test that risk level mapping works correctly (it's an enum, not int)
            assert_that(mapping.risk_level).is_instance_of(RiskLevel)
            assert_that(mapping.risk_level.value).is_between(1, 3)

            # Test that cluster membership type is valid
            assert_that(mapping.cluster_membership_type).is_instance_of(
                ClusterMembershipType
            )

            # Test that categories are valid enum instances
            assert_that(mapping.nist_category).is_instance_of(NISTCategory)
            assert_that(mapping.dhs_category).is_instance_of(DHSCategory)
            assert_that(mapping.hipaa_category).is_instance_of(HIPAACategory)

            # Test that provider enums are either valid enum instances or None
            if mapping.presidio_enum is not None:
                assert_that(mapping.presidio_enum).is_instance_of(MSFTPresidioPIIType)
            if mapping.azure_enum is not None:
                assert_that(mapping.azure_enum).is_instance_of(AzureDetectionType)
            if mapping.aws_enum is not None:
                assert_that(mapping.aws_enum).is_instance_of(AWSComprehendPIIType)

    def test_risk_level_definition_mapping(self):
        """Test that risk level to definition mapping works correctly"""
        for pii_type in PII_TYPE_MAPPINGS:
            # Test that we can create a RiskAssessment without errors
            risk_assessment = PII_MAPPER.map_pii_type(pii_type)

            # Test that risk level definition is a valid string
            assert_that(risk_assessment.risk_level_definition).is_instance_of(str)

            # Test that risk level definition is one of the valid values
            valid_definitions = [level.value for level in RiskLevelDefinition]
            assert_that(
                risk_assessment.risk_level_definition in valid_definitions
            ).is_true()

            # Test that risk level is an integer
            assert_that(risk_assessment.risk_level).is_instance_of(int)
            assert_that(risk_assessment.risk_level).is_between(1, 3)

    def test_provider_enum_consistency(self):
        """Test that provider-specific enum mappings are consistent"""
        # Test some key mappings that should have all three providers
        key_mappings = [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "PERSON",
            "US_SOCIAL_SECURITY_NUMBER",
            "CREDIT_CARD_NUMBER",
        ]

        for pii_type in key_mappings:
            if pii_type in PII_TYPE_MAPPINGS:
                mapping = PII_TYPE_MAPPINGS[pii_type]

                # These should have all three provider enums
                assert_that(mapping.presidio_enum).is_not_none()
                assert_that(mapping.azure_enum).is_not_none()
                assert_that(mapping.aws_enum).is_not_none()

                # Test that the enum names are consistent
                if mapping.presidio_enum:
                    assert_that(mapping.presidio_enum.name).is_equal_to(pii_type)
                if mapping.azure_enum:
                    assert_that(mapping.azure_enum.name).is_equal_to(pii_type)
                if mapping.aws_enum:
                    # AWS might have different naming (e.g., CREDIT_DEBIT_NUMBER vs CREDIT_CARD_NUMBER)
                    assert_that(mapping.aws_enum.name).is_not_empty()

    def test_azure_usuk_passport_mapping(self):
        """Test the specific fix for US_PASSPORT_NUMBER -> USUK_PASSPORT_NUMBER"""
        us_passport_mapping = PII_TYPE_MAPPINGS.get("US_PASSPORT_NUMBER")
        assert_that(us_passport_mapping).is_not_none()

        if us_passport_mapping and us_passport_mapping.azure_enum:
            assert_that(us_passport_mapping.azure_enum.name).is_equal_to(
                "USUK_PASSPORT_NUMBER"
            )

    def test_aws_australian_types_none(self):
        """Test that AWS doesn't have Australian business/company types (set to None)"""
        au_business_mapping = PII_TYPE_MAPPINGS.get("AU_BUSINESS_NUMBER")
        au_company_mapping = PII_TYPE_MAPPINGS.get("AU_COMPANY_NUMBER")

        if au_business_mapping:
            assert_that(au_business_mapping.aws_enum).is_none()
        if au_company_mapping:
            assert_that(au_company_mapping.aws_enum).is_none()

    def test_no_csv_dependencies(self):
        """Test that we no longer have CSV file dependencies"""
        # Check that the module doesn't have pandas-related attributes
        assert_that(hasattr(util_module, "_pii_mapping_data_frame")).is_false()

        # Check that we're using the new mapping system (PII_MAPPER is imported from config)
        assert_that(PII_MAPPER).is_not_none()

        # Test that map_pii_type works without CSV
        result = PII_MAPPER.map_pii_type("EMAIL_ADDRESS")
        assert_that(result).is_not_none()
        assert_that(result.pii_type_detected).is_equal_to("EMAIL_ADDRESS")

    # endregion

    # CSV-related tests removed - no longer using CSV files
