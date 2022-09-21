import pandas as pd
from assertpy import assert_that
import pytest

from pii_codex.models.common import (
    PIIType,
    ClusterMembershipType,
    DHSCategory,
    NISTCategory,
    HIPAACategory,
)
from pii_codex.utils.pii_mapping_util import (
    open_pii_type_mapping_csv,
    open_pii_type_mapping_json,
    convert_pii_type_mapping_csv_to_json,
    delete_mapping_file,
    delete_mapping_folder,
    map_pii_type,
)


class TestPIIMappingUtil:

    # region PII MAPPING FUNCTIONS
    @pytest.mark.parametrize(
        "pii_type",
        [pii_type.name for pii_type in PIIType],
    )
    def test_map_pii_type(self, pii_type):
        if pii_type is not PIIType.DOCUMENTS.name:
            mapped_pii = map_pii_type(pii_type)
            assert_that(mapped_pii.risk_level.value).is_greater_than(1)
            assert_that(
                isinstance(mapped_pii.cluster_membership_type, ClusterMembershipType)
            ).is_true()
            assert_that(isinstance(mapped_pii.dhs_category, DHSCategory)).is_true()
            assert_that(isinstance(mapped_pii.nist_category, NISTCategory)).is_true()
            assert_that(isinstance(mapped_pii.hipaa_category, HIPAACategory)).is_true()

    # endregion

    # region MAPPING DATA FILE FUNCTIONS

    def test_open_mappings_csv_v1(self):
        csv_file_dataframe = open_pii_type_mapping_csv("v1")

        assert_that(csv_file_dataframe).is_not_none()
        assert_that(isinstance(csv_file_dataframe, pd.DataFrame)).is_true()

    def test_open_mappings_json_v1(self):
        json_file_dataframe = open_pii_type_mapping_json("v1")

        assert_that(json_file_dataframe).is_not_none()
        assert_that(isinstance(json_file_dataframe, pd.DataFrame)).is_true()

    def test_mappings_json_create_delete(self):
        new_version = "test"
        csv_file_dataframe = open_pii_type_mapping_csv("v1")

        # Create the new version
        convert_pii_type_mapping_csv_to_json(
            data_frame=csv_file_dataframe, mapping_file_version=new_version
        )

        json_file_dataframe = open_pii_type_mapping_json(
            mapping_file_version=new_version, mapping_file_name="pii_type_mappings"
        )

        # Assert file exists
        assert_that(json_file_dataframe).is_not_none()
        assert_that(isinstance(json_file_dataframe, pd.DataFrame)).is_true()

        # Delete file and folder
        delete_mapping_file(
            mapping_file_version=new_version, json_file_name="pii_type_mappings"
        )

        delete_mapping_folder(mapping_file_version=new_version)
        # endregion
