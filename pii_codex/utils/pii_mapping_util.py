# pylint: disable=broad-except, unused-variable
import pandas as pd

from pii_codex.models.aws_pii import AWSComprehendPIIType
from pii_codex.models.azure_pii import AzurePIIType
from pii_codex.models.common import (
    RiskLevel,
    RiskLevelDefinition,
    ClusterMembershipType,
    HIPAACategory,
    DHSCategory,
    NISTCategory,
    PIIType,
)
from pii_codex.models.analysis import RiskAssessment
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.utils.file_util import (
    delete_folder,
    delete_file,
    write_json_file,
    get_relative_path,
)

# region PII MAPPING AND RATING UTILS


def map_pii_type(pii_type: str) -> RiskAssessment:
    """
    Maps the PII Type to a full RiskAssessment including categories it belongs to, risk level, and
    its location in the text.

    @param pii_type:
    @return:
    """
    pii_data_frame = open_pii_type_mapping_json("v1")

    information_detail_lookup = pii_data_frame[pii_data_frame.PII_Type == pii_type]

    # if not information_detail_lookup:
    #     raise Exception("PII type not found")

    # Retrieve the risk_level name by the value of the risk definition enum entry
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
        dhs_category=DHSCategory(information_detail_lookup.DHS_Category.item()).value,
        nist_category=NISTCategory(
            information_detail_lookup.NIST_Category.item()
        ).value,
    )


def convert_common_pii_to_msft_presidio_type(pii_type: PIIType) -> MSFTPresidioPIIType:
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


def convert_common_pii_to_azure_pii_type(pii_type: PIIType) -> AzurePIIType:
    """
    Converts a common PII Type to an Azure PII Type
    @param pii_type:
    @return:
    """
    try:
        converted_type = AzurePIIType[pii_type.name]
    except Exception as ex:
        raise Exception(
            "The current version does not support this PII Type conversion."
        )

    return converted_type


def convert_common_pii_to_aws_comprehend_type(
    pii_type: PIIType,
) -> AWSComprehendPIIType:
    """
    Converts a common PII Type to an AWS PII Type
    @param pii_type:
    @return:
    """
    try:
        converted_type = AWSComprehendPIIType[pii_type.name]
    except Exception as ex:
        raise Exception(
            "The current version does not support this PII Type conversion."
        )

    return converted_type


def convert_azure_pii_to_common_pii_type(pii_type: str) -> PIIType:
    """
    Converts an Azure PII Type to a common PII Type
    @param pii_type:
    @return:
    """
    try:
        converted_type = PIIType[AzurePIIType(pii_type).name]
    except Exception as ex:
        raise Exception(
            "The current version does not support this PII Type conversion."
        )

    return converted_type


def convert_aws_comprehend_pii_to_common_pii_type(
    pii_type: str,
) -> PIIType:
    """
    Converts an AWS PII Type to a common PII Type
    @param pii_type: str from AWS Comprehend (maps to value of AWSComprehendPIIType)
    @return:
    """
    try:
        if pii_type == AWSComprehendPIIType.US_PASSPORT_NUMBER.value:
            # Special case, map to USUK for all US and UK Passport types
            converted_type = PIIType.USUK_PASSPORT_NUMBER
        else:
            converted_type = PIIType[AWSComprehendPIIType(pii_type).name]
    except Exception as ex:
        raise Exception(
            "The current version does not support this PII Type conversion."
        )

    return converted_type


def convert_msft_presidio_pii_to_common_pii_type(
    pii_type: str,
) -> PIIType:
    """
    Converts a Microsoft Presidio PII Type to a common PII Type
    @param pii_type: str from Presidio (maps to value of PIIType)
    @return:
    """
    try:
        if pii_type == MSFTPresidioPIIType.US_PASSPORT_NUMBER.value:
            # Special case, map to USUK for all US and UK Passport types
            converted_type = PIIType.USUK_PASSPORT_NUMBER
        else:
            converted_type = PIIType[MSFTPresidioPIIType(pii_type).name]
    except Exception as ex:
        raise Exception(
            "The current version does not support this PII Type conversion."
        )

    return converted_type


# endregion


# region MAPPING FILE UTILS


def open_pii_type_mapping_csv(
    mapping_file_version: str = "v1", mapping_file_name: str = "pii_type_mappings"
):
    """

    @param mapping_file_name:
    @param mapping_file_version:
    """
    file_path = get_relative_path(
        f"../data/{mapping_file_version}/{mapping_file_name}.csv"
    )
    with file_path.open() as file:
        return pd.read_csv(file)


def open_pii_type_mapping_json(
    mapping_file_version: str = "v1", mapping_file_name: str = "pii_type_mappings"
):
    """

    @param mapping_file_name:
    @param mapping_file_version:
    @return:
    """

    file_path = get_relative_path(
        f"../data/{mapping_file_version}/{mapping_file_name}.json"
    )
    with file_path.open() as file:
        json_file_dataframe = pd.read_json(file)
        json_file_dataframe.drop("index", axis=1, inplace=True)

        return json_file_dataframe


def convert_pii_type_mapping_csv_to_json(
    data_frame: pd.DataFrame,
    mapping_file_version: str = "v1",
    json_file_name: str = "pii_type_mappings",
):
    """
    Writes JSON mapping file given a dataframe. Used primarily to update data folder with new versions

    @param data_frame:
    @param mapping_file_version:
    @param json_file_name:
    """

    folder_path = get_relative_path(f"../data/{mapping_file_version}")

    file_path = get_relative_path(
        f"../data/{mapping_file_version}/{json_file_name}.json"
    )

    write_json_file(
        folder_name=folder_path,
        file_name=file_path,
        json_data=data_frame.reset_index().to_json(orient="records"),
    )


def delete_json_mapping_file(
    mapping_file_version: str = "v1",
    json_file_name: str = "pii_type_mappings",
):
    """
    Deletes a version file within a data version folder

    @param mapping_file_version:
    @param json_file_name:
    """

    file_path = get_relative_path(
        f"../data/{mapping_file_version}/{json_file_name}.json"
    )

    delete_file(file_path)


def delete_json_mapping_folder(
    mapping_file_version: str,
):
    """
    Deletes a version folder within the data folder

    @param mapping_file_version:
    """

    folder_path = get_relative_path(f"../data/{mapping_file_version}")
    delete_folder(folder_path)


# endregion
