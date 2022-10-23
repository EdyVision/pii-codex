"""
File utils
"""
import json
import os
from pathlib import Path
import pandas as pd

from .logging import logger

dirname = os.path.dirname(__file__)


def get_relative_path(path_to_file: str):
    """
    Returns the file_path relative to the project

    @param path_to_file:
    @return:
    """
    filename = os.path.join(dirname, path_to_file)

    return Path(__file__).parent / filename


def write_json_file(folder_name: str, file_name: str, json_data):
    """
    Writes json file given json data, a folder name, and a file name.

    @param folder_name:
    @param file_name:
    @param json_data:
    """
    # Create a new directory because it does not exist
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

        logger.info(f"A new version directory has been created: {folder_name}")

    with open(file_name, "w", encoding="utf-8") as json_file:
        json.dump(
            json.loads(json_data),
            json_file,
            ensure_ascii=False,
            indent=4,
        )


def delete_file(
    file_path: str = "pii_type_mappings",
):
    """
    Deletes a version file if it exists

    @param file_path:
    @return:
    """

    # Delete file if it exists
    if os.path.exists(file_path):
        os.remove(file_path)

        logger.info(f"The file {file_path} has been deleted")
    else:
        raise Exception(f"The file {file_path} does not exist")


def delete_folder(
    folder_path: str,
):
    """
    Deletes a folder if it exists and nothing is within it

    @param folder_path:
    """

    # Delete folder if it exists
    if os.path.exists(folder_path):
        os.rmdir(folder_path)

        logger.info(f"The folder {folder_path} has been deleted")
    else:
        raise Exception(f"The folder {folder_path} does not exist")


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
