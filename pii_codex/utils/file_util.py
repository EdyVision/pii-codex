"""
File utils
"""

import json
import logging
import os
from pathlib import Path

dirname = os.path.dirname(__file__)


def get_relative_path(path_to_file: str):
    """
    Returns the file_path relative to the project

    @param path_to_file:
    @return:
    """
    filename = os.path.join(dirname, path_to_file)

    return Path(__file__).parent / filename


def write_json_file(folder_name: str, file_name: str, json_data: json):
    """
    Writes json file given json data, a folder name, and a file name.

    @param folder_name:
    @param file_name:
    @param json_data:
    """
    # Create a new directory because it does not exist
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

        logging.info(f"A new version directory has been created: {folder_name}")

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

        logging.info(f"The file {file_path} has been deleted")
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

        logging.info(f"The folder {folder_path} has been deleted")
    else:
        raise Exception(f"The folder {folder_path} does not exist")
