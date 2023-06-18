import subprocess
import sys


def install_spacy_package(package_name):
    """
    Installs missing spacy package (if found missing)
    @param package_name:
    @return:
    """
    subprocess.check_call([sys.executable, "-m", "spacy", "download", package_name])
