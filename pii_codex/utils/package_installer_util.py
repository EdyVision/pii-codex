import subprocess
import sys


def install_spacy_package(package_name):
    subprocess.check_call([sys.executable, "-m", "spacy", "download", package_name])
