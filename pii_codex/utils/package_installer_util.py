import subprocess
import sys

# Wheel URL for fallback when "spacy download" fails (e.g. uv venv without pip)
SPACY_MODEL_URLS = {
    "en_core_web_lg": (
        "https://github.com/explosion/spacy-models/releases/download/"
        "en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl"
    ),
}


def install_spacy_package(package_name: str) -> None:
    """
    Installs missing spacy package (if found missing).
    Tries `spacy download` first; if that fails (e.g. no pip in uv venv), tries uv pip install with known wheel URL.
    """
    try:
        subprocess.check_call([sys.executable, "-m", "spacy", "download", package_name])
        return
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    url = SPACY_MODEL_URLS.get(package_name)
    if url is None:
        raise RuntimeError(
            f"Cannot install spacy model '{package_name}' automatically (no pip and no known URL). "
            f"Install it yourself: pip install {package_name}, or use a venv with pip."
        )
    subprocess.check_call(["uv", "pip", "install", "--python", sys.executable, url])
