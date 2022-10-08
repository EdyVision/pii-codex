# Local Repo Setup
For those contributing or modifying the source, use the following to set up locally.

## Environment Config
You'll need the Python (^3.9) and Poetry configured on your machine. Once those are configured, create a virtual
environment and install dependencies.

```bash
python3.9 -m venv venv

. venv/bin/activate

pip install --upgrade pip

make install
```

Installing dependencies will vary by usage. For those in need of the PII-Codex integration of the MSFT Presidio Analyzer, it is recommended to install the `detections` extras:

```bash
poetry install --extras="detections"
```

As part of the `detections` extras installation, the download for the `en_core_web_lg` spaCy model will be enabled on first use of the `PresidioPIIAnalyzer()`. If more language support is needed, you'll need to download it separately. Reference <a href="https://github.com/explosion/spacy-models/releases?q=en_core_web_lg&expanded=true">explosion/spacy-models</a>.

Depending on your setup and need, you may need to add the virtual environment to Jupyter. You may do so with the following command:

```bash
make jupyter.attach.venv
```