# New Project Setup
See README.md for step-by-step details on installing the pii-codex package as an import.

Video Demo of package import and usage:
<div align="center">

[![PII-Codex Video Demo](https://img.youtube.com/vi/51TP2I5SNlo/0.jpg)](https://youtu.be/51TP2I5SNlo)

</div>

`Note: This video has no sound, it just shows steps taken to install the package and use it in a file.`

# Local Repo Setup
For those contributing or modifying the source, use the following to set up locally.

## Environment Config
You'll need Python (^3.11) and `uv` configured on your machine. Once those are configured, create a virtual
environment and install dependencies.

```bash
uv sync
```

Installing dependencies will vary by usage. For those in need of the PII-Codex integration of the MSFT Presidio Analyzer, it is recommended to install the `detections` extras:

```bash
uv sync --extra detections
```

As part of the `detections` extras installation, the download for the `en_core_web_lg` spaCy model will be enabled on first use of the `PresidioPIIAnalyzer()`. If more language support is needed, you'll need to download it separately. Reference <a href="https://github.com/explosion/spacy-models/releases?q=en_core_web_lg&expanded=true">explosion/spacy-models</a>.

Depending on your setup and need, you may need to add the virtual environment to Jupyter. You may do so with the following command:

```bash
make jupyter.attach.venv
```