# PII Codex 
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![License: Hippocratic 3.0](https://img.shields.io/badge/License-Hippocratic_3.0-lightgrey.svg)](https://firstdonoharm.dev)

The PII Codex project was built as a core part of an ongoing research effort in Personal Identifiable Information (PII) detection and risk assessment. There was a need to not only detect PII in unstructured text, but also identify its severity, associated categorizations in cybersecurity research and policy documentation, and provide a way for others in similar research efforts to reproduce or extend the research. PII Codex is a combination of systematic research, conceptual frameworks, and third-party open source software. The categorizations are directly influenced by the research by Milne et al. 2018 while the ranking is a result of category severities on the scale provided by Schwartz and Solove (2012) from Non-Identifiable, Semi-Identifiable, and Identifiable.  

## Local Setup
Install dependencies first. Virtual environment highly recommended.

```bash
python3 -m venv venv

. venv/bin/activate

make install
```

Depending on your setup, you may need to add the virtual environment to Jupyter. You may do so with the following command:
```bash
make jupyter.attach.venv
```

## Usage

### Import and Init
