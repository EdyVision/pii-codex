# PII Codex 
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
![](https://img.shields.io/badge/code%20style-black-000000.svg)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![License: Hippocratic 3.0](https://img.shields.io/badge/License-Hippocratic_3.0-green.svg)](https://firstdonoharm.dev)
[![Coverage](https://github.com/EdyVision/pii-codex/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/EdyVision/pii-codex/actions/workflows/test.yml?branch=main)
[![Python 3.9](https://img.shields.io/badge/python-3.9-blue.svg)](https://www.python.org/downloads/release/python-390/)

The PII Codex project was built as a core part of an ongoing research effort in Personal Identifiable Information (PII) detection and risk assessment. There was a need to not only detect PII in unstructured text, but also identify its severity, associated categorizations in cybersecurity research and policy documentation, and provide a way for others in similar research efforts to reproduce or extend the research. PII Codex is a combination of systematic research, conceptual frameworks, third-party open source software, and cloud service provider integrations. The categorizations are directly influenced by the research by Milne et al. (2016) while the ranking is a result of category severities on the scale provided by Schwartz and Solove (2012) from Non-Identifiable, Semi-Identifiable, and Identifiable.  

## Local Setup
Install dependencies first. A virtual environment highly recommended.

```bash
python3 -m venv venv

. venv/bin/activate

pip install --upgrade pip

make install
```

Depending on your setup, you may need to add the virtual environment to Jupyter. You may do so with the following command:
```bash
make jupyter.attach.venv
```

## Importing
The repository releases are hosted on both GitHub and PyPi. To import from PyPi, use the following in your requirements.txt or pyproject.toml file:

```
pii-codex==0.x.x
```

To import from PyPi, use the following in your requirements.txt or pyproject.toml file:

``` 
git+ssh://git.github.com/EdyVision/pii-codex@v0.x.x#egg=pii-codex
```

## Usage
Check out the respect documentation for guidance on using PII-Codex.

| Topic                       | Document                                                                                            | Description                                                                              |
|-----------------------------|-----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| PII Type Mappings           | [PII Mappings](https://github.com/EdyVision/pii-codex/docs/MAPPING.MD)                              | Overview of how to perform mappings between PII types and how to review store PII types. |
| PII Detections and Analysis | [PII Detection and Analysis](https://github.com/EdyVision/pii-codex/docs/DETECTION_AND_ANALYSIS.MD) | Overview of how to detect and analyze strings                                            |


## Community Guidelines
### Contributions
In general, you can contribute to this project by creating issues. You are also welcome to contribute to the source code directly by forking the project, modifying the code, and creating pull requests. Please use clear and organized descriptions when creating issues and pull requests and leverage the templates when possible.

### Bug Report and Support Requests
You can use issues to report bugs and seek support. Before creating any new issues, please check for similar ones in the issue list first.

## Attributions
This project benefited greatly from a number of PII research works like that from Milne et al (2016), Schwartz and Solove (2012), and the documentation by NIST, DHS, and HIPAA. A special thanks to all the open source projects, and frameworks that made the setup and organization of this project much easier like Poetry, Microsoft Presidio, spaCy, Jupyter, and several others.
