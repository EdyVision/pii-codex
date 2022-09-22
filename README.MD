# PII Codex 
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![Python 3.9](https://img.shields.io/badge/python-3.9-blue.svg)](https://www.python.org/downloads/release/python-390/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![License: Hippocratic 3.0](https://img.shields.io/badge/License-Hippocratic_3.0-green.svg)](https://firstdonoharm.dev)

The PII Codex project was built as a core part of an ongoing research effort in Personal Identifiable Information (PII) detection and risk assessment. There was a need to not only detect PII in unstructured text, but also identify its severity, associated categorizations in cybersecurity research and policy documentation, and provide a way for others in similar research efforts to reproduce or extend the research. PII Codex is a combination of systematic research, conceptual frameworks, third-party open source software, and cloud service provider integrations. The categorizations are directly influenced by the research by Milne et al. 2018 while the ranking is a result of category severities on the scale provided by Schwartz and Solove (2012) from Non-Identifiable, Semi-Identifiable, and Identifiable.  

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

## Importing
The repository releases are hosted on both GitHub and Pypi. To import from Pypi, use the following in your requirements.txt or pyproject.toml file:

```
pii-codex==0.x.x
```

To import from Pypi, use the following in your requirements.txt or pyproject.toml file:

``` 
git+ssh://git.github.com/EdyVision/pii-codex@v0.x.x#egg=pii-codex
```

## Usage

### Enums and PII Mapping Util
The PII Codex has a number of enums to help with the definitions and labeling of PII, their categories, and their severity rankings across modules. At this time, only AWS Comprehend, Microsoft Presidio, and Microsoft Azure PII entity types are mapped to using the common PII types listing.

Selecting a PII type from the common PII type listing:

```python
from pii_codex.models.common import PIIType
PIIType.EMAIL_ADDRESS # Selecting a single common PIIType 
PIIType.EMAIL_ADDRESS.name # The name of the enum entry
PIIType.EMAIL_ADDRESS.value # The String value of the enum entry
```

Iterating through all common types supported:

```python
from pii_codex.models.common import PIIType
pii_types = [pii_type.name for pii_type in PIIType]
print(pii_types)
```

Each module or cloud resource will have its own string labeling for the PII Type. It is sometimes required to map to that string value in order to properly parse out a PII detection or to initialize an analyzer. To map to a different PII type (if supported with the version, using MSFT Presidio for example):

```python
from pii_codex.models.common import PIIType
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType

presidio_pii_type = MSFTPresidioPIIType[PIIType.EMAIL_ADDRESS.name] # MSFT Presidio enum entry

print("Presidio Enum Type Name for Email: ", presidio_pii_type.name)
print("Presidio Enum Type Value for Email: ", presidio_pii_type.value)
```

Using the built-in mapper can be a help, just pass in the mapping you'd like to perform and it'll provide you with the enum name and the enum type entry. If it is not supported, you'll be supplied with the error instead.

```python

# write up how to use the built in mapper
```

### PII Detection Service
In the case that you are not bringing your own detection service, there is a detection service built into PII Codex that provides flexibility in analyzer type. The following are supported PII detectors bundled into the service that are either open source or offered by a cloud service provider:

<ol>
    <li>Microsoft Presidio (Open Source) [<a href="https://github.com/microsoft/presidio">docs</a>]</li>
    <li>AWS Comprehend (Requires AWS Account) [<a href="https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html">docs</a>]</li>
    <li>Azure PII Detection Cognitive Skill (Requires Azure Account) [<a href="">docs</a>]</li>
</ol>

These analyzers leverage Named Entity Recognition (NER) to identify or extract PII tokens from text. Each detection service will have its own notebook under the `/notebooks` folder. In there you will see how each analyzer is called and the associated analysis results.

## Attributions
This project benefited greatly from a number of PII research works like that from Milne et. al (2018), Schwartz and Solove (2012), [insert the rest]. A special thanks to all the software modules, open source projects, and frameworks that made the setup and organization of this project much easier like Poetry, Microsoft Presidio, spaCy, and several others.
