<div align="center">

![alt text](https://github.com/EdyVision/pii-codex/blob/main/docs/PII_Codex_Logo.svg?raw=true)

PII Detection, Categorization, and Severity Assessment

[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
![](https://img.shields.io/badge/code%20style-black-000000.svg)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/EdyVision/pii-codex/graphs/commit-activity)
[![codecov](https://codecov.io/gh/EdyVision/pii-codex/branch/main/graph/badge.svg?token=QO7DNMP87X)](https://codecov.io/gh/EdyVision/pii-codex)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Python 3.9](https://img.shields.io/badge/python-3.9-blue.svg)](https://www.python.org/downloads/release/python-390/)
[![DOI](https://zenodo.org/badge/533554671.svg)](https://zenodo.org/badge/latestdoi/533554671)

</div>

---
The <em>PII Codex</em> project was built as a core part of an ongoing research effort in Personal Identifiable Information (PII) detection and risk assessment (to be publicly released later in 2023). There was a need to not only detect PII in text, but also identify its severity, associated categorizations in cybersecurity research and policy documentation, and provide a way for others in similar research efforts to reproduce or extend the research. PII Codex is a combination of systematic research, conceptual frameworks, third-party open source software, and cloud service provider integrations. The categorizations are directly influenced by the research of Milne et al. (2016) while the ranking is a result of category severities on the scale provided by Schwartz and Solove (2012) from Non-Identifiable, Semi-Identifiable, and Identifiable.

The outputs of the primary PII Codex analysis and adapter functions are AnalysisResult or AnalysisResultSet objects that will provide a listing of detections, severities, mean risk scores for each string processed, and summary statistics on the analysis made. The final outputs do not contain the original texts but instead will provide where to find the detections should the end-user care for this information in their analysis.

## Statement of Need

The general knowledge base of identifiable data, the usage restrictions of this data, and the associated policies surrounding it have shifted drastically over the years. The tech industry has had to adjust to many policy changes regarding the tracking of individuals, the usage of data from online profiles and platforms, and the right to be forgotten entirely from a service or platform (GDPR). While the shift has provided data protections around the globe, the majority of technology users continue to have little to no control over their personal information with third-party data consumers (Trepte, 2020). 

Understanding if identifiable data types exist in a data set can prevent accidental sharing of such data by allowing its detection in the first place and, in the case of this software package, present sanitized strings, the reasons to why the token was considered to be PII, and permit for the results to be publishable.

## Potential Usages
Potential usages include sanitizing of dataset strings (e.g. a collection of social media posts), presenting results to users for software examining their interactions (e.g. UX research on user-awareness in cybersecurity applications), etc.

<hr/>

## Running Locally
This project uses Poetry. To run this project, install `poetry` and proceed to follow the instructions under `/docs/LOCAL_SETUP.md`.

`Note: This project has only been tested with Ubuntu and MacOS.`

## Importing
Before adding `pii-codex` on your project, download the spaCy `en_core_web_lg` model:

```bash
python3 -m spacy download en_core_web_lg
```


The repository releases are hosted on PyPi.

Using pip (must have latest pip version and running Python 3.9 or 3.10):

```bash
pip install --upgrade pip
pip install pii-codex
pip install pii-codex[detections]
```

Using Poetry:

```bash
poetry update
poetry add pii-codex
poetry install pii-codex --extras="detections"
```

For those using Google Collab, check out the example notebook:

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/gist/EdyVision/802ce21aab21eb5d9afa9e43d301eef7/pii-codex-sample-notebook.ipynb)

## Usage

### Sample Input / Output
The built-in analyzer uses Microsoft Presidio. Feed in a collection of strings with analyze_collection() or just a single string with analyze_item(). Those analyzing a collection of strings will also be provided with statistics calculated on the risk scores for detected items.
```python
from pii_codex.services.analysis_service import PIIAnalysisService
PIIAnalysisService().analyze_collection(
    texts=["your collection of strings"],
    language_code="en",
    collection_name="Data Set Label", # Optional Labeling
    collection_type="SAMPLE" # Defaults to POPULATION, used stats calculations
)
```

You can also pass in a `data` param (dataframe) instead of simple text array with a text column and a metadata column to be analyzed for those analyzing social media posts. Current metadata supported are `URL`, `LOCATION`, and `SCREEN_NAME`.

Sample output (results object converted to `dict` from notebook):
```
{
    "collection_name": "PII Collection 1",
    "collection_type": "POPULATION",
    "analyses": [
        {
            "analysis": [
                {
                    "pii_type_detected": "PERSON",
                    "risk_level": 3,
                    "risk_level_definition": "Identifiable",
                    "cluster_membership_type": "Financial Information",
                    "hipaa_category": "Protected Health Information",
                    "dhs_category": "Linkable",
                    "nist_category": "Directly PII",
                    "entity_type": "PERSON",
                    "score": 0.85,
                    "start": 21,
                    "end": 24,
                }
            ],
            "index": 0,
            "risk_score_mean": 3,
            "sanitized_text: "Hi! My name is <REDACTED>",
        },
        ...
    ],
    "detection_count": 5,
    "risk_scores": [3, 2.6666666666666665, 1, 2, 1],
    "risk_score_mean": 1.9333333333333333,
    "risk_score_mode": 1,
    "risk_score_median": 2,
    "risk_score_standard_deviation": 0.8273115763993905,
    "risk_score_variance": 0.6844444444444444,
    "detected_pii_types": {
        "LOCATION",
        "EMAIL_ADDRESS",
        "URL",
        "PHONE_NUMBER",
        "PERSON",
    },
    "detected_pii_type_frequencies": {
        "PERSON": 1,
        "EMAIL_ADDRESS": 1,
        "PHONE_NUMBER": 1,
        "URL": 1,
        "LOCATION": 1,
    },
}
```

### Docs
For more information on usage, check out the respective documentation for guidance on using PII-Codex.

| Topic                       | Document                                                     | Description                                                                              |
|-----------------------------|--------------------------------------------------------------|------------------------------------------------------------------------------------------|
| PII Type Mappings           | [PII Mappings](docs/MAPPING.md)                              | Overview of how to perform mappings between PII types and how to review store PII types. |
| PII Detections and Analysis | [PII Detection and Analysis](docs/DETECTION_AND_ANALYSIS.md) | Overview of how to detect and analyze strings                                            |
| Local Repo Setup            | [Local Repo Setup](docs/LOCAL_SETUP.md)                      | Instructions for local repository setup                                                  |
| Example Analysis            | [Example Analysis Notebook](notebooks/pii-analysis-ms-presidio.ipynb)  | Notebook with example analysis using MSFT Presidio                             |

<hr/>

## Attributions
This project benefited greatly from a number of PII research works like that from Milne et al (2016) with the definition of the types and categories, Schwartz and Solove (2012) with the severity levels of Non-Identifiable, Semi-Identifiable, and Identifiable, and the documentation by NIST, DHS (2012), and HIPAA. A special thanks to all the open source projects, and frameworks that made the setup and structuring of this project much easier like Poetry, Microsoft Presidio, spaCy (2017), Jupyter, and several others.
