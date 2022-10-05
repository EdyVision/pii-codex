# Detection and Analysis with PII-Codex
In the case that you are not bringing your own detection service, Microsoft Presidio is integrated into PII Codex that provides flexibility in analyzer type. At the time of this repo's creation, only a select number of evaluators exist. You may create your own evaluators and swap out the version of presidio that pii-codex uses. Note that with this change, you will also need to update the mappings where applicable.

The following are not integrated into the service, but have PII type mapping and detection object conversion support:

<ol>
    <li>AWS Comprehend (Requires AWS Account) [<a href="https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html">docs</a>]</li>
    <li>Azure PII Detection Cognitive Skill (Requires Azure Account) [<a href="https://learn.microsoft.com/en-us/azure/search/cognitive-search-skill-pii-detection">docs</a>]</li>
</ol>

In the case you are using the built-in Presidio functionality, you can call the analysis service as follows:

```python
from pii_codex.services.pii_analysis import PII_ANALYSIS_SERVICE

strings_to_analyze = ["string to analyze", "string to analyze"] # strings to analyze
results = PII_ANALYSIS_SERVICE.analyze_collection(
    texts=strings_to_analyze,
    language_code="en",
    collection_name="Data Set Label", # this is optional, geared for those that require labeling of collections
    collection_type="SAMPLE" # defaults to POPULATION, input used for standard deviation and variance calculations
)
print(results)
```

To supply the analyzer module with a collection of pre-detected results from your own Microsoft Presidio, Azure, or AWS Comprehend analysis process, you will need to first convert the detection to a set of DetectionResult objects to feed into the analyzer as follows:

```python
from typing import List
from presidio_analyzer import RecognizerResult
from pii_codex.services.pii_analysis import PII_ANALYSIS_SERVICE
from pii_codex.services.pii_detection import PresidioPIIDetectionService
from pii_codex.models.analysis import DetectionResult

presidio_detection_service = PresidioPIIDetectionService()

list_of_detections: List[RecognizerResult] = [] # your list of MSFT Presidio detections 
converted_detections: List[DetectionResult] = presidio_detection_service.convert_analyzed_collection(
                                                    pii_detections=list_of_detections
                                              )

results = PII_ANALYSIS_SERVICE.analyze_detection_collection(
    detection_collection=converted_detections,
    collection_name="Data Set Label",  # this is more for those that intend to find a way to label collections
    collection_type="SAMPLE"  # defaults to POPULATION, input used for standard deviation and variance calculations
)
print(results)
```

The other two detection services available are AWSComprehendPIIDetectionAdapter and AzurePIIDetectionAdapter.

Check out full analysis example in the notebook: notebooks/pii-batch-analysis-ms-presidio.