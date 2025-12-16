# Mapping Across PII Detections with PII-Codex
The PII Codex has a number of enums to help with the definitions and labeling of PII, their categories, and their severity rankings across modules. At this time, only AWS Comprehend, Microsoft Presidio, and Microsoft Azure PII entity types are mapped to using the common PII types listing.

Selecting a PII type from the common PII type listing:

## Mapping Between PII Types
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
```

Each module or cloud resource will have its own string labeling for the PII Type. It is sometimes required to map to that string value in order to properly parse out a PII detection or to initialize an analyzer. To map to a different PII type (if supported with the version, using MSFT Presidio for example):

```python
from pii_codex.models.common import PIIType
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.models.azure_pii import AzureDetectionType
from pii_codex.models.aws_pii import AWSComprehendPIIType

presidio_pii_type = MSFTPresidioPIIType[PIIType.EMAIL_ADDRESS.name] # MSFT Presidio enum entry

print("Presidio Enum Type Name for Email: ", presidio_pii_type.name)
print("Presidio Enum Type Value for Email: ", presidio_pii_type.value)
```

Using the built-in mapper can be a help, just pass in the mapping you'd like to perform and it'll provide you with the enum name and the enum type entry. If it is not supported, you'll be supplied with the error instead.

```python
from pii_codex.models.common import PIIType
from pii_codex.utils.pii_mapping_util import PIIMapper

pii_mapper = PIIMapper()

azure_pii = pii_mapper.convert_common_pii_to_azure_pii_type(PIIType.EMAIL_ADDRESS)

aws_pii = pii_mapper.convert_common_pii_to_aws_comprehend_type(PIIType.EMAIL_ADDRESS)
presidio_pii = pii_mapper.convert_common_pii_to_msft_presidio_type(PIIType.EMAIL_ADDRESS)
```

In the case you are using the PII-Codex module for just detection conversions and analysis, there is an inverse set of mappers that will take Presidio, Azure, or AWS Comprehend PII types and convert to the PII-Codex commmon types:

```python
from pii_codex.models.common import PIIType
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.models.azure_pii import AzureDetectionType
from pii_codex.models.aws_pii import AWSComprehendPIIType
from pii_codex.utils.pii_mapping_util import PIIMapper

pii_mapper = PIIMapper()

azure_to_common_pii = pii_mapper.convert_azure_pii_to_common_pii_type(
    AzureDetectionType.EMAIL_ADDRESS.value
)
aws_to_common_pii = pii_mapper.convert_aws_comprehend_pii_to_common_pii_type(
    AWSComprehendPIIType.EMAIL_ADDRESS.value
)
presidio_to_common_pii = pii_mapper.convert_msft_presidio_pii_to_common_pii_type(
    MSFTPresidioPIIType.US_SOCIAL_SECURITY_NUMBER.value  # e.g. "US_SSN"
)
```

### Example: provider‑specific labels vs common PII types

Some providers use compact or region‑encoded labels which do **not** match the human‑readable common PII type names. For example:

```python
from pii_codex.models.common import PIIType
from pii_codex.models.microsoft_presidio_pii import MSFTPresidioPIIType
from pii_codex.utils.pii_mapping_util import PIIMapper

pii_mapper = PIIMapper()

# Presidio emits "US_SSN", which we represent as:
assert MSFTPresidioPIIType.US_SOCIAL_SECURITY_NUMBER.value == "US_SSN"

# PII Codex maps this back to the canonical common type:
common_type = pii_mapper.convert_msft_presidio_pii_to_common_pii_type("US_SSN")
assert common_type is PIIType.US_SOCIAL_SECURITY_NUMBER

# Likewise for AU tax identifiers:
assert MSFTPresidioPIIType.AU_TAX_FILE_NUMBER.value == "AU_TFN"
common_au_tfn = pii_mapper.convert_msft_presidio_pii_to_common_pii_type("AU_TFN")
assert common_au_tfn is PIIType.AU_TAX_FILE_NUMBER

# The key idea: provider enums mirror the provider's own labels,
# and PIIType is the canonical, provider‑independent surface.
```

## Importing Updated Files

```python

from pii_codex.utils import pii_mapping_util
from pii_codex.models.common import PIIType
# Data frame loaded from csv mapping file (assumes /data location in pii-codex)
csv_file_dataframe = pii_mapping_util.open_pii_type_mapping_csv("v1")

# Data frame loaded from json mapping file (assumes /data location in pii-codex)
json_file_dataframe = pii_mapping_util.open_pii_type_mapping_json("v1")

# Retrieving the entries for "IP Address" Information Type, for example
ip_address = json_file_dataframe[json_file_dataframe.Information_Type=='IP Address'].item()

pii_type = PIIType[ip_address]
print("Enum Type Name for IP Address: ", pii_type.name)
print("Enum Type Name for IP Address: ", pii_type.value)
```
