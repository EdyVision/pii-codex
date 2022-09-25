import boto3

from ...config import settings

COMPREHEND_CLIENT = boto3.client(
    "comprehend",
    aws_access_key_id=settings.AWS_ACCESS_KEY,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    region_name="us-east-1",
)  # us-west-1 doesn't support comprehend yet


class AWSComprehend:
    """
    Class for AWS Comprehend Client
    Boto3 Docs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/comprehend.html
    """

    COMPREHEND = COMPREHEND_CLIENT

    def detect_pii(self, text: str, language_code: str) -> dict:
        """
        @param text:
        @param language_code:
        @return:         {
            'Entities': [
                {
                    'Score': ...,
                    'Type': 'BANK_ACCOUNT_NUMBER'|'BANK_ROUTING'|'CREDIT_DEBIT_NUMBER'|'CREDIT_DEBIT_CVV'|
                    'CREDIT_DEBIT_EXPIRY'|'PIN'|'EMAIL'|'ADDRESS'|'NAME'|'PHONE'|'SSN'|'DATE_TIME'|'PASSPORT_NUMBER'|
                    'DRIVER_ID'|'URL'|'AGE'|'USERNAME'|'PASSWORD'|'AWS_ACCESS_KEY'|'AWS_SECRET_KEY'|'IP_ADDRESS'|
                    'MAC_ADDRESS'|'ALL'|'LICENSE_PLATE'|'VEHICLE_IDENTIFICATION_NUMBER'|'UK_NATIONAL_INSURANCE_NUMBER'|
                    'CA_SOCIAL_INSURANCE_NUMBER'|'US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER'|
                    'UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER'|'IN_PERMANENT_ACCOUNT_NUMBER'|'IN_NREGA'|
                    'INTERNATIONAL_BANK_ACCOUNT_NUMBER'|'SWIFT_CODE'|'UK_NATIONAL_HEALTH_SERVICE_NUMBER'|
                    'CA_HEALTH_NUMBER'|'IN_AADHAAR'|'IN_VOTER_NUMBER',
                    'BeginOffset': 123,
                    'EndOffset': 123
                },
            ]
        }
        """
        return self.COMPREHEND.detect_pii_entities(
            Text=text, LanguageCode=language_code
        )


# Exported Services
AWS_COMPREHEND = AWSComprehend()
