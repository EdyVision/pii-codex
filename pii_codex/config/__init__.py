from pydantic import BaseSettings


class CommonSettings(BaseSettings):
    APP_NAME: str = "PII Codex"


class AWSSettings(BaseSettings):
    """Specific settings for AWS"""

    AWS_ACCESS_KEY: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_ACCOUNT: str = ""  # Your AWS Account #
    AWS_REGION: str = ""  # Example: us-east-1


class Settings(
    CommonSettings,
    AWSSettings,
):
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
