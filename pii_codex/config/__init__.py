from pydantic import BaseSettings


class CommonSettings(BaseSettings):
    APP_NAME: str = "Unraveled API"
    DEBUG_MODE: bool = False


class AWSSettings(BaseSettings):
    """Specific settings for AWS"""

    AWS_ACCESS_KEY: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_ACCOUNT: str = ""  # Your AWS Account #
    AWS_REGION: str = ""  # Example: us-east-1


class MachineLearningSettings(BaseSettings):
    """ML Learning Settings like NLTK and other such libraries"""

    NLTK_DATA_PATH: str = "./data/nltk_data"


class Settings(
    CommonSettings,
    MachineLearningSettings,
    AWSSettings,
):
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
