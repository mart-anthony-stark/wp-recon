from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings():
    DEFAULT_TIMEOUT: int = 10
    RATE_LIMIT_SECONDS = 0.75
    USER_AGENT = "PassiveWPScanner/1.0 (For Devensive and Security Testing)"

    model_config = SettingsConfigDict(env_file=".env", extra='allow')

settings = Settings()