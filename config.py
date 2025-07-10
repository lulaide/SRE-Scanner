from pydantic_settings import BaseSettings, SettingsConfigDict

class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    openai_base_url: str = "https://api.openai.com/v1"
    openai_api_key: str
    openai_model: str

config = AppConfig()