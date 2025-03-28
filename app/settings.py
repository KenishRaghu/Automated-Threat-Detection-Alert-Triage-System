from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        env_nested_delimiter="__",
    )

    app_name: str = "Automated Threat Detection & Alert Triage System"
    redis_url: str = "redis://localhost:6379/0"
    opensearch_url: str = "http://localhost:9200"
    opensearch_verify_certs: bool = False
    slack_webhook_url: str = ""
    pagerduty_routing_key: str = ""
    ticket_system_url: str = "https://tickets.example.internal/api"
    siem_shared_secret: str = "dev-shared-secret"


settings = Settings()
