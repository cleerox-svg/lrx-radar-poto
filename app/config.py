from functools import cached_property

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "LRX Radar"
    database_url: str = "sqlite:///./lrx_radar.db"
    redis_url: str = "redis://localhost:6379/0"
    raw_event_queue: str = "lrx:raw_events"
    monitored_brands: str = (
        "microsoft,google,okta,adobe,amazon,paypal,bankofamerica,docu-sign"
    )
    producer_loop_sleep_seconds: int = 3
    live_feed_enabled: bool = False

    @cached_property
    def brand_list(self) -> list[str]:
        return [entry.strip() for entry in self.monitored_brands.split(",") if entry.strip()]


settings = Settings()
