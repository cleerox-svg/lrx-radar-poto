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
    public_api_base_url: str = "http://localhost:8000"

    certstream_enabled: bool = False
    certstream_ws_url: str = "wss://certstream.calidog.io/"
    certstream_reconnect_max_seconds: int = 60
    certstream_lookalike_similarity: float = 0.78
    certstream_emit_on_exact_brand: bool = False

    dmarc_imap_enabled: bool = False
    dmarc_imap_host: str = ""
    dmarc_imap_port: int = 993
    dmarc_imap_username: str = ""
    dmarc_imap_password: str = ""
    dmarc_imap_folder: str = "INBOX"
    dmarc_imap_search_query: str = "UNSEEN"
    dmarc_imap_poll_seconds: int = 60
    dmarc_imap_processed_set: str = "lrx:dmarc:processed"
    dmarc_local_drop_dir: str = ""

    proofpoint_blocklist_endpoint: str = "https://tap-api-v2.proofpoint.com/v2/threat/blocklist"
    proofpoint_api_token: str = ""
    takedown_submit_endpoint: str = "https://api.takedown-partner.com/v1/incidents/submit"
    takedown_api_key: str = ""
    okta_workflow_invoke_url: str = ""
    okta_oauth_token: str = ""
    orchestrator_timeout_seconds: int = 15

    @cached_property
    def brand_list(self) -> list[str]:
        return [entry.strip() for entry in self.monitored_brands.split(",") if entry.strip()]


settings = Settings()
