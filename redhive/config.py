"""Central configuration for RedHive.

All settings come from environment variables (see .env.example).
Import `settings` anywhere; do not read os.environ directly elsewhere.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # LLM provider: "openai" (default) or "claude"
    llm_provider: str = "openai"

    openai_api_key: str = ""
    openai_model: str = "gpt-4o"

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"

    database_url: str = "postgresql://redhive:redhive@localhost:5432/redhive"

    # Comma-separated hosts the agent may scan. Parsed by scope guard.
    scan_allowlist: str = "localhost,127.0.0.1,juiceshop,host.docker.internal"

    @property
    def allowlist(self) -> list[str]:
        return [h.strip().lower() for h in self.scan_allowlist.split(",") if h.strip()]


settings = Settings()
