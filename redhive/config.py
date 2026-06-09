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

    # Comma-separated hosts that are ALWAYS scannable without ownership
    # verification — intentionally-vulnerable practice apps used for demos and
    # tests. Customer targets are authorized per-org via verified Target rows
    # (see redhive.scope / redhive.targets), not this list.
    scan_allowlist: str = "localhost,127.0.0.1,juiceshop,host.docker.internal"

    # Auth: secret used to sign session JWTs for the dashboard. MUST be
    # overridden in production via env. The 32+ char default is dev-only.
    secret_key: str = "dev-secret-change-me-in-production-0000000000"
    # Dashboard session lifetime, in minutes.
    session_ttl_minutes: int = 60 * 24 * 7  # one week

    # DNS TXT record name customers add to prove target ownership.
    ownership_dns_prefix: str = "_redhive-verify"

    # Comma-separated browser origins allowed to call the API (the dashboard).
    # Never use "*" with credentials — set the real dashboard origin(s) in prod.
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    # Per-plan quotas (max concurrent/queued scans, verified targets).
    # Enforced in the API; "free" is the default plan for new orgs.
    free_target_limit: int = 3
    free_monthly_scan_limit: int = 50

    @property
    def allowlist(self) -> list[str]:
        return [h.strip().lower() for h in self.scan_allowlist.split(",") if h.strip()]


settings = Settings()
