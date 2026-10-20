"""Validated backend settings. Production mode intentionally fails closed."""
import ipaddress
import re
from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


DEVELOPMENT_SECRET = "development-secret-key-change-before-production-000000"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WEBGUARD_", env_file=".env", extra="ignore")

    env: str = "development"
    database_url: str = "sqlite:///./webguard.db"
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    cors_origins: str = ""
    allowed_hosts: str = "localhost,127.0.0.1,testserver"
    secret_key: str = DEVELOPMENT_SECRET
    access_token_ttl_minutes: int = Field(default=15, ge=5, le=60)
    max_request_body_bytes: int = Field(default=1_048_576, ge=16_384, le=10_485_760)
    max_page_size: int = Field(default=100, ge=1, le=500)
    default_page_size: int = Field(default=20, ge=1, le=100)
    # Local targets remain disabled unless the operator explicitly enables this setting.
    allow_lab_targets: bool = False
    # Tooling is opt-in; external engines must also be protected by deployment-level egress policy.
    tool_execution_enabled: bool = False
    external_tools_enabled: bool = False
    egress_policy_confirmed: bool = False
    tool_job_timeout_seconds: int = Field(default=180, ge=10, le=900)
    tool_rate_limit_requests: int = Field(default=5, ge=1, le=60)
    workspace_scan_root: str | None = None
    zap_api_url: str | None = None
    zap_api_key: str | None = Field(default=None, repr=False)
    nuclei_path: str = "nuclei"
    k6_path: str = "k6"
    schemathesis_path: str = "schemathesis"
    trivy_path: str = "trivy"
    semgrep_path: str = "semgrep"
    testssl_path: str = "testssl.sh"
    gitleaks_path: str = "gitleaks"
    playwright_enabled: bool = False
    # Optional Groq Chat Completions API (OpenAI-compatible). Credentials remain backend-only.
    ai_provider_name: str = "Groq"
    ai_base_url: str = "https://api.groq.com/openai/v1"
    ai_api_key: str | None = Field(default=None, repr=False)
    ai_model: str = "openai/gpt-oss-120b"
    ai_timeout_seconds: int = Field(default=20, ge=5, le=60)
    ai_max_output_tokens: int = Field(default=1200, ge=128, le=4000)
    ai_rate_limit_requests: int = Field(default=10, ge=1, le=100)

    @field_validator("ai_api_key")
    @classmethod
    def normalize_ai_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @model_validator(mode="after")
    def validate_production(self) -> "Settings":
        parsed_ai = urlsplit(self.ai_base_url.strip())
        try:
            ai_port = parsed_ai.port
        except ValueError as exc:
            raise ValueError("WEBGUARD_AI_BASE_URL contains an invalid port") from exc
        if (parsed_ai.scheme not in {"http", "https"} or not parsed_ai.hostname
                or parsed_ai.username or parsed_ai.password or parsed_ai.query or parsed_ai.fragment
                or (ai_port is not None and not 1 <= ai_port <= 65535)):
            raise ValueError("WEBGUARD_AI_BASE_URL must be an HTTP(S) base without credentials, query or fragment")
        if self.ai_api_key and not self.ai_model.strip():
            raise ValueError("WEBGUARD_AI_MODEL must be set when WEBGUARD_AI_API_KEY is configured")
        if self.external_tools_enabled and not self.egress_policy_confirmed:
            raise ValueError("WEBGUARD_EGRESS_POLICY_CONFIRMED=true is required before enabling external tool engines")
        if self.env.lower() == "production":
            if not re.fullmatch(r"[a-fA-F0-9]{96}", self.secret_key):
                raise ValueError("WEBGUARD_SECRET_KEY must be 48 random bytes encoded as 96 hexadecimal characters in production")
            if not self.database_url.startswith("postgresql+psycopg://"):
                raise ValueError("production requires postgresql+psycopg://; SQLite is for local development only")
            hosts = [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]
            if not hosts or "*" in hosts:
                raise ValueError("WEBGUARD_ALLOWED_HOSTS must list explicit hostnames in production")
            if any(host in {"localhost", "127.0.0.1", "testserver"} for host in hosts):
                raise ValueError("production allowed hosts must not include local development hosts")
            origins = [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
            if "*" in origins or any("localhost" in origin or "127.0.0.1" in origin for origin in origins):
                raise ValueError("production CORS origins must be explicit public origins, never wildcard or localhost")
            for origin in origins:
                parsed = urlsplit(origin)
                if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
                    raise ValueError("production CORS origins must be HTTPS origins without paths, queries or fragments")
            if self.allow_lab_targets:
                raise ValueError("WEBGUARD_ALLOW_LAB_TARGETS must be false in production")
            if self.ai_api_key:
                if parsed_ai.scheme != "https":
                    raise ValueError("configured production AI provider must use HTTPS")
                host = parsed_ai.hostname.lower().rstrip(".")
                if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal")):
                    raise ValueError("configured production AI provider must be an external HTTPS endpoint")
                try:
                    address = ipaddress.ip_address(host)
                except ValueError:
                    address = None
                if address is not None and not address.is_global:
                    raise ValueError("configured production AI provider must not use a private or reserved IP")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
