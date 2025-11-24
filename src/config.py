"""Configuration handling for Disk Space Monitor."""

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv


@dataclass
class SentryConfig:
    """Sentry-related configuration."""

    dsn: str
    environment: str = "production"


@dataclass
class ThresholdsConfig:
    """Alert threshold configuration."""

    warning: int = 80
    critical: int = 90

    def __post_init__(self):
        if not 0 < self.warning < 100:
            raise ValueError(f"Warning threshold must be between 0 and 100, got {self.warning}")
        if not 0 < self.critical <= 100:
            raise ValueError(f"Critical threshold must be between 0 and 100, got {self.critical}")
        if self.warning >= self.critical:
            raise ValueError(
                f"Warning threshold ({self.warning}) must be less than critical ({self.critical})"
            )


@dataclass
class AlertsConfig:
    """Alert behavior configuration."""

    cooldown: int = 3600  # seconds


@dataclass
class MonitoringConfig:
    """Monitoring behavior configuration."""

    paths: list[str] = field(default_factory=lambda: ["/"])
    check_interval: int = 300  # seconds
    hostfs_prefix: str = ""  # Set to "/hostfs" when running in Docker


@dataclass
class LoggingConfig:
    """Logging configuration."""

    level: str = "INFO"


@dataclass
class Config:
    """Main configuration container."""

    sentry: SentryConfig
    monitoring: MonitoringConfig
    thresholds: ThresholdsConfig
    alerts: AlertsConfig
    logging: LoggingConfig
    hostname: str = field(default_factory=socket.gethostname)

    def get_real_path(self, path: str) -> str:
        """Get the real filesystem path, accounting for hostfs prefix in Docker."""
        if self.monitoring.hostfs_prefix:
            # Normalize path to avoid double slashes
            prefix = self.monitoring.hostfs_prefix.rstrip("/")
            if path == "/":
                return prefix
            return f"{prefix}{path}"
        return path


def _get_env_list(key: str, default: list[str]) -> list[str]:
    """Parse comma-separated environment variable into list."""
    value = os.getenv(key)
    if value:
        return [p.strip() for p in value.split(",") if p.strip()]
    return default


def _get_env_int(key: str, default: int) -> int:
    """Parse integer from environment variable."""
    value = os.getenv(key)
    if value:
        try:
            return int(value)
        except ValueError as err:
            raise ValueError(f"Invalid integer value for {key}: {value}") from err
    return default


def load_config(config_path: str | None = None) -> Config:
    """
    Load configuration from YAML file and environment variables.

    Environment variables take precedence over YAML config.

    Args:
        config_path: Optional path to YAML config file.

    Returns:
        Configured Config instance.

    Raises:
        ValueError: If required configuration is missing or invalid.
    """
    # Load .env file if present
    load_dotenv()

    # Start with defaults from YAML if provided
    yaml_config: dict = {}
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            yaml_config = yaml.safe_load(f) or {}

    # Extract nested configs with defaults
    yaml_sentry = yaml_config.get("sentry", {})
    yaml_monitoring = yaml_config.get("monitoring", {})
    yaml_thresholds = yaml_config.get("thresholds", {})
    yaml_alerts = yaml_config.get("alerts", {})
    yaml_logging = yaml_config.get("logging", {})

    # Build Sentry config (env vars take precedence)
    sentry_dsn = os.getenv("SENTRY_DSN") or yaml_sentry.get("dsn")
    if not sentry_dsn:
        raise ValueError("SENTRY_DSN is required (via environment or config file)")

    sentry_config = SentryConfig(
        dsn=sentry_dsn,
        environment=os.getenv("SENTRY_ENVIRONMENT") or yaml_sentry.get("environment", "production"),
    )

    # Build Monitoring config
    yaml_paths = yaml_monitoring.get("paths", ["/"])
    monitoring_config = MonitoringConfig(
        paths=_get_env_list("MONITOR_PATHS", yaml_paths),
        check_interval=_get_env_int("CHECK_INTERVAL", yaml_monitoring.get("check_interval", 300)),
        hostfs_prefix=os.getenv("HOSTFS_PREFIX", ""),
    )

    # Build Thresholds config
    thresholds_config = ThresholdsConfig(
        warning=_get_env_int("WARNING_THRESHOLD", yaml_thresholds.get("warning", 80)),
        critical=_get_env_int("CRITICAL_THRESHOLD", yaml_thresholds.get("critical", 90)),
    )

    # Build Alerts config
    alerts_config = AlertsConfig(
        cooldown=_get_env_int("ALERT_COOLDOWN", yaml_alerts.get("cooldown", 3600)),
    )

    # Build Logging config
    logging_config = LoggingConfig(
        level=os.getenv("LOG_LEVEL") or yaml_logging.get("level", "INFO"),
    )

    # Get hostname
    hostname = os.getenv("HOSTNAME_OVERRIDE") or socket.gethostname()

    return Config(
        sentry=sentry_config,
        monitoring=monitoring_config,
        thresholds=thresholds_config,
        alerts=alerts_config,
        logging=logging_config,
        hostname=hostname,
    )
