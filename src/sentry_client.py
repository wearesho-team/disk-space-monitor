"""Sentry integration for sending disk space alerts."""

import logging
from dataclasses import dataclass
from typing import Literal

import sentry_sdk

logger = logging.getLogger(__name__)

AlertLevel = Literal["warning", "critical"]


@dataclass
class DiskUsage:
    """Disk usage statistics for a path."""

    path: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    usage_percent: float

    @property
    def total_gb(self) -> float:
        """Total space in GB."""
        return self.total_bytes / (1024**3)

    @property
    def used_gb(self) -> float:
        """Used space in GB."""
        return self.used_bytes / (1024**3)

    @property
    def free_gb(self) -> float:
        """Free space in GB."""
        return self.free_bytes / (1024**3)


@dataclass
class Alert:
    """Alert to be sent to Sentry."""

    path: str
    level: AlertLevel
    usage: DiskUsage
    hostname: str


class SentryAlertClient:
    """Client for sending disk space alerts to Sentry."""

    def __init__(self, dsn: str, environment: str = "production"):
        """
        Initialize Sentry SDK.

        Args:
            dsn: Sentry DSN for the project.
            environment: Environment name (e.g., production, staging).
        """
        self.dsn = dsn
        self.environment = environment
        self._initialized = False

    def initialize(self) -> None:
        """Initialize the Sentry SDK. Call once at startup."""
        if self._initialized:
            return

        sentry_sdk.init(
            dsn=self.dsn,
            environment=self.environment,
            # Disable default integrations we don't need
            default_integrations=False,
            # Set sample rate for performance (we're not using it)
            traces_sample_rate=0,
        )
        self._initialized = True
        logger.info("Sentry SDK initialized for environment: %s", self.environment)

    def send_alert(self, alert: Alert) -> bool:
        """
        Send a disk space alert to Sentry.

        Args:
            alert: The alert to send.

        Returns:
            True if the alert was sent successfully, False otherwise.
        """
        if not self._initialized:
            self.initialize()

        # Map alert level to Sentry level
        sentry_level: Literal["error", "warning"] = (
            "error" if alert.level == "critical" else "warning"
        )

        try:
            with sentry_sdk.push_scope() as scope:
                # Set tags for filtering
                scope.set_tag("monitor_type", "disk_space")
                scope.set_tag("host", alert.hostname)
                scope.set_tag("mount_point", alert.path)
                scope.set_tag("alert_level", alert.level)

                # Set extra context
                scope.set_extra("usage_percent", round(alert.usage.usage_percent, 2))
                scope.set_extra("used_gb", round(alert.usage.used_gb, 2))
                scope.set_extra("free_gb", round(alert.usage.free_gb, 2))
                scope.set_extra("total_gb", round(alert.usage.total_gb, 2))

                # Set fingerprint for grouping same alerts together
                scope.fingerprint = [
                    "disk_space",
                    alert.hostname,
                    alert.path,
                    alert.level,
                ]

                scope.level = sentry_level

                # Create the message
                message = (
                    f"Disk space {alert.level}: {alert.usage.usage_percent:.1f}% used on {alert.path} "
                    f"({alert.usage.free_gb:.1f} GB free of {alert.usage.total_gb:.1f} GB)"
                )

                event_id = sentry_sdk.capture_message(message, level=sentry_level)

            if event_id:
                logger.info(
                    "Alert sent to Sentry: %s on %s (%s) - event_id: %s",
                    alert.level,
                    alert.path,
                    alert.hostname,
                    event_id,
                )
                return True
            else:
                logger.warning("Sentry returned no event_id for alert")
                return False

        except Exception as e:
            logger.error("Failed to send alert to Sentry: %s", e)
            return False

    def send_test_event(self, hostname: str, disk_usages: list[DiskUsage]) -> bool:
        """
        Send a test event to Sentry to verify connectivity.

        Args:
            hostname: The hostname to include in the event.
            disk_usages: List of current disk usage stats to include.

        Returns:
            True if the event was sent successfully, False otherwise.
        """
        if not self._initialized:
            self.initialize()

        try:
            with sentry_sdk.push_scope() as scope:
                # Set tags for filtering
                scope.set_tag("monitor_type", "disk_space")
                scope.set_tag("host", hostname)
                scope.set_tag("event_type", "test")

                # Build disk usage summary
                disk_info = []
                for usage in disk_usages:
                    disk_info.append(
                        {
                            "path": usage.path,
                            "usage_percent": round(usage.usage_percent, 2),
                            "used_gb": round(usage.used_gb, 2),
                            "free_gb": round(usage.free_gb, 2),
                            "total_gb": round(usage.total_gb, 2),
                        }
                    )

                scope.set_extra("disk_usage", disk_info)
                scope.set_extra("paths_monitored", [u.path for u in disk_usages])

                # Set fingerprint for grouping test events together
                scope.fingerprint = ["disk_space", "test", hostname]

                scope.level = "info"

                message = f"Disk space monitor test event from {hostname}"
                event_id = sentry_sdk.capture_message(message, level="info")

            if event_id:
                logger.info("Test event sent to Sentry - event_id: %s", event_id)
                return True
            else:
                logger.warning("Sentry returned no event_id for test event")
                return False

        except Exception as e:
            logger.error("Failed to send test event to Sentry: %s", e)
            return False

    def flush(self, timeout: int = 2) -> None:
        """
        Flush pending events to Sentry.

        Args:
            timeout: Maximum time to wait in seconds.
        """
        sentry_sdk.flush(timeout=timeout)
