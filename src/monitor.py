"""Core disk space monitoring logic."""

import argparse
import logging
import os
import signal
import sys
import threading
import time

import psutil

from .config import Config, load_config
from .sentry_client import Alert, AlertLevel, DiskUsage, SentryAlertClient

logger = logging.getLogger(__name__)


class DiskMonitor:
    """Monitor disk space and send alerts when thresholds are exceeded."""

    def __init__(self, config: Config, sentry_client: SentryAlertClient):
        """
        Initialize the disk monitor.

        Args:
            config: Application configuration.
            sentry_client: Sentry client for sending alerts.
        """
        self.config = config
        self.sentry_client = sentry_client
        # Track cooldowns: {path: {level: timestamp}}
        self.last_alerts: dict[str, dict[str, float]] = {}
        self._running = False
        self._stop_event = threading.Event()

    def check_disk_usage(self, path: str) -> DiskUsage | None:
        """
        Get disk usage statistics for a given path.

        Args:
            path: The mount point or path to check.

        Returns:
            DiskUsage object with statistics, or None if path is inaccessible.
        """
        real_path = self.config.get_real_path(path)

        try:
            usage = psutil.disk_usage(real_path)
            return DiskUsage(
                path=path,  # Report the original path, not the hostfs path
                total_bytes=usage.total,
                used_bytes=usage.used,
                free_bytes=usage.free,
                usage_percent=usage.percent,
            )
        except FileNotFoundError:
            logger.warning("Path not found: %s (real path: %s)", path, real_path)
            return None
        except PermissionError:
            logger.warning("Permission denied for path: %s (real path: %s)", path, real_path)
            return None
        except OSError as e:
            logger.error("Error checking disk usage for %s: %s", path, e)
            return None

    def get_alert_level(self, usage_percent: float) -> AlertLevel | None:
        """
        Determine the alert level based on usage percentage.

        Args:
            usage_percent: Current disk usage percentage.

        Returns:
            'critical', 'warning', or None if below thresholds.
        """
        if usage_percent >= self.config.thresholds.critical:
            return "critical"
        elif usage_percent >= self.config.thresholds.warning:
            return "warning"
        return None

    def should_alert(self, path: str, level: AlertLevel) -> bool:
        """
        Check if we should send an alert, respecting cooldown period.

        Args:
            path: The mount point path.
            level: The alert level.

        Returns:
            True if enough time has passed since the last alert of this type.
        """
        now = time.time()
        cooldown = self.config.alerts.cooldown

        path_alerts = self.last_alerts.get(path, {})
        last_alert_time = path_alerts.get(level)

        if last_alert_time is None:
            return True

        time_since_alert = now - last_alert_time
        if time_since_alert >= cooldown:
            return True

        remaining = cooldown - time_since_alert
        logger.debug(
            "Alert for %s (%s) on cooldown, %d seconds remaining",
            path,
            level,
            remaining,
        )
        return False

    def record_alert(self, path: str, level: AlertLevel) -> None:
        """Record that an alert was sent for cooldown tracking."""
        if path not in self.last_alerts:
            self.last_alerts[path] = {}
        self.last_alerts[path][level] = time.time()

    def run_check(self) -> list[Alert]:
        """
        Run a single check cycle for all configured paths.

        Returns:
            List of alerts that were generated (and should be sent).
        """
        alerts: list[Alert] = []

        for path in self.config.monitoring.paths:
            usage = self.check_disk_usage(path)
            if usage is None:
                continue

            logger.debug(
                "Disk usage for %s: %.1f%% (%.1f GB free of %.1f GB)",
                path,
                usage.usage_percent,
                usage.free_gb,
                usage.total_gb,
            )

            level = self.get_alert_level(usage.usage_percent)
            if level is None:
                continue

            if not self.should_alert(path, level):
                continue

            alert = Alert(
                path=path,
                level=level,
                usage=usage,
                hostname=self.config.hostname,
            )
            alerts.append(alert)

        return alerts

    def send_alerts(self, alerts: list[Alert]) -> None:
        """Send alerts to Sentry and record them for cooldown tracking."""
        for alert in alerts:
            success = self.sentry_client.send_alert(alert)
            if success:
                self.record_alert(alert.path, alert.level)
            else:
                logger.warning(
                    "Failed to send alert for %s (%s), will retry next cycle",
                    alert.path,
                    alert.level,
                )

    def run(self) -> None:
        """Main monitoring loop."""
        self._running = True
        logger.info(
            "Starting disk monitor (hostname: %s, interval: %ds, paths: %s)",
            self.config.hostname,
            self.config.monitoring.check_interval,
            ", ".join(self.config.monitoring.paths),
        )
        logger.info(
            "Thresholds - warning: %d%%, critical: %d%%, cooldown: %ds",
            self.config.thresholds.warning,
            self.config.thresholds.critical,
            self.config.alerts.cooldown,
        )

        # Initialize Sentry
        self.sentry_client.initialize()

        while self._running:
            try:
                alerts = self.run_check()
                if alerts:
                    self.send_alerts(alerts)
                    self.sentry_client.flush()

                logger.debug(
                    "Check cycle complete, sleeping for %ds", self.config.monitoring.check_interval
                )
                # Use event.wait() instead of time.sleep() for interruptible sleep
                if self._stop_event.wait(timeout=self.config.monitoring.check_interval):
                    # Event was set, meaning stop was requested
                    break

            except KeyboardInterrupt:
                logger.info("Received keyboard interrupt")
                break
            except Exception as e:
                logger.exception("Error during check cycle: %s", e)
                # Continue running even if there's an error
                if self._stop_event.wait(timeout=self.config.monitoring.check_interval):
                    break

        logger.info("Disk monitor stopped")

    def stop(self) -> None:
        """Signal the monitor to stop."""
        self._running = False
        self._stop_event.set()  # Wake up from sleep immediately


def setup_logging(level: str) -> None:
    """Configure logging for the application."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Monitor disk space and send alerts to Sentry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.monitor              # Run the monitor
  python -m src.monitor --test       # Send a test event to Sentry and exit
        """,
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Send a test event to Sentry with current disk usage and exit",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config file (default: config.yml or CONFIG_PATH env var)",
    )
    return parser.parse_args()


def run_test_event(config: Config, sentry_client: SentryAlertClient) -> bool:
    """
    Send a test event to Sentry with current disk usage.

    Returns:
        True if the test event was sent successfully, False otherwise.
    """
    import time as time_module

    monitor = DiskMonitor(config, sentry_client)

    # Collect disk usage for all configured paths
    logger.info("Collecting disk usage...")
    disk_usages: list[DiskUsage] = []
    for path in config.monitoring.paths:
        usage = monitor.check_disk_usage(path)
        if usage:
            disk_usages.append(usage)
            logger.info(
                "Disk usage for %s: %.1f%% (%.1f GB free of %.1f GB)",
                path,
                usage.usage_percent,
                usage.free_gb,
                usage.total_gb,
            )

    if not disk_usages:
        logger.error("Could not collect disk usage from any configured path")
        return False

    # Initialize Sentry
    logger.info("Initializing Sentry SDK...")
    start = time_module.time()
    sentry_client.initialize()
    logger.info("Sentry SDK initialized in %.2fs", time_module.time() - start)

    # Send test event
    logger.info("Sending test event to Sentry...")
    start = time_module.time()
    success = sentry_client.send_test_event(config.hostname, disk_usages)
    logger.info("Test event sent in %.2fs", time_module.time() - start)

    # Flush to ensure delivery
    logger.info("Flushing events (waiting up to 10s for delivery)...")
    start = time_module.time()
    sentry_client.flush(timeout=10)
    logger.info("Flush completed in %.2fs", time_module.time() - start)

    return success


def main() -> None:
    """Entry point for the disk monitor."""
    args = parse_args()

    # Load configuration
    config_path = args.config or os.getenv("CONFIG_PATH", "config.yml")
    try:
        config = load_config(config_path if os.path.exists(config_path) else None)
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    # Setup logging
    setup_logging(config.logging.level)

    # Create Sentry client
    sentry_client = SentryAlertClient(
        dsn=config.sentry.dsn,
        environment=config.sentry.environment,
    )

    # Handle test mode
    if args.test:
        logger.info("Running in test mode - sending test event to Sentry")
        success = run_test_event(config, sentry_client)
        if success:
            logger.info("Test event sent successfully!")
            sys.exit(0)
        else:
            logger.error("Failed to send test event")
            sys.exit(1)

    # Create and run monitor
    monitor = DiskMonitor(config, sentry_client)

    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received signal %s, shutting down...", signum)
        monitor.stop()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Run the monitor
    monitor.run()


if __name__ == "__main__":
    main()
