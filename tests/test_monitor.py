"""Tests for disk monitor functionality."""

import time
from unittest import mock

import pytest

from src.config import (
    AlertsConfig,
    Config,
    LoggingConfig,
    MonitoringConfig,
    SentryConfig,
    ThresholdsConfig,
)
from src.monitor import DiskMonitor
from src.sentry_client import DiskUsage, SentryAlertClient


@pytest.fixture
def mock_config():
    """Create a mock configuration for testing."""
    return Config(
        sentry=SentryConfig(dsn="test-dsn", environment="test"),
        monitoring=MonitoringConfig(paths=["/", "/data"], check_interval=60, hostfs_prefix=""),
        thresholds=ThresholdsConfig(warning=80, critical=90),
        alerts=AlertsConfig(cooldown=3600),
        logging=LoggingConfig(level="DEBUG"),
        hostname="test-host",
    )


@pytest.fixture
def mock_sentry_client():
    """Create a mock Sentry client."""
    client = mock.MagicMock(spec=SentryAlertClient)
    client.send_alert.return_value = True
    return client


@pytest.fixture
def monitor(mock_config, mock_sentry_client):
    """Create a DiskMonitor instance for testing."""
    return DiskMonitor(mock_config, mock_sentry_client)


class TestGetAlertLevel:
    """Tests for alert level determination."""

    def test_below_warning_returns_none(self, monitor):
        """Test that usage below warning threshold returns None."""
        assert monitor.get_alert_level(79.9) is None
        assert monitor.get_alert_level(50.0) is None
        assert monitor.get_alert_level(0.0) is None

    def test_at_warning_returns_warning(self, monitor):
        """Test that usage at warning threshold returns warning."""
        assert monitor.get_alert_level(80.0) == "warning"

    def test_between_warning_and_critical_returns_warning(self, monitor):
        """Test that usage between thresholds returns warning."""
        assert monitor.get_alert_level(85.0) == "warning"
        assert monitor.get_alert_level(89.9) == "warning"

    def test_at_critical_returns_critical(self, monitor):
        """Test that usage at critical threshold returns critical."""
        assert monitor.get_alert_level(90.0) == "critical"

    def test_above_critical_returns_critical(self, monitor):
        """Test that usage above critical threshold returns critical."""
        assert monitor.get_alert_level(95.0) == "critical"
        assert monitor.get_alert_level(100.0) == "critical"


class TestShouldAlert:
    """Tests for alert cooldown logic."""

    def test_first_alert_always_allowed(self, monitor):
        """Test that the first alert for a path/level is always allowed."""
        assert monitor.should_alert("/", "warning") is True
        assert monitor.should_alert("/", "critical") is True
        assert monitor.should_alert("/data", "warning") is True

    def test_alert_blocked_during_cooldown(self, monitor):
        """Test that repeated alerts are blocked during cooldown."""
        # Record an alert
        monitor.record_alert("/", "warning")

        # Should be blocked immediately after
        assert monitor.should_alert("/", "warning") is False

    def test_alert_allowed_after_cooldown(self, monitor):
        """Test that alerts are allowed after cooldown period."""
        # Record an alert in the past
        monitor.last_alerts["/"] = {"warning": time.time() - 3601}  # 1 second past cooldown

        assert monitor.should_alert("/", "warning") is True

    def test_different_levels_independent(self, monitor):
        """Test that warning and critical cooldowns are independent."""
        monitor.record_alert("/", "warning")

        # Warning should be blocked
        assert monitor.should_alert("/", "warning") is False
        # Critical should still be allowed
        assert monitor.should_alert("/", "critical") is True

    def test_different_paths_independent(self, monitor):
        """Test that cooldowns for different paths are independent."""
        monitor.record_alert("/", "warning")

        # Same path should be blocked
        assert monitor.should_alert("/", "warning") is False
        # Different path should be allowed
        assert monitor.should_alert("/data", "warning") is True


class TestCheckDiskUsage:
    """Tests for disk usage checking."""

    def test_returns_disk_usage(self, monitor):
        """Test that disk usage is returned for valid paths."""
        mock_usage = mock.MagicMock()
        mock_usage.total = 100 * 1024**3  # 100 GB
        mock_usage.used = 85 * 1024**3  # 85 GB
        mock_usage.free = 15 * 1024**3  # 15 GB
        mock_usage.percent = 85.0

        with mock.patch("psutil.disk_usage", return_value=mock_usage):
            result = monitor.check_disk_usage("/")

        assert result is not None
        assert result.path == "/"
        assert result.usage_percent == 85.0
        assert result.total_gb == pytest.approx(100.0)
        assert result.used_gb == pytest.approx(85.0)
        assert result.free_gb == pytest.approx(15.0)

    def test_returns_none_for_missing_path(self, monitor):
        """Test that None is returned for missing paths."""
        with mock.patch("psutil.disk_usage", side_effect=FileNotFoundError()):
            result = monitor.check_disk_usage("/nonexistent")

        assert result is None

    def test_returns_none_for_permission_error(self, monitor):
        """Test that None is returned for permission errors."""
        with mock.patch("psutil.disk_usage", side_effect=PermissionError()):
            result = monitor.check_disk_usage("/restricted")

        assert result is None

    def test_uses_hostfs_prefix(self, mock_config, mock_sentry_client):
        """Test that hostfs prefix is applied when checking disk usage."""
        mock_config.monitoring.hostfs_prefix = "/hostfs"
        monitor = DiskMonitor(mock_config, mock_sentry_client)

        mock_usage = mock.MagicMock()
        mock_usage.total = 100 * 1024**3
        mock_usage.used = 50 * 1024**3
        mock_usage.free = 50 * 1024**3
        mock_usage.percent = 50.0

        with mock.patch("psutil.disk_usage", return_value=mock_usage) as mock_disk:
            result = monitor.check_disk_usage("/")
            # Should call with prefixed path
            mock_disk.assert_called_once_with("/hostfs")
            # But result should have original path
            assert result.path == "/"


class TestRunCheck:
    """Tests for the check cycle."""

    def test_generates_alerts_for_high_usage(self, monitor):
        """Test that alerts are generated when usage exceeds thresholds."""
        mock_usage = mock.MagicMock()
        mock_usage.total = 100 * 1024**3
        mock_usage.used = 85 * 1024**3
        mock_usage.free = 15 * 1024**3
        mock_usage.percent = 85.0

        with mock.patch("psutil.disk_usage", return_value=mock_usage):
            alerts = monitor.run_check()

        # Should have warnings for both paths
        assert len(alerts) == 2
        assert all(a.level == "warning" for a in alerts)

    def test_no_alerts_for_low_usage(self, monitor):
        """Test that no alerts are generated for normal usage."""
        mock_usage = mock.MagicMock()
        mock_usage.total = 100 * 1024**3
        mock_usage.used = 50 * 1024**3
        mock_usage.free = 50 * 1024**3
        mock_usage.percent = 50.0

        with mock.patch("psutil.disk_usage", return_value=mock_usage):
            alerts = monitor.run_check()

        assert len(alerts) == 0

    def test_respects_cooldown_in_check(self, monitor):
        """Test that check respects cooldown for existing alerts."""
        # Record previous alert
        monitor.record_alert("/", "warning")

        mock_usage = mock.MagicMock()
        mock_usage.total = 100 * 1024**3
        mock_usage.used = 85 * 1024**3
        mock_usage.free = 15 * 1024**3
        mock_usage.percent = 85.0

        with mock.patch("psutil.disk_usage", return_value=mock_usage):
            alerts = monitor.run_check()

        # Should only have alert for /data, not /
        assert len(alerts) == 1
        assert alerts[0].path == "/data"

    def test_skips_inaccessible_paths(self, monitor):
        """Test that inaccessible paths are skipped."""

        def mock_disk_usage(path):
            if path == "/":
                raise FileNotFoundError()
            usage = mock.MagicMock()
            usage.total = 100 * 1024**3
            usage.used = 85 * 1024**3
            usage.free = 15 * 1024**3
            usage.percent = 85.0
            return usage

        with mock.patch("psutil.disk_usage", side_effect=mock_disk_usage):
            alerts = monitor.run_check()

        # Should only have alert for /data
        assert len(alerts) == 1
        assert alerts[0].path == "/data"


class TestDiskUsage:
    """Tests for DiskUsage dataclass."""

    def test_gb_conversions(self):
        """Test GB conversion properties."""
        usage = DiskUsage(
            path="/",
            total_bytes=100 * 1024**3,
            used_bytes=75 * 1024**3,
            free_bytes=25 * 1024**3,
            usage_percent=75.0,
        )

        assert usage.total_gb == pytest.approx(100.0)
        assert usage.used_gb == pytest.approx(75.0)
        assert usage.free_gb == pytest.approx(25.0)
