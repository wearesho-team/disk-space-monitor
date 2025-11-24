"""Tests for configuration handling."""

import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest
import yaml

from src.config import (
    Config,
    ThresholdsConfig,
    load_config,
)


class TestThresholdsConfig:
    """Tests for ThresholdsConfig validation."""

    def test_valid_thresholds(self):
        """Test valid threshold configuration."""
        config = ThresholdsConfig(warning=70, critical=90)
        assert config.warning == 70
        assert config.critical == 90

    def test_warning_must_be_less_than_critical(self):
        """Test that warning must be less than critical."""
        with pytest.raises(ValueError, match="Warning threshold.*must be less than critical"):
            ThresholdsConfig(warning=90, critical=80)

    def test_warning_equals_critical_invalid(self):
        """Test that warning cannot equal critical."""
        with pytest.raises(ValueError, match="Warning threshold.*must be less than critical"):
            ThresholdsConfig(warning=80, critical=80)

    def test_warning_below_zero_invalid(self):
        """Test that warning must be positive."""
        with pytest.raises(ValueError, match="Warning threshold must be between 0 and 100"):
            ThresholdsConfig(warning=0, critical=90)

    def test_warning_above_100_invalid(self):
        """Test that warning must be below 100."""
        with pytest.raises(ValueError, match="Warning threshold must be between 0 and 100"):
            ThresholdsConfig(warning=100, critical=100)

    def test_critical_above_100_invalid(self):
        """Test that critical must be at most 100."""
        with pytest.raises(ValueError, match="Critical threshold must be between 0 and 100"):
            ThresholdsConfig(warning=80, critical=101)


class TestConfigGetRealPath:
    """Tests for path translation with hostfs prefix."""

    def test_no_prefix_returns_original(self):
        """Test that paths are unchanged without hostfs prefix."""
        config = Config(
            sentry=mock.MagicMock(dsn="test"),
            monitoring=mock.MagicMock(hostfs_prefix="", paths=["/"]),
            thresholds=mock.MagicMock(),
            alerts=mock.MagicMock(),
            logging=mock.MagicMock(),
            hostname="test",
        )
        assert config.get_real_path("/") == "/"
        assert config.get_real_path("/var/lib") == "/var/lib"

    def test_with_prefix_translates_root(self):
        """Test that root path is translated with prefix."""
        config = Config(
            sentry=mock.MagicMock(dsn="test"),
            monitoring=mock.MagicMock(hostfs_prefix="/hostfs", paths=["/"]),
            thresholds=mock.MagicMock(),
            alerts=mock.MagicMock(),
            logging=mock.MagicMock(),
            hostname="test",
        )
        assert config.get_real_path("/") == "/hostfs"

    def test_with_prefix_translates_subpath(self):
        """Test that subpaths are translated with prefix."""
        config = Config(
            sentry=mock.MagicMock(dsn="test"),
            monitoring=mock.MagicMock(hostfs_prefix="/hostfs", paths=["/"]),
            thresholds=mock.MagicMock(),
            alerts=mock.MagicMock(),
            logging=mock.MagicMock(),
            hostname="test",
        )
        assert config.get_real_path("/var/lib/docker") == "/hostfs/var/lib/docker"

    def test_prefix_with_trailing_slash(self):
        """Test that trailing slash in prefix is handled."""
        config = Config(
            sentry=mock.MagicMock(dsn="test"),
            monitoring=mock.MagicMock(hostfs_prefix="/hostfs/", paths=["/"]),
            thresholds=mock.MagicMock(),
            alerts=mock.MagicMock(),
            logging=mock.MagicMock(),
            hostname="test",
        )
        assert config.get_real_path("/") == "/hostfs"
        assert config.get_real_path("/var") == "/hostfs/var"


class TestLoadConfig:
    """Tests for configuration loading."""

    def test_missing_dsn_raises_error(self):
        """Test that missing SENTRY_DSN raises an error."""
        with mock.patch.dict(os.environ, {}, clear=True):
            # Clear any existing env vars
            for key in ["SENTRY_DSN", "SENTRY_ENVIRONMENT"]:
                os.environ.pop(key, None)
            with pytest.raises(ValueError, match="SENTRY_DSN is required"):
                load_config()

    def test_env_vars_override_yaml(self):
        """Test that environment variables override YAML config."""
        yaml_content = {
            "sentry": {"dsn": "yaml-dsn", "environment": "yaml-env"},
            "monitoring": {"paths": ["/yaml"], "check_interval": 100},
            "thresholds": {"warning": 70, "critical": 85},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(yaml_content, f)
            config_path = f.name

        try:
            env_vars = {
                "SENTRY_DSN": "env-dsn",
                "SENTRY_ENVIRONMENT": "env-env",
                "MONITOR_PATHS": "/env1,/env2",
                "CHECK_INTERVAL": "200",
                "WARNING_THRESHOLD": "75",
                "CRITICAL_THRESHOLD": "95",
            }
            with mock.patch.dict(os.environ, env_vars, clear=False):
                config = load_config(config_path)

            # Env vars should take precedence
            assert config.sentry.dsn == "env-dsn"
            assert config.sentry.environment == "env-env"
            assert config.monitoring.paths == ["/env1", "/env2"]
            assert config.monitoring.check_interval == 200
            assert config.thresholds.warning == 75
            assert config.thresholds.critical == 95
        finally:
            Path(config_path).unlink()

    def test_yaml_config_defaults(self):
        """Test that YAML config is used when env vars not set."""
        yaml_content = {
            "sentry": {"dsn": "yaml-dsn", "environment": "staging"},
            "monitoring": {"paths": ["/", "/data"], "check_interval": 600},
            "thresholds": {"warning": 75, "critical": 85},
            "alerts": {"cooldown": 7200},
            "logging": {"level": "DEBUG"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(yaml_content, f)
            config_path = f.name

        try:
            # Clear relevant env vars
            clean_env = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith("SENTRY")
                and k
                not in [
                    "MONITOR_PATHS",
                    "CHECK_INTERVAL",
                    "WARNING_THRESHOLD",
                    "CRITICAL_THRESHOLD",
                    "ALERT_COOLDOWN",
                    "LOG_LEVEL",
                    "HOSTNAME_OVERRIDE",
                ]
            }
            with mock.patch.dict(os.environ, clean_env, clear=True):
                config = load_config(config_path)

            assert config.sentry.dsn == "yaml-dsn"
            assert config.sentry.environment == "staging"
            assert config.monitoring.paths == ["/", "/data"]
            assert config.monitoring.check_interval == 600
            assert config.thresholds.warning == 75
            assert config.thresholds.critical == 85
            assert config.alerts.cooldown == 7200
            assert config.logging.level == "DEBUG"
        finally:
            Path(config_path).unlink()

    def test_monitor_paths_parsing(self):
        """Test parsing of comma-separated monitor paths."""
        with mock.patch.dict(
            os.environ,
            {
                "SENTRY_DSN": "test-dsn",
                "MONITOR_PATHS": "/path1, /path2 , /path3",
            },
            clear=False,
        ):
            config = load_config()

        assert config.monitoring.paths == ["/path1", "/path2", "/path3"]

    def test_hostname_override(self):
        """Test hostname override from environment."""
        with mock.patch.dict(
            os.environ,
            {
                "SENTRY_DSN": "test-dsn",
                "HOSTNAME_OVERRIDE": "custom-host",
            },
            clear=False,
        ):
            config = load_config()

        assert config.hostname == "custom-host"
