# Disk Space Monitor

A Python-based disk space monitoring tool that runs in Docker and sends alerts to Sentry when disk usage exceeds configurable thresholds.

## Features

- Monitor multiple mount points/paths
- Configurable warning and critical thresholds
- Alert cooldown to prevent duplicate notifications
- Self-hosted Sentry support
- Docker-ready with host filesystem monitoring
- Proper Sentry event grouping and tagging
- Test mode to verify Sentry connectivity

## Quick Start

### Using Docker Compose (Recommended)

1. Clone the repository:
```bash
git clone <repository-url>
cd disk-space-monitor
```

2. Create your configuration:
```bash
cp .env.example .env
```

3. Edit `.env` with your Sentry DSN:
```bash
SENTRY_DSN=https://your-key@your-sentry-host/project-id
```

4. Start the monitor:
```bash
docker-compose up -d
```

5. View logs:
```bash
docker-compose logs -f
```

### Running Locally

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export SENTRY_DSN=https://your-key@your-sentry-host/project-id
```

3. Run the monitor:
```bash
python -m src.monitor
```

### Testing Sentry Connectivity

Before running the monitor continuously, you can send a test event to verify Sentry is properly configured:

```bash
# Local
python -m src.monitor --test

# Docker
docker-compose run --rm disk-monitor python -m src.monitor --test
```

This sends an info-level event with current disk usage to Sentry and exits. Check your Sentry dashboard to confirm the event was received.

## Command-Line Options

```
python -m src.monitor [OPTIONS]

Options:
  --test          Send a test event to Sentry and exit
  --config PATH   Path to config file (default: config.yml)
  -h, --help      Show help message
```

## Configuration

The monitor can be configured via environment variables or a YAML config file. Environment variables take precedence.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SENTRY_DSN` | Sentry DSN (required) | - |
| `SENTRY_ENVIRONMENT` | Sentry environment name | `production` |
| `MONITOR_PATHS` | Comma-separated paths to monitor | `/` |
| `CHECK_INTERVAL` | Seconds between checks | `300` |
| `WARNING_THRESHOLD` | Warning threshold percentage | `80` |
| `CRITICAL_THRESHOLD` | Critical threshold percentage | `90` |
| `ALERT_COOLDOWN` | Seconds before repeating same alert | `3600` |
| `HOSTNAME_OVERRIDE` | Override detected hostname | auto-detected |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `HOSTFS_PREFIX` | Prefix for host filesystem in Docker | `/hostfs` (in Docker) |
| `CONFIG_PATH` | Path to YAML config file | `config.yml` |

### YAML Configuration

Create a `config.yml` file:

```yaml
sentry:
  dsn: "https://your-key@your-sentry-host/project-id"
  environment: "production"

monitoring:
  paths:
    - /
    - /var/lib/docker
  check_interval: 300  # seconds

thresholds:
  warning: 80   # percentage
  critical: 90  # percentage

alerts:
  cooldown: 3600  # seconds

logging:
  level: INFO
```

## Docker Setup

### Monitoring Host Filesystem

When running in Docker, the host filesystem is mounted at `/hostfs`:

```yaml
volumes:
  - /:/hostfs:ro
```

The monitor automatically translates paths (e.g., `/` becomes `/hostfs/`) when `HOSTFS_PREFIX=/hostfs` is set.

### Resource Limits

The default `docker-compose.yml` includes resource limits:
- CPU: 0.25 cores (max)
- Memory: 128MB (max)

These can be adjusted based on your needs.

### Custom Config File in Docker

To use a YAML config file with Docker:

```yaml
volumes:
  - /:/hostfs:ro
  - ./config.yml:/app/config.yml:ro
```

## Sentry Setup

### Creating a Sentry Project

1. Log into your Sentry instance
2. Create a new project (Platform: Python)
3. Copy the DSN from Project Settings > Client Keys

### Alert Structure

Alerts are sent to Sentry with:

**Tags:**
- `monitor_type`: `disk_space`
- `host`: hostname of the monitored server
- `mount_point`: the monitored path (e.g., `/`, `/var/lib/docker`)
- `alert_level`: `warning` or `critical`

**Extra Context:**
- `usage_percent`: current usage percentage
- `used_gb`: used space in GB
- `free_gb`: free space in GB
- `total_gb`: total space in GB

**Fingerprinting:**

Events are grouped by `[monitor_type, host, mount_point, alert_level]` so that:
- Different hosts create separate issues
- Different mount points create separate issues
- Warning and critical alerts create separate issues

### Example Sentry Alert

```
Disk space critical: 92.5% used on / (15.0 GB free of 200.0 GB)
```

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html
```

## Troubleshooting

### Monitor can't see host disk usage

Ensure the host filesystem is mounted correctly:
```yaml
volumes:
  - /:/hostfs:ro
```

And `HOSTFS_PREFIX=/hostfs` is set.

### Alerts not appearing in Sentry

1. Check the Sentry DSN is correct
2. Verify network connectivity to your Sentry instance
3. Check logs for connection errors:
   ```bash
   docker-compose logs disk-monitor | grep -i error
   ```

### Permission errors

The container runs as a non-root user. Ensure mounted paths are readable:
```bash
# Check host filesystem permissions
ls -la /
```

### Too many alerts

Increase the cooldown period:
```bash
ALERT_COOLDOWN=7200  # 2 hours
```

### Debug logging

Enable debug logging for more information:
```bash
LOG_LEVEL=DEBUG
```

## Architecture

```
src/
├── __init__.py
├── config.py        # Configuration loading and validation
├── sentry_client.py # Sentry SDK integration
└── monitor.py       # Core monitoring logic and main loop
```

### Flow

1. Load configuration from environment/YAML
2. Initialize Sentry SDK
3. Start monitoring loop:
   - Check disk usage for each configured path
   - Determine if thresholds are exceeded
   - Check if alert is on cooldown
   - Send alerts to Sentry if needed
   - Sleep for check interval
