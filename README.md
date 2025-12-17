# CT Moniteur - Certificate Transparency Log Monitor

A Python library for monitoring Certificate Transparency (CT) logs with support for both classic and modern tiled CT logs. Monitor all public CT logs with async operations, state persistence, and easy-to-use APIs.

## Disclaimer

This library is an independent project and is not an official product. It is provided as-is, without warranties or guarantees of any kind. While it has been used successfully by some of our analysts, it is not intended for production use and should not be treated as production-ready software.

## Features

- **Concurrent monitoring** - Built on `asyncio` and `httpx` to monitor dozens of logs simultaneously
- **Dual protocol support** - Works with both classic and tiled CT logs
- **State persistence** - Save and resume monitoring from previous state
- **Periodic log list refresh** - Automatically discover new logs and remove retired ones
- **Automatic retries** - Built-in retry logic with configurable retry count and delay
- **Statistics tracking** - Monitor processing stats per log
- **Flexible callbacks** - Support for both sync and async callback functions
- **Multi-log monitoring** - Monitor all public CT logs concurrently
- **Comprehensive error handling** - Robust error handling and logging
- **CLI tool included** - Monitor CT logs without writing code
- **Connection pool tuning** - Configure max connections and keepalive
- **Log filtering** - Include/exclude logs by URL patterns
- **Sharding support** - Distribute logs across multiple instances
- **Raw mode** - Fetcher-parser architecture for high-volume logs
- **Parallel parsing** - ProcessPoolExecutor for CPU-bound certificate parsing
- **Gap tracking** - Failed ranges tracked and retried, no data loss on transient errors
- **Extended state** - Per-log state with current_index, highest_fetched, and gaps

## Installation

Install directly from GitHub:

```bash
pip install git+https://github.com/CERT-Polska/ct-moniteur
```

Or clone and install locally:

```bash
git clone https://github.com/CERT-Polska/ct-moniteur
cd ct-moniteur
pip install .
```

## Command-Line Tool

The library includes a simple `ct-moniteur` command-line demo tool.

### Basic Usage

Monitor all CT logs and print domains to console:

```bash
ct-moniteur
```

Output:
```
[2025-10-05T14:23:45.123456] https://ct.googleapis.com/logs/argon2024 - [example.com, www.example.com]
[2025-10-05T14:23:45.234567] https://oak.ct.letsencrypt.org/2024h1 - [test.org]
```

### Domains Only

Output only domain names (one per line) for easy processing with bash tools:

```bash
ct-moniteur --domains-only
```

Output:
```
example.com
www.example.com
test.org
mail.test.org
```

### JSON Output

Output certificates in JSON format:

```bash
ct-moniteur --json
```

Output:
```json
{"timestamp": 1728137025123, "entry_type": "X509LogEntry", "source": {"index": 12345, "log": {"url": "https://ct.googleapis.com/logs/argon2024", "name": "Argon 2024", "operator": "Google"}}, "domains": ["example.com", "www.example.com"], "subject": "CN=example.com", "issuer": "CN=Let's Encrypt", ...}
```

### Verbose Logging

Enable detailed logging:

```bash
ct-moniteur --verbose
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--domains-only` | Output only domain names |
| `--json` | Format output as JSON |
| `--verbose` | Display debug logging |

## Quick Start

### Basic Usage - Print All Domains

```python
import asyncio
from ct_moniteur import CTMoniteur

def process_certificate(entry):
    """Process each certificate entry"""
    print(entry.domains)

async def main():
    # Create monitor
    monitor = CTMoniteur(callback=process_certificate)
    
    try:
        # Start monitoring from current position
        await monitor.start()
        
        # Run indefinitely (or until Ctrl+C)
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await monitor.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

## State Persistence Example

The library supports full state persistence, allowing you to resume monitoring from where you left off after restarts.

```python
import asyncio
import json
from pathlib import Path
from ct_moniteur import CTMoniteur

STATE_FILE = Path("ct_state.json")
SAVE_INTERVAL = 60  # Save state every 60 seconds

def load_state():
    """Load previous state from disk"""
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            state = json.load(f)
        print(f"Loaded state with {len(state)} logs")
        return state
    return None

def save_state(monitor):
    """Save current state to disk"""
    state = monitor.get_state()
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)
    print(f"State saved ({len(state)} logs tracked)")

def process_certificate(entry):
    """Process each certificate entry"""
    # Print all domains
    print(f"[{entry.source.log.name}] {', '.join(entry.domains)}")
    
    # Example: Filter for specific domains
    if any(domain.endswith('.example.com') for domain in entry.domains):
        print(f"  -> Found example.com certificate!")

async def main():
    # Load previous state (or start from current position if no state exists)
    initial_state = load_state()
    
    # Create monitor with state
    monitor = CTMoniteur(
        callback=process_certificate,
        initial_state=initial_state
    )
    
    try:
        # Start monitoring
        await monitor.start()
        
        # Periodically save state
        while True:
            await asyncio.sleep(SAVE_INTERVAL)
            save_state(monitor)
            
            # Print statistics
            stats = monitor.get_stats()
            print(f"Total entries processed: {stats.total_entries_processed}")
            print(f"Active logs: {stats.active_logs}")
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Save final state before exiting
        save_state(monitor)
        await monitor.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

## Sharding and Filtering

### Log Filtering

Include or exclude specific logs by URL patterns:

```python
# Only monitor Google logs
monitor = CTMoniteur(
    callback=process_certificate,
    include_logs=["googleapis.com"]
)

# Exclude Let's Encrypt logs
monitor = CTMoniteur(
    callback=process_certificate,
    exclude_logs=["letsencrypt.org"]
)

# Combine both
monitor = CTMoniteur(
    callback=process_certificate,
    include_logs=["googleapis.com", "cloudflare"],
    exclude_logs=["argon2025"]
)
```

### Distributed Processing with Sharding

Automatically distribute logs across multiple instances using hash-based sharding:

```python
# Instance 0 of 6
monitor = CTMoniteur(
    callback=process_certificate,
    shard_id=0,
    total_shards=6
)

# Instance 1 of 6
monitor = CTMoniteur(
    callback=process_certificate,
    shard_id=1,
    total_shards=6
)
```

**Algorithm:** `(md5(hostname) + md5(path)) % total_shards`

- Uses MD5 hash (deterministic across processes, unlike Python's `hash()`)
- Combines hostname and path hashes to spread same-host logs across shards
- Example: ct.googleapis.com has 46 logs → distributed across all shards

**Benefits:**
- High-volume hostnames spread across all shards (not clustered)
- Stable: adding/removing logs doesn't reshuffle existing assignments
- New logs automatically assigned without coordination
- Scale by increasing `total_shards` and adding instances

### Connection Pool Tuning

Adjust connection limits for high-throughput scenarios:

```python
monitor = CTMoniteur(
    callback=process_certificate,
    max_connections=200,           # Total connections
    max_keepalive_connections=50   # Persistent connections
)
```

## Raw Mode (Fetcher-Parser Architecture)

For high-volume logs, separate network I/O from CPU-bound parsing using raw mode:

```python
from ct_moniteur import CTMoniteur, RawEntry

def on_raw_entry(raw: RawEntry):
    """Receive raw certificate data without parsing"""
    # Push to queue for separate parser workers
    queue.push({
        "index": raw.index,
        "timestamp": raw.timestamp,
        "entry_type": raw.entry_type,  # 0=X509, 1=Precert
        "cert_data": raw.cert_data,    # DER-encoded bytes
        "log_url": raw.log_url,
        "log_name": raw.log_name,
        "log_operator": raw.log_operator
    })

# Fetcher: only fetch, no parsing
monitor = CTMoniteur(
    raw_callback=on_raw_entry,
    include_logs=["argon", "xenon"],
    log_prefix="fetcher",     # Shows as "fetcher:" in log messages
    parallel_fetches=8,       # 8 parallel batch requests per log
)
```

**Why use raw mode:**
- Parsing is CPU-bound (GIL contention in Python)
- Network I/O and parsing can be scaled independently
- Single fetcher → queue → N parser workers
- Adding parser workers actually helps (vs entry-level sharding where each shard fetches everything)
- `parallel_fetches` reduces latency by having multiple requests in flight (within connection pool limits)

**Gap tracking (raw mode):**
- Speculative parallel fetching may have some requests fail (transient errors, rate limits)
- Failed ranges are tracked as "gaps" and retried on subsequent iterations
- Successful entries are yielded immediately (no caching needed - they're processed)
- `current_index` only advances when entries are contiguous (safe restart point)
- `highest_fetched` tracks how far ahead we've fetched
- CT logs are append-only/immutable, so failed ranges can safely be retried later

### Parallel Parsing (In-Process)

For moderate volume, use in-process parallel parsing with ProcessPoolExecutor:

```python
monitor = CTMoniteur(
    callback=process_certificate,
    parse_workers=4  # Parse certificates in parallel (0=sequential)
)
```

**Note:** `parse_workers` uses ProcessPoolExecutor to bypass GIL. Good for moderate volume, but for very high volume logs, raw mode with separate parser workers scales better.

## API Reference

### CTMoniteur

Main class for monitoring all CT logs.

**Constructor:**
```python
CTMoniteur(
    callback: Callable = None,       # Function to process parsed entries (sync or async)
    raw_callback: Callable = None,   # Function to process raw entries (no parsing)
    initial_state: Dict[str, Any],   # Optional: {log_url: LogState dict or int}
    skip_retired: bool = True,       # Skip retired logs
    poll_interval: float = 30.0,     # Polling interval in seconds
    timeout: float = 30.0,           # HTTP timeout
    user_agent: str = None,          # Custom user agent
    max_retries: int = 3,            # Max retries per log
    retry_delay: float = 10.0,       # Delay between retries
    refresh_interval: float = 6.0,   # Log list refresh interval in hours (0 to disable)
    max_connections: int = 100,      # HTTP connection pool size
    max_keepalive_connections: int = 20,  # Keepalive connections
    include_logs: List[str] = None,  # Only include logs matching patterns
    exclude_logs: List[str] = None,  # Exclude logs matching patterns
    shard_id: int = None,            # Shard ID for distributed processing
    total_shards: int = None,        # Total number of shards
    parse_workers: int = 0,          # Parallel parsing processes (0=sequential)
    log_prefix: str = None,          # Custom prefix for log messages (e.g. "fetcher")
    parallel_fetches: int = 1,       # Parallel batch fetches per log (raw mode)
)
```

**Note:** Provide either `callback` (parsed entries) or `raw_callback` (raw entries), not both.

**Methods:**
- `start()` - Start monitoring all logs
- `stop()` - Stop monitoring gracefully
- `get_state()` - Get current state (dict of log_url -> {current_index, highest_fetched, gaps})
- `get_stats()` - Get monitoring statistics

### CertificateEntry

Each certificate entry contains:

- `timestamp` - Certificate timestamp
- `entry_type` - "X509LogEntry" or "PrecertLogEntry"
- `certificate` - Raw X.509 certificate object
- `source` - EntrySource object containing:
  - `index` - Entry index in the log
  - `log` - LogMeta object with:
    - `url` - Source CT log URL
    - `name` - Source CT log name
    - `operator` - Log operator name
- `domains` - List of domains (CN + SANs)
- `subject` - Certificate subject
- `issuer` - Certificate issuer
- `not_before` - Valid from datetime
- `not_after` - Valid until datetime
- `serial_number` - Certificate serial number (hex)
- `fingerprint_sha256` - SHA-256 fingerprint
- `fingerprint_sha1` - SHA-1 fingerprint

### RawEntry

Raw certificate entry (used with `raw_callback`):

- `index` - Entry index in the log
- `timestamp` - Entry timestamp (milliseconds)
- `entry_type` - 0 for X509LogEntry, 1 for PrecertLogEntry
- `cert_data` - DER-encoded certificate bytes
- `log_url` - Source CT log URL
- `log_name` - Source CT log name
- `log_operator` - Log operator name

### LogState

Extended state for a single CT log with gap tracking:

- `current_index` - Highest contiguous index (safe restart point)
- `highest_fetched` - Highest index successfully fetched
- `gaps` - List of [start, end] ranges that failed and need retry

**Methods:**
- `to_dict()` - Convert to dictionary for serialization
- `from_dict(data)` - Create from dictionary (handles backwards compat with int)

### MoniteurStats

Statistics tracked during monitoring:

- `total_entries_processed` - Total number of certificates processed
- `entries_per_log` - Dictionary of entries processed per log
- `errors_per_log` - Dictionary of errors encountered per log
- `active_logs` - Number of logs being monitored
- `start_time` - Monitoring start time

## State File Format

The state is a JSON dictionary with extended per-log tracking:

```json
{
  "https://ct.googleapis.com/logs/argon2024": {
    "current_index": 12345678,
    "highest_fetched": 12345800,
    "gaps": []
  },
  "https://oak.ct.letsencrypt.org/2024h1": {
    "current_index": 87654321,
    "highest_fetched": 87654500,
    "gaps": [[87654400, 87654450]]
  }
}
```

Each log URL maps to a state object with:
- `current_index` - Highest contiguous index (safe restart point)
- `highest_fetched` - Highest index successfully fetched
- `gaps` - List of [start, end] ranges that failed and need retry

**Backwards compatibility:** Old state format (just an integer) is automatically converted.

## Performance Considerations

- The library monitors ~71 active CT logs concurrently using asyncio
- Use async callbacks for I/O operations (database, API calls)
- Save state periodically (every 15 minutes) - state includes gap tracking for recovery
- Consider filtering certificates in the callback to reduce processing load
- Logs are polled with staggered delays to avoid request bursts
- Poll cycle warnings include Unix timestamp and prefix for debugging:
  ```
  1765798677:fetcher-google:Poll cycle for https://ct.googleapis.com/logs/us1/argon2026h1/ exceeded interval by 12.42s
  ```
- Gap tracking ensures no data loss on transient errors or restarts

## License

BSD 3-Clause
