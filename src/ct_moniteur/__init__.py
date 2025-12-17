"""
Certificate Transparency Log Monitor Library
Supports both classic and tiled CT logs with async operations and state persistence.
"""

import asyncio
import base64
import hashlib
import logging
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Union, cast

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .binary_reader import BinaryReader, DataType, Endianness
from .httpx_ratelimit import RateLimitedTransport

__version__ = "1.0.0"

# Create module logger
logger = logging.getLogger(__name__)
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"


class EntryType(IntEnum):
    """CT log entry types"""

    X509_ENTRY = 0
    PRECERT_ENTRY = 1


@dataclass
class TiledCheckpoint:
    """Checkpoint information from a tiled CT log"""

    origin: str
    size: int
    hash: str


@dataclass
class SignedTreeHead:
    """Signed Tree Head from a classic CT log"""

    tree_size: int
    timestamp: int
    sha256_root_hash: str
    tree_head_signature: str


@dataclass
class LogEntry:
    """Single entry from a CT log"""

    timestamp: int
    entry_type: EntryType
    entry: bytes
    chain: List[bytes] = field(default_factory=list)


@dataclass
class LogMeta:
    """Metadata about a CT log"""

    url: str
    name: str
    operator: str


@dataclass
class EntrySource:
    """Source information for a certificate entry"""

    index: int
    log: LogMeta


@dataclass
class CertificateEntry:
    """Parsed certificate entry"""

    timestamp: int
    entry_type: str  # "X509LogEntry" or "PrecertLogEntry"
    source: EntrySource

    # Certificate details
    domains: List[str] = field(default_factory=list)
    subject: str = ""
    issuer: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial_number: str = ""
    fingerprint_sha256: str = ""
    fingerprint_sha1: str = ""
    certificate: Optional[x509.Certificate] = None  # Optional for multiprocessing


@dataclass
class RawEntry:
    """Unparsed entry for deferred parsing (fetcher -> parser architecture)."""

    index: int
    timestamp: int
    entry_type: int  # 0=X509, 1=Precert
    cert_data: bytes  # DER encoded certificate
    log_url: str
    log_name: str
    log_operator: str


@dataclass
class LogState:
    """Extended state for a single CT log with gap tracking."""

    current_index: int = 0  # Highest contiguous index (safe restart point)
    highest_fetched: int = 0  # Highest index we've successfully fetched
    gaps: List[List[int]] = field(default_factory=list)  # [[start, end], ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current_index": self.current_index,
            "highest_fetched": self.highest_fetched,
            "gaps": self.gaps,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogState":
        if isinstance(data, int):
            # Backwards compatibility: old format was just an int
            return cls(current_index=data, highest_fetched=data, gaps=[])
        return cls(
            current_index=data.get("current_index", 0),
            highest_fetched=data.get("highest_fetched", 0),
            gaps=data.get("gaps", []),
        )


@dataclass
class MoniteurStats:
    """Statistics for monitoring"""

    total_entries_processed: int = 0
    entries_per_log: Dict[str, int] = field(default_factory=dict)
    errors_per_log: Dict[str, int] = field(default_factory=dict)
    active_logs: int = 0
    start_time: Optional[datetime] = None


def _mp_parse_entry(args: tuple) -> Optional[tuple]:
    """
    Multiprocessing worker for certificate parsing.
    Must be module-level for pickling.

    Args:
        args: (entry_index, timestamp, entry_type_val, entry_data,
               log_url, log_name, log_operator)

    Returns:
        Tuple of parsed data or None on error
    """
    (entry_index, timestamp, entry_type_val, entry_data,
     log_url, log_name, log_operator) = args

    try:
        if entry_type_val == 0:
            entry_type_str = "X509LogEntry"
        elif entry_type_val == 1:
            entry_type_str = "PrecertLogEntry"
        else:
            return None

        cert = x509.load_der_x509_certificate(entry_data, default_backend())

        # Extract domains
        domains: List[str] = []
        try:
            cn_attr = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_attr:
                cn_value = cn_attr[0].value
                if isinstance(cn_value, bytes):
                    cn_value = cn_value.decode("utf-8", errors="ignore")
                domains.append(str(cn_value))
        except Exception:
            pass

        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
            domains.extend(san_names)
        except Exception:
            pass

        domains = list(set(domains))

        # Calculate fingerprints
        sha256_fp = ":".join(f"{b:02X}" for b in hashlib.sha256(entry_data).digest())
        sha1_fp = ":".join(f"{b:02X}" for b in hashlib.sha1(entry_data).digest())

        return (
            entry_index,
            timestamp,
            entry_type_str,
            domains,
            cert.subject.rfc4514_string(),
            cert.issuer.rfc4514_string(),
            cert.not_valid_before_utc,
            cert.not_valid_after_utc,
            format(cert.serial_number, "X"),
            sha256_fp,
            sha1_fp,
            log_url,
            log_name,
            log_operator,
        )
    except Exception:
        return None


class TiledLogClient:
    """Client for interacting with tiled CT logs"""

    DEFAULT_USER_AGENT = f"CT-Moniteur/{__version__}"
    TILE_SIZE = 256
    PARSE_BATCH_SIZE = 256  # Parse this many entries in parallel
    RAW_BATCH_SIZE = 1000   # Entries per batch in raw mode

    def __init__(
        self,
        log_meta: LogMeta,
        timeout: float = 30.0,
        user_agent: Optional[str] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        shard_id: Optional[int] = None,
        total_shards: Optional[int] = None,
        executor: Optional[ProcessPoolExecutor] = None,
        log_prefix: Optional[str] = None,
        parallel_fetches: int = 1,
    ):
        self.log_meta = log_meta
        self.timeout = timeout
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        self.shard_id = shard_id
        self.total_shards = total_shards
        self._executor = executor
        self._log_prefix = log_prefix
        self._parallel_fetches = parallel_fetches
        self._client = httpx.AsyncClient(
            base_url=log_meta.url,
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            transport=transport or RateLimitedTransport(),
        )

    def _get_group_prefix(self) -> str:
        """Get group-aware prefix based on log URL or custom prefix."""
        if self._log_prefix:
            return f"{self._log_prefix}:"
        if self.shard_id is None:
            return ""
        url = self.log_meta.url
        # Check for specific high-volume log names first
        if "/argon" in url:
            return f"argon{self.shard_id}:"
        elif "/xenon" in url:
            return f"xenon{self.shard_id}:"
        elif "googleapis.com" in url:
            return f"google{self.shard_id}:"
        elif "trustasia.com" in url:
            return f"trustasia{self.shard_id}:"
        else:
            return f"shard{self.shard_id}:"

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def close(self):
        """Close the HTTP client"""
        await self._client.aclose()

    async def fetch_checkpoint(self) -> TiledCheckpoint:
        """Fetch the checkpoint from a tiled CT log"""
        response = await self._client.get("/checkpoint")
        response.raise_for_status()

        lines = response.text.strip().split("\n")
        if len(lines) < 3:
            raise ValueError(
                f"Invalid checkpoint format: expected at least 3 lines, got {len(lines)}"
            )

        return TiledCheckpoint(origin=lines[0], size=int(lines[1]), hash=lines[2])

    async def fetch_tree_size(self) -> int:
        """Fetch the current tree size (number of entries in the log)"""
        checkpoint = await self.fetch_checkpoint()
        return checkpoint.size

    async def fetch_tile(
        self, tile_index: int, partial_width: Optional[int] = None
    ) -> List[LogEntry]:
        """
        Fetch a tile from the tiled CT log

        Args:
            tile_index: The index of the tile to fetch
            partial_width: If specified, fetch a partial tile with this width (1-255)
        """
        tile_path = self._encode_tile_path(tile_index)

        # Add partial tile suffix if specified
        if partial_width is not None:
            if not (1 <= partial_width <= 255):
                raise ValueError(
                    f"Partial tile width must be between 1 and 255, got {partial_width}"
                )
            tile_path = f"{tile_path}.p/{partial_width}"

        response = await self._client.get(f"/tile/data/{tile_path}")
        response.raise_for_status()

        return self._parse_tile_data(response.content)

    async def fetch_issuer(self, fingerprint: bytes) -> bytes:
        """
        Fetch an issuer certificate by its SHA-256 fingerprint.

        Args:
            fingerprint: 32-byte SHA-256 hash of the ASN.1 encoding of the issuer certificate

        Returns:
            ASN.1-encoded issuer certificate bytes
        """
        # Convert fingerprint bytes to lowercase hex string
        fingerprint_hex = fingerprint.hex().lower()

        response = await self._client.get(f"/issuer/{fingerprint_hex}")
        response.raise_for_status()

        return response.content

    @staticmethod
    def _encode_tile_path(index: int) -> str:
        """
        Encode a tile index into the proper path format.
        Example: 1234567 -> x001/x234/567
        """
        if index == 0:
            return "000"

        groups = []
        n = index
        while n > 0:
            groups.append(n % 1000)
            n //= 1000

        groups.reverse()

        parts = [f"x{g:03d}" for g in groups[:-1]] + [f"{groups[-1]:03d}"]
        return "/".join(parts)

    def _parse_tile_data(self, data: bytes) -> List[LogEntry]:
        """Parse binary tile data into LogEntry entries"""
        reader = BinaryReader(data, Endianness.BIG)
        leaves: List[LogEntry] = []

        while reader.remaining >= 10:  # Minimum header size
            # Read timestamp (8 bytes) and entry_type (2 bytes)
            timestamp = reader.read(DataType.UINT, 8)
            entry_type = reader.read(DataType.UINT, 2)

            entry_data: bytes
            chain: List[bytes] = []

            if entry_type == EntryType.X509_ENTRY:
                # Read certificate (3-byte length)
                if not reader.has_bytes(3):
                    break
                cert_len = reader.read(DataType.UINT, 3)

                if not reader.has_bytes(cert_len):
                    break
                entry_data = reader.read(DataType.BYTES, cert_len)

                # Read extensions (skip)
                if not reader.has_bytes(2):
                    break
                ext_len = reader.read(DataType.UINT, 2)
                if not reader.has_bytes(ext_len):
                    break
                reader.skip(ext_len)

            elif entry_type == EntryType.PRECERT_ENTRY:
                # Skip issuer key hash
                if not reader.has_bytes(32):
                    break
                reader.skip(32)

                # Read TBSCertificate length and skip it
                if not reader.has_bytes(3):
                    break
                tbs_len = reader.read(DataType.UINT, 3)

                if not reader.has_bytes(tbs_len):
                    break
                reader.skip(tbs_len)

                # Read extensions (skip)
                if not reader.has_bytes(2):
                    break
                ext_len = reader.read(DataType.UINT, 2)
                if not reader.has_bytes(ext_len):
                    break
                reader.skip(ext_len)

                # Read the pre_certificate from LogEntry
                if not reader.has_bytes(3):
                    break
                cert_len = reader.read(DataType.UINT, 3)

                if not reader.has_bytes(cert_len):
                    break
                entry_data = reader.read(DataType.BYTES, cert_len)

            else:
                raise ValueError(f"Unknown entry type: {entry_type}")

            # Read fingerprints
            if not reader.has_bytes(2):
                break
            fp_len = reader.read(DataType.UINT, 2)

            if not reader.has_bytes(fp_len):
                break

            # Parse fingerprints (32 bytes each)
            fp_count = fp_len // 32
            for _ in range(fp_count):
                if reader.has_bytes(32):
                    fingerprint = reader.read(DataType.BYTES, 32)
                    chain.append(fingerprint)

            leaf = LogEntry(
                timestamp=timestamp,
                entry_type=EntryType(entry_type),
                entry=entry_data,
                chain=chain,
            )
            leaves.append(leaf)

        return leaves

    async def fetch_entries_raw(
        self,
        start_index: int,
    ) -> AsyncIterator[tuple[int, LogEntry]]:
        """
        Fetch new entries from the tiled log since the given index (raw version).

        Args:
            start_index: Index of first entry to retrieve (inclusive)

        Yields:
            Tuples of (entry_index, LogEntry) for new entries (unparsed)
        """
        checkpoint = await self.fetch_checkpoint()
        current_size = checkpoint.size

        if current_size <= start_index:
            return

        start_tile = start_index // self.TILE_SIZE
        end_tile = current_size // self.TILE_SIZE

        # Process complete tiles
        for tile_idx in range(start_tile, end_tile):
            leaves = await self.fetch_tile(tile_idx)

            for i, leaf in enumerate(leaves):
                entry_index = tile_idx * self.TILE_SIZE + i

                if entry_index < start_index:
                    continue

                yield entry_index, leaf

        # Process partial tile if exists
        partial_size = current_size % self.TILE_SIZE
        if partial_size > 0 and end_tile * self.TILE_SIZE < current_size:
            leaves = await self.fetch_tile(end_tile, partial_width=partial_size)

            for i, leaf in enumerate(leaves):
                entry_index = end_tile * self.TILE_SIZE + i

                if entry_index < start_index:
                    continue

                if entry_index >= current_size:
                    break

                yield entry_index, leaf

    async def fetch_entries(
        self,
        start_index: int,
        entry_shard_id: Optional[int] = None,
        entry_total_shards: Optional[int] = None,
    ) -> AsyncIterator[CertificateEntry]:
        """
        Fetch new entries from the tiled log since the given index.

        Args:
            start_index: Index of first entry to retrieve (inclusive)
            entry_shard_id: If set, only process entries where index % total == shard_id
            entry_total_shards: Total shards for entry-level distribution

        Yields:
            CertificateEntry objects for new entries
        """
        batch: List[tuple[int, LogEntry]] = []

        async for entry_index, leaf in self.fetch_entries_raw(start_index):
            # Entry-level sharding: skip entries not assigned to this shard
            if entry_shard_id is not None and entry_total_shards is not None:
                if entry_index % entry_total_shards != entry_shard_id:
                    continue

            batch.append((entry_index, leaf))

            if len(batch) >= self.PARSE_BATCH_SIZE:
                async for entry in self._parse_batch(batch):
                    yield entry
                batch = []

        # Process remaining entries
        if batch:
            async for entry in self._parse_batch(batch):
                yield entry

    async def _parse_batch(
        self, batch: List[tuple[int, LogEntry]]
    ) -> AsyncIterator[CertificateEntry]:
        """Parse a batch of entries in parallel using process pool."""
        if not batch:
            return

        if self._executor is None:
            # Fallback to sequential parsing
            for entry_index, leaf in batch:
                try:
                    source = EntrySource(index=entry_index, log=self.log_meta)
                    entry = CertificateParser.parse_log_entry(leaf, source)
                    yield entry
                except Exception as e:
                    logger.warning(
                        f"Error parsing tiled entry {entry_index} from "
                        f"{self.log_meta.url}: {e}"
                    )
            return

        loop = asyncio.get_running_loop()

        # Prepare args for multiprocessing (must be picklable)
        mp_args = [
            (
                entry_index,
                leaf.timestamp,
                int(leaf.entry_type),
                leaf.entry,
                self.log_meta.url,
                self.log_meta.name,
                self.log_meta.operator,
            )
            for entry_index, leaf in batch
        ]

        # Submit to process pool
        futures = [
            loop.run_in_executor(self._executor, _mp_parse_entry, args)
            for args in mp_args
        ]

        results = await asyncio.gather(*futures)

        # Convert results back to CertificateEntry
        for result in results:
            if result is not None:
                (entry_index, timestamp, entry_type, domains, subject,
                 issuer, not_before, not_after, serial, sha256_fp,
                 sha1_fp, log_url, log_name, log_operator) = result

                source = EntrySource(
                    index=entry_index,
                    log=LogMeta(url=log_url, name=log_name, operator=log_operator)
                )
                entry = CertificateEntry(
                    timestamp=timestamp,
                    entry_type=entry_type,
                    source=source,
                    domains=domains,
                    subject=subject,
                    issuer=issuer,
                    not_before=not_before,
                    not_after=not_after,
                    serial_number=serial,
                    fingerprint_sha256=sha256_fp,
                    fingerprint_sha1=sha1_fp,
                )
                yield entry

    async def watch(
        self,
        start_index: Optional[int] = None,
        poll_interval: float = 30,
    ) -> AsyncIterator[CertificateEntry]:
        """
        Continuously watch the log for new entries.

        Args:
            start_index: Index to start from. If None, starts from current tree size
            poll_interval: How often to poll for new entries (seconds)

        Yields:
            CertificateEntry objects as they are discovered

        Example:
            async with TiledLogClient(url, name, operator) as client:
                async for entry in client.watch():
                    print(entry.domains)
        """
        current_index = start_index
        if current_index is None:
            current_index = await self.fetch_tree_size()
            await asyncio.sleep(poll_interval)

        lag: float = 0
        while True:
            loop = asyncio.get_running_loop()
            cycle_start = loop.time()

            async for entry in self.fetch_entries(
                current_index + 1,
                entry_shard_id=self.shard_id,
                entry_total_shards=self.total_shards,
            ):
                current_index = entry.source.index
                yield entry

            # Sleep for the remaining time in the poll interval
            remaining_time = poll_interval - (loop.time() - cycle_start)

            if remaining_time > 0:
                await asyncio.sleep(remaining_time)
                lag = 0
            else:
                current_lag = -remaining_time
                if current_lag > lag:
                    logger.warning(
                        f"{int(time.time())}:{self._get_group_prefix()}Poll cycle for "
                        f"{self.log_meta.url} exceeded interval by {current_lag:.2f}s"
                    )
                lag = current_lag

    async def _fetch_tile_speculative(
        self, tile_index: int
    ) -> List[tuple[int, LogEntry]]:
        """
        Fetch a tile speculatively (may return empty if tile doesn't exist).

        Args:
            tile_index: The tile index to fetch

        Returns:
            List of (entry_index, LogEntry) tuples. May be empty if tile doesn't exist.
        """
        try:
            leaves = await self.fetch_tile(tile_index)
            base_index = tile_index * self.TILE_SIZE
            return [(base_index + i, leaf) for i, leaf in enumerate(leaves)]
        except Exception:
            # Tile may not exist yet - that's fine for speculative fetching
            return []

    async def watch_raw(
        self,
        start_index: Optional[int] = None,
        poll_interval: float = 30,
        state: Optional[LogState] = None,
    ) -> AsyncIterator[RawEntry]:
        """
        Continuously watch the log for new entries WITHOUT parsing.
        Uses speculative parallel tile fetching with gap tracking.

        Args:
            start_index: Index to start from. If None, starts from current tree size
            poll_interval: How often to poll for new entries (seconds)
            state: Optional LogState for tracking gaps and progress. Updated in place.

        Yields:
            RawEntry objects (unparsed) as they are discovered
        """
        # Initialize state
        if state is None:
            state = LogState()

        if start_index is not None:
            state.current_index = start_index
            state.highest_fetched = start_index

        if state.current_index == 0 and state.highest_fetched == 0:
            tree_size = await self.fetch_tree_size()
            state.current_index = tree_size
            state.highest_fetched = tree_size
            await asyncio.sleep(poll_interval)

        n_parallel = self._parallel_fetches
        lag: float = 0
        tile_size = self.TILE_SIZE

        # Convert gaps to failed tile set for efficient lookup
        failed_tiles: set[int] = set()
        for gap_start, gap_end in state.gaps:
            start_tile = gap_start // tile_size
            end_tile = gap_end // tile_size
            for t in range(start_tile, end_tile + 1):
                failed_tiles.add(t)

        while True:
            loop = asyncio.get_running_loop()
            cycle_start = loop.time()

            # Keep fetching until no new data
            while True:
                # Calculate tiles to fetch:
                # 1. Failed tiles (gaps) that are >= current_index tile
                # 2. New tiles beyond highest_fetched
                current_tile = (state.current_index + 1) // tile_size
                highest_tile = state.highest_fetched // tile_size

                tiles_to_fetch: List[int] = []

                # Add failed tiles that we haven't passed yet
                for ft in sorted(failed_tiles):
                    if ft >= current_tile and len(tiles_to_fetch) < n_parallel:
                        tiles_to_fetch.append(ft)

                # Add new tiles beyond highest_fetched
                next_new_tile = highest_tile + 1
                while len(tiles_to_fetch) < n_parallel:
                    tiles_to_fetch.append(next_new_tile)
                    next_new_tile += 1

                if not tiles_to_fetch:
                    break

                # Fetch all tiles in parallel
                results = await asyncio.gather(
                    *[self._fetch_tile_speculative(t) for t in tiles_to_fetch]
                )

                # Process results: track successes and failures
                all_entries: List[tuple[int, LogEntry]] = []
                newly_failed: set[int] = set()
                newly_succeeded: set[int] = set()

                for tile_idx, tile_results in zip(tiles_to_fetch, results):
                    if tile_results:
                        # Success - remove from failed, add entries
                        newly_succeeded.add(tile_idx)
                        for entry_index, leaf in tile_results:
                            if entry_index > state.current_index:
                                all_entries.append((entry_index, leaf))
                    else:
                        # Failed or empty - only mark as failed if within tree
                        # (speculative fetches beyond tree return empty)
                        if tile_idx <= highest_tile or tile_idx in failed_tiles:
                            newly_failed.add(tile_idx)

                # Update failed tiles
                failed_tiles -= newly_succeeded
                failed_tiles |= newly_failed

                if not all_entries:
                    break

                # Sort entries by index
                all_entries.sort(key=lambda x: x[0])

                # Yield ALL successful entries immediately
                max_entry_index = state.current_index
                for entry_index, leaf in all_entries:
                    yield RawEntry(
                        index=entry_index,
                        timestamp=leaf.timestamp,
                        entry_type=int(leaf.entry_type),
                        cert_data=leaf.entry,
                        log_url=self.log_meta.url,
                        log_name=self.log_meta.name,
                        log_operator=self.log_meta.operator,
                    )
                    if entry_index > max_entry_index:
                        max_entry_index = entry_index

                # Update highest_fetched
                if max_entry_index > state.highest_fetched:
                    state.highest_fetched = max_entry_index

                # Update current_index to highest contiguous point
                # Walk from current_index + 1 and find where gaps start
                new_current = state.current_index
                check_tile = (new_current + 1) // tile_size
                while check_tile not in failed_tiles:
                    # This tile is complete, advance current_index
                    tile_end = (check_tile + 1) * tile_size - 1
                    if tile_end > state.highest_fetched:
                        # Don't advance past what we've fetched
                        new_current = state.highest_fetched
                        break
                    new_current = tile_end
                    check_tile += 1

                state.current_index = new_current

                # Convert failed_tiles back to gaps for state
                state.gaps = []
                for ft in sorted(failed_tiles):
                    gap_start = ft * tile_size
                    gap_end = (ft + 1) * tile_size - 1
                    state.gaps.append([gap_start, gap_end])

            # Sleep for remaining poll interval
            remaining_time = poll_interval - (loop.time() - cycle_start)

            if remaining_time > 0:
                await asyncio.sleep(remaining_time)
                lag = 0
            else:
                current_lag = -remaining_time
                if current_lag > lag:
                    logger.warning(
                        f"{int(time.time())}:{self._get_group_prefix()}Poll cycle for "
                        f"{self.log_meta.url} exceeded interval by {current_lag:.2f}s"
                    )
                lag = current_lag


class ClassicLogClient:
    """Client for interacting with classic CT logs"""

    DEFAULT_USER_AGENT = f"CT-Moniteur/{__version__}"
    PARSE_BATCH_SIZE = 1000  # Parse this many entries in parallel
    RAW_BATCH_SIZE = 1000    # Entries per batch in raw mode

    def __init__(
        self,
        log_meta: LogMeta,
        timeout: float = 30.0,
        user_agent: Optional[str] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        shard_id: Optional[int] = None,
        total_shards: Optional[int] = None,
        executor: Optional[ProcessPoolExecutor] = None,
        log_prefix: Optional[str] = None,
        parallel_fetches: int = 1,
    ):
        self.log_meta = log_meta
        self.timeout = timeout
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        self.shard_id = shard_id
        self.total_shards = total_shards
        self._executor = executor
        self._log_prefix = log_prefix
        self._parallel_fetches = parallel_fetches
        self._client = httpx.AsyncClient(
            base_url=log_meta.url,
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            transport=transport or RateLimitedTransport(),
        )

    def _get_group_prefix(self) -> str:
        """Get group-aware prefix based on log URL or custom prefix."""
        if self._log_prefix:
            return f"{self._log_prefix}:"
        if self.shard_id is None:
            return ""
        url = self.log_meta.url
        # Check for specific high-volume log names first
        if "/argon" in url:
            return f"argon{self.shard_id}:"
        elif "/xenon" in url:
            return f"xenon{self.shard_id}:"
        elif "googleapis.com" in url:
            return f"google{self.shard_id}:"
        elif "trustasia.com" in url:
            return f"trustasia{self.shard_id}:"
        else:
            return f"shard{self.shard_id}:"

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def close(self):
        """Close the HTTP client"""
        await self._client.aclose()

    async def get_sth(self) -> SignedTreeHead:
        """Get Signed Tree Head"""
        response = await self._client.get("/ct/v1/get-sth")
        response.raise_for_status()
        data = cast(Dict[str, Any], response.json())
        return SignedTreeHead(**data)

    async def fetch_tree_size(self) -> int:
        """Fetch the current tree size (number of entries in the log)"""
        sth = await self.get_sth()
        return sth.tree_size

    async def get_entries(self, start: int, end: int) -> List[LogEntry]:
        """Get entries from the log"""
        params = {"start": start, "end": end}
        response = await self._client.get("/ct/v1/get-entries", params=params)
        response.raise_for_status()
        data = cast(Dict[str, Any], response.json())
        raw_entries = cast(List[Dict[str, str]], data.get("entries", []))
        return self._parse_classic_entries(raw_entries)

    def _parse_classic_entries(self, raw_entries: List[Dict[str, str]]) -> List[LogEntry]:
        """Parse classic CT log entries into LogEntry objects"""
        log_entries: List[LogEntry] = []

        for entry_data in raw_entries:
            try:
                leaf_input = base64.b64decode(entry_data["leaf_input"])

                # Parse the MerkleTreeLeaf structure
                # Format: version(1) + leaf_type(1) + timestamp(8) + entry_type(2) + ...
                reader = BinaryReader(leaf_input, Endianness.BIG)

                # Validate version (must be 0 for v1)
                version = reader.read(DataType.UINT, 1)
                if version != 0:
                    raise ValueError(f"Invalid MerkleTreeLeaf version: {version}")

                # Validate leaf_type (must be 0 for timestamped_entry)
                leaf_type = reader.read(DataType.UINT, 1)
                if leaf_type != 0:
                    raise ValueError(f"Invalid leaf_type: {leaf_type}")

                timestamp = reader.read(DataType.UINT, 8)
                entry_type_val = reader.read(DataType.UINT, 2)

                chain: List[bytes] = []

                # For X509Entry: certificate is in leaf_input after the header
                # For PrecertEntry: certificate is in extra_data (PreCertEntry.LeafCert)
                if entry_type_val == 0:  # X509Entry
                    # Format: entry_type(2) + cert_length(3) + cert_data + extensions...
                    cert_len = reader.read(DataType.UINT, 3)
                    cert_data = reader.read(DataType.BYTES, cert_len)

                    # Parse chain from extra_data
                    if "extra_data" in entry_data:
                        extra_data = base64.b64decode(entry_data["extra_data"])
                        chain = self._parse_certificate_chain(extra_data)

                elif entry_type_val == 1:  # PrecertEntry
                    # For precerts, extra_data contains PreCertEntry:
                    # - LeafCert (3-byte length + cert data) - the actual precertificate
                    extra_data = base64.b64decode(entry_data["extra_data"])
                    extra_reader = BinaryReader(extra_data, Endianness.BIG)

                    # Read the LeafCert (the precertificate)
                    cert_len = extra_reader.read(DataType.UINT, 3)
                    cert_data = extra_reader.read(DataType.BYTES, cert_len)

                    # Parse chain from remaining data in extra_reader
                    remaining_data = extra_reader.read(DataType.BYTES, extra_reader.remaining)
                    chain = self._parse_certificate_chain(remaining_data)

                else:
                    raise ValueError(f"Unknown entry type: {entry_type_val}")

                log_entry = LogEntry(
                    timestamp=timestamp,
                    entry_type=EntryType(entry_type_val),
                    entry=cert_data,
                    chain=chain,
                )
                log_entries.append(log_entry)

            except Exception as e:
                logger.warning(f"Error parsing classic entry from {self.log_meta.url}: {e}")
                continue

        return log_entries

    def _parse_certificate_chain(self, chain_data: bytes) -> List[bytes]:
        """
        Parse a certificate chain from binary data.

        Format: repeated sequence of (3-byte length + certificate data)

        Args:
            chain_data: Binary data containing the certificate chain

        Returns:
            List of certificate data as bytes
        """
        chain: List[bytes] = []

        if not chain_data:
            return chain

        reader = BinaryReader(chain_data, Endianness.BIG)

        while reader.remaining >= 3:
            # Read certificate length (3 bytes)
            cert_len = reader.read(DataType.UINT, 3)

            # Check if we have enough bytes for the certificate
            if not reader.has_bytes(cert_len):
                break

            # Read certificate data
            cert_data = reader.read(DataType.BYTES, cert_len)
            chain.append(cert_data)

        return chain

    async def fetch_entries_raw(
        self,
        start_index: int,
    ) -> AsyncIterator[tuple[int, LogEntry]]:
        """
        Fetch new entries from the classic log since the given index (raw version).

        Args:
            start_index: Index of first entry to retrieve (inclusive)

        Yields:
            Tuples of (entry_index, LogEntry) for new entries (unparsed)
        """
        sth = await self.get_sth()
        tree_size = sth.tree_size

        if tree_size <= start_index:
            return

        current_start = start_index
        while current_start < tree_size:
            entries = await self.get_entries(current_start, tree_size - 1)

            if not entries:
                break

            for i, log_entry in enumerate(entries):
                yield current_start + i, log_entry

            current_start += len(entries)

    async def fetch_entries(
        self,
        start_index: int,
        entry_shard_id: Optional[int] = None,
        entry_total_shards: Optional[int] = None,
    ) -> AsyncIterator[CertificateEntry]:
        """
        Fetch new entries from the classic log since the given index.

        Args:
            start_index: Index of first entry to retrieve (inclusive)
            entry_shard_id: If set, only process entries where index % total == shard_id
            entry_total_shards: Total shards for entry-level distribution

        Yields:
            CertificateEntry objects for new entries
        """
        batch: List[tuple[int, LogEntry]] = []

        async for entry_index, log_entry in self.fetch_entries_raw(start_index):
            # Entry-level sharding: skip entries not assigned to this shard
            if entry_shard_id is not None and entry_total_shards is not None:
                if entry_index % entry_total_shards != entry_shard_id:
                    continue

            batch.append((entry_index, log_entry))

            if len(batch) >= self.PARSE_BATCH_SIZE:
                async for entry in self._parse_batch(batch):
                    yield entry
                batch = []

        # Process remaining entries
        if batch:
            async for entry in self._parse_batch(batch):
                yield entry

    async def _parse_batch(
        self, batch: List[tuple[int, LogEntry]]
    ) -> AsyncIterator[CertificateEntry]:
        """Parse a batch of entries in parallel using process pool."""
        if not batch:
            return

        if self._executor is None:
            # Fallback to sequential parsing
            for entry_index, log_entry in batch:
                try:
                    source = EntrySource(index=entry_index, log=self.log_meta)
                    entry = CertificateParser.parse_log_entry(log_entry, source)
                    yield entry
                except Exception as e:
                    logger.warning(
                        f"Error parsing classic entry {entry_index} from "
                        f"{self.log_meta.url}: {e}"
                    )
            return

        loop = asyncio.get_running_loop()

        # Prepare args for multiprocessing (must be picklable)
        mp_args = [
            (
                entry_index,
                log_entry.timestamp,
                int(log_entry.entry_type),
                log_entry.entry,
                self.log_meta.url,
                self.log_meta.name,
                self.log_meta.operator,
            )
            for entry_index, log_entry in batch
        ]

        # Submit to process pool
        futures = [
            loop.run_in_executor(self._executor, _mp_parse_entry, args)
            for args in mp_args
        ]

        results = await asyncio.gather(*futures)

        # Convert results back to CertificateEntry
        for result in results:
            if result is not None:
                (entry_index, timestamp, entry_type, domains, subject,
                 issuer, not_before, not_after, serial, sha256_fp,
                 sha1_fp, log_url, log_name, log_operator) = result

                source = EntrySource(
                    index=entry_index,
                    log=LogMeta(url=log_url, name=log_name, operator=log_operator)
                )
                entry = CertificateEntry(
                    timestamp=timestamp,
                    entry_type=entry_type,
                    source=source,
                    domains=domains,
                    subject=subject,
                    issuer=issuer,
                    not_before=not_before,
                    not_after=not_after,
                    serial_number=serial,
                    fingerprint_sha256=sha256_fp,
                    fingerprint_sha1=sha1_fp,
                )
                yield entry

    async def watch(
        self,
        start_index: Optional[int] = None,
        poll_interval: float = 30,
    ) -> AsyncIterator[CertificateEntry]:
        """
        Continuously watch the log for new entries.

        Args:
            start_index: Index to start from. If None, starts from current tree size
            poll_interval: How often to poll for new entries (seconds)

        Yields:
            CertificateEntry objects as they are discovered

        Example:
            async with ClassicLogClient(url, name, operator) as client:
                async for entry in client.watch():
                    print(entry.domains)
        """
        current_index = start_index
        if current_index is None:
            current_index = await self.fetch_tree_size()
            await asyncio.sleep(poll_interval)

        lag: float = 0
        while True:
            loop = asyncio.get_running_loop()
            cycle_start = loop.time()

            async for entry in self.fetch_entries(
                current_index + 1,
                entry_shard_id=self.shard_id,
                entry_total_shards=self.total_shards,
            ):
                current_index = entry.source.index
                yield entry

            # Sleep for the remaining time in the poll interval
            remaining_time = poll_interval - (loop.time() - cycle_start)

            if remaining_time > 0:
                await asyncio.sleep(remaining_time)
                lag = 0
            else:
                current_lag = -remaining_time
                if current_lag > lag:
                    logger.warning(
                        f"{int(time.time())}:{self._get_group_prefix()}Poll cycle for "
                        f"{self.log_meta.url} exceeded interval by {current_lag:.2f}s"
                    )
                lag = current_lag

    async def _fetch_range_speculative(
        self, start: int, end: int
    ) -> List[tuple[int, LogEntry]]:
        """
        Fetch a range of entries speculatively (may return partial/empty).

        Args:
            start: Start index (inclusive)
            end: End index (inclusive)

        Returns:
            List of (index, LogEntry) tuples. May be empty if range doesn't exist.
        """
        try:
            entries = await self.get_entries(start, end)
            return [(start + i, entry) for i, entry in enumerate(entries)]
        except Exception:
            # Range may not exist yet - that's fine for speculative fetching
            return []

    async def watch_raw(
        self,
        start_index: Optional[int] = None,
        poll_interval: float = 30,
        state: Optional[LogState] = None,
    ) -> AsyncIterator[RawEntry]:
        """
        Continuously watch the log for new entries WITHOUT parsing.
        Uses speculative parallel fetching with gap tracking.

        Args:
            start_index: Index to start from. If None, starts from current tree size
            poll_interval: How often to poll for new entries (seconds)
            state: Optional LogState for tracking gaps and progress. Updated in place.

        Yields:
            RawEntry objects (unparsed) as they are discovered
        """
        # Initialize state
        if state is None:
            state = LogState()

        if start_index is not None:
            state.current_index = start_index
            state.highest_fetched = start_index

        if state.current_index == 0 and state.highest_fetched == 0:
            tree_size = await self.fetch_tree_size()
            state.current_index = tree_size
            state.highest_fetched = tree_size
            await asyncio.sleep(poll_interval)

        batch_size = self.RAW_BATCH_SIZE
        n_parallel = self._parallel_fetches
        lag: float = 0

        # Convert gaps to failed ranges set: {(start, end), ...}
        failed_ranges: set[tuple[int, int]] = set()
        for gap_start, gap_end in state.gaps:
            failed_ranges.add((gap_start, gap_end))

        while True:
            loop = asyncio.get_running_loop()
            cycle_start = loop.time()

            # Keep fetching until no new data
            while True:
                # Calculate ranges to fetch:
                # 1. Failed ranges (gaps) starting at or after current_index
                # 2. New ranges beyond highest_fetched
                ranges_to_fetch: List[tuple[int, int]] = []

                # Add failed ranges that we haven't passed yet
                for fr_start, fr_end in sorted(failed_ranges):
                    if fr_start > state.current_index and len(ranges_to_fetch) < n_parallel:
                        ranges_to_fetch.append((fr_start, fr_end))

                # Add new ranges beyond highest_fetched
                next_start = state.highest_fetched + 1
                while len(ranges_to_fetch) < n_parallel:
                    next_end = next_start + batch_size - 1
                    ranges_to_fetch.append((next_start, next_end))
                    next_start = next_end + 1

                if not ranges_to_fetch:
                    break

                # Fetch all ranges in parallel
                results = await asyncio.gather(
                    *[self._fetch_range_speculative(s, e) for s, e in ranges_to_fetch]
                )

                # Process results: track successes and failures
                all_entries: List[tuple[int, LogEntry]] = []
                newly_failed: set[tuple[int, int]] = set()
                newly_succeeded: set[tuple[int, int]] = set()

                for (range_start, range_end), range_results in zip(ranges_to_fetch, results):
                    if range_results:
                        # Success
                        newly_succeeded.add((range_start, range_end))
                        for entry_index, log_entry in range_results:
                            if entry_index > state.current_index:
                                all_entries.append((entry_index, log_entry))
                    else:
                        # Failed or empty - only mark as failed if within known range
                        if range_start <= state.highest_fetched or (range_start, range_end) in failed_ranges:
                            newly_failed.add((range_start, range_end))

                # Update failed ranges
                failed_ranges -= newly_succeeded
                failed_ranges |= newly_failed

                if not all_entries:
                    break

                # Sort entries by index
                all_entries.sort(key=lambda x: x[0])

                # Yield ALL successful entries immediately
                max_entry_index = state.current_index
                for entry_index, log_entry in all_entries:
                    yield RawEntry(
                        index=entry_index,
                        timestamp=log_entry.timestamp,
                        entry_type=int(log_entry.entry_type),
                        cert_data=log_entry.entry,
                        log_url=self.log_meta.url,
                        log_name=self.log_meta.name,
                        log_operator=self.log_meta.operator,
                    )
                    if entry_index > max_entry_index:
                        max_entry_index = entry_index

                # Update highest_fetched
                if max_entry_index > state.highest_fetched:
                    state.highest_fetched = max_entry_index

                # Update current_index to highest contiguous point
                new_current = state.current_index
                while True:
                    # Check if there's a gap starting right after new_current
                    has_gap = False
                    for gap_start, gap_end in failed_ranges:
                        if gap_start == new_current + 1:
                            has_gap = True
                            break
                    if has_gap:
                        break
                    # No gap, can we advance?
                    if new_current >= state.highest_fetched:
                        break
                    # Advance by batch_size or to highest_fetched
                    new_current = min(new_current + batch_size, state.highest_fetched)

                state.current_index = new_current

                # Update gaps in state
                state.gaps = [[s, e] for s, e in sorted(failed_ranges)]

            # Sleep for remaining poll interval
            remaining_time = poll_interval - (loop.time() - cycle_start)

            if remaining_time > 0:
                await asyncio.sleep(remaining_time)
                lag = 0
            else:
                current_lag = -remaining_time
                if current_lag > lag:
                    logger.warning(
                        f"{int(time.time())}:{self._get_group_prefix()}Poll cycle for "
                        f"{self.log_meta.url} exceeded interval by {current_lag:.2f}s"
                    )
                lag = current_lag


class CertificateParser:
    """Parse certificates from CT log entries"""

    @staticmethod
    def parse_x509_certificate(cert_data: bytes) -> x509.Certificate:
        """Parse X.509 certificate from DER bytes"""
        return x509.load_der_x509_certificate(cert_data, default_backend())

    @staticmethod
    def extract_domains(cert: x509.Certificate) -> List[str]:
        """Extract all domains from certificate"""
        domains: List[str] = []

        # Get CN from subject
        try:
            cn_attr = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_attr:
                cn_value = cn_attr[0].value
                # Ensure it's a string
                if isinstance(cn_value, bytes):
                    cn_value = cn_value.decode("utf-8", errors="ignore")
                domains.append(str(cn_value))
        except Exception:
            pass

        # Get SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
            domains.extend(san_names)
        except Exception:
            pass

        return list(set(domains))  # Remove duplicates

    @staticmethod
    def calculate_fingerprint(cert_data: bytes, algorithm: str = "sha256") -> str:
        """Calculate certificate fingerprint"""
        if algorithm == "sha256":
            h = hashlib.sha256(cert_data).digest()
        elif algorithm == "sha1":
            h = hashlib.sha1(cert_data).digest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        return ":".join(f"{b:02X}" for b in h)

    @classmethod
    def parse_log_entry(cls, log_entry: LogEntry, source: EntrySource) -> CertificateEntry:
        """Parse a LogEntry into a CertificateEntry"""
        if log_entry.entry_type == EntryType.X509_ENTRY:
            entry_type = "X509LogEntry"
        elif log_entry.entry_type == EntryType.PRECERT_ENTRY:
            entry_type = "PrecertLogEntry"
        else:
            raise ValueError(f"Unknown entry type: {log_entry.entry_type}")

        cert = cls.parse_x509_certificate(log_entry.entry)
        domains = cls.extract_domains(cert)

        return CertificateEntry(
            source=source,
            timestamp=log_entry.timestamp,
            entry_type=entry_type,
            certificate=cert,
            domains=domains,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            serial_number=format(cert.serial_number, "X"),
            fingerprint_sha256=cls.calculate_fingerprint(log_entry.entry, "sha256"),
            fingerprint_sha1=cls.calculate_fingerprint(log_entry.entry, "sha1"),
        )


class CTMoniteur:
    """
    High-level monitor for all CT logs with state management.

    This is the main entry point for monitoring all CT logs with the ability
    to save and resume from previous state.
    """

    DEFAULT_USER_AGENT = f"CT-Moniteur/{__version__}"

    def __init__(
        self,
        callback: Optional[Union[
            Callable[[CertificateEntry], None], Callable[[CertificateEntry], asyncio.Future]
        ]] = None,
        raw_callback: Optional[Union[
            Callable[[RawEntry], None], Callable[[RawEntry], asyncio.Future]
        ]] = None,
        initial_state: Optional[Dict[str, Any]] = None,
        skip_retired: bool = True,
        poll_interval: float = 30,
        timeout: float = 30.0,
        user_agent: Optional[str] = None,
        max_retries: int = 5,
        retry_delay: float = 10.0,
        refresh_interval: float = 6.0,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
        include_logs: Optional[List[str]] = None,
        exclude_logs: Optional[List[str]] = None,
        shard_id: Optional[int] = None,
        total_shards: Optional[int] = None,
        parse_workers: int = 4,
        log_prefix: Optional[str] = None,
        parallel_fetches: int = 1,
    ):
        """
        Initialize CT Moniteur.

        Args:
            callback: Function to call for each parsed certificate entry
            raw_callback: Function to call for each raw (unparsed) entry.
                         When set, skips parsing - used for fetcher->parser architecture
            initial_state: Optional dict of {log_url: last_index} to resume from
            skip_retired: Skip retired logs
            poll_interval: How often to poll for new entries (seconds)
            timeout: HTTP request timeout
            user_agent: Custom user agent string
            max_retries: Maximum retries for failed log connections
            retry_delay: Delay between retries (seconds)
            refresh_interval: How often to refresh the log list (hours, 0 to disable)
            max_connections: Max concurrent connections across all logs
            max_keepalive_connections: Max keepalive connections in pool
            include_logs: Only monitor logs matching these patterns (partial URL match)
            exclude_logs: Skip logs matching these patterns (partial URL match)
            shard_id: This instance's shard ID (0 to total_shards-1)
            total_shards: Total number of shards for distributed processing
            parse_workers: Number of threads for parallel certificate parsing (ignored in raw mode)
            log_prefix: Custom prefix for log messages (e.g. "fetcher")
            parallel_fetches: Number of parallel batch fetches per log (for raw mode)
        """
        if callback is None and raw_callback is None:
            raise ValueError("Either callback or raw_callback must be provided")
        self.callback = callback
        self.raw_callback = raw_callback
        self.skip_retired = skip_retired
        self.poll_interval = poll_interval
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.refresh_interval = refresh_interval
        self.include_logs = include_logs
        self.exclude_logs = exclude_logs
        self.shard_id = shard_id
        self.total_shards = total_shards
        self.parse_workers = parse_workers
        self.log_prefix = log_prefix
        self.parallel_fetches = parallel_fetches

        # Parse initial state into LogState objects
        self._state: Dict[str, LogState] = {}
        if initial_state:
            for url, state_data in initial_state.items():
                self._state[url] = LogState.from_dict(state_data)
        self._clients: List[Union[TiledLogClient, ClassicLogClient]] = []
        self._tasks: List[asyncio.Task] = []
        self._running = False
        self._stats = MoniteurStats()
        self._state_lock = asyncio.Lock()
        self._transport = RateLimitedTransport(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            shard_id=shard_id,
        )
        self._refresh_task: Optional[asyncio.Task] = None
        self._executor: Optional[ProcessPoolExecutor] = None

    async def start(self) -> None:
        """
        Start monitoring all CT logs.

        This will fetch the list of all logs and start watching them concurrently.
        Also starts a periodic refresh task to update the log list if enabled.
        """
        if self._running:
            raise RuntimeError("Moniteur is already running")

        self._running = True
        self._stats.start_time = datetime.utcnow()

        # Create process pool for parallel certificate parsing (bypasses GIL)
        if self.parse_workers > 0:
            self._executor = ProcessPoolExecutor(max_workers=self.parse_workers)

        self._clients = await self._create_clients()
        self._stats.active_logs = len(self._clients)

        logger.info(f"Starting monitoring of {len(self._clients)} CT logs")

        self._start_watch_tasks()

        if self.refresh_interval > 0:
            self._refresh_task = asyncio.create_task(self._periodic_refresh())

    async def stop(self) -> None:
        """Stop monitoring all logs gracefully."""
        if not self._running:
            return

        logger.info("Stopping CT Moniteur...")
        self._running = False

        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass

        await self._stop_watch_tasks()

        # Shutdown thread pool executor
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None

        logger.info("CT Moniteur stopped")

    def get_state(self) -> Dict[str, Any]:
        """
        Get current monitoring state.

        Returns:
            Dictionary mapping log URLs to state dict with:
            - current_index: Highest contiguous index (safe restart point)
            - highest_fetched: Highest index successfully fetched
            - gaps: List of [start, end] ranges that failed

        Example:
            state = monitor.get_state()
            # Save to file
            with open('ct_state.json', 'w') as f:
                json.dump(state, f)
        """
        return {url: state.to_dict() for url, state in self._state.items()}

    def get_stats(self) -> MoniteurStats:
        """Get monitoring statistics."""
        return self._stats

    def _should_include_log(self, url: str) -> bool:
        """Check if log URL should be included based on include/exclude filters."""
        if self.include_logs:
            if not any(pattern in url for pattern in self.include_logs):
                return False
        if self.exclude_logs:
            if any(pattern in url for pattern in self.exclude_logs):
                return False
        return True

    def _get_shard_for_url(self, url: str) -> int:
        """Get shard assignment for URL. Spreads same hostname across shards."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.netloc
        path = parsed.path
        # Combine hostname and path hashes to spread same-host logs across shards
        # while keeping assignment stable when new logs are added
        host_hash = int(hashlib.md5(hostname.encode()).hexdigest(), 16)
        path_hash = int(hashlib.md5(path.encode()).hexdigest(), 16)
        return (host_hash + path_hash) % self.total_shards

    async def _create_clients(self) -> List[Union[TiledLogClient, ClassicLogClient]]:
        """Create clients for all CT logs."""
        from urllib.parse import urlparse
        from collections import defaultdict

        log_list = await self._fetch_log_list()

        # Collect all logs first (apply include/exclude filters)
        all_logs: List[Dict[str, Any]] = []
        for operator in log_list.get("operators", []):
            operator_name = operator.get("name", "Unknown")

            for log in operator.get("logs", []):
                if self.skip_retired and log.get("state", {}).get("retired"):
                    continue
                url = log.get("url", "")
                if url and self._should_include_log(url):
                    all_logs.append({
                        "url": url,
                        "description": log.get("description", ""),
                        "operator": operator_name,
                        "type": "classic",
                    })

            for log in operator.get("tiled_logs", []):
                if self.skip_retired and log.get("state", {}).get("retired"):
                    continue
                url = log.get("monitoring_url", "")
                if url and self._should_include_log(url):
                    all_logs.append({
                        "url": url,
                        "description": log.get("description", ""),
                        "operator": operator_name,
                        "type": "tiled",
                    })

        # Group by hostname and sort for deterministic ordering
        by_host: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for log in all_logs:
            hostname = urlparse(log["url"]).netloc
            by_host[hostname].append(log)

        for hostname in by_host:
            by_host[hostname].sort(key=lambda x: x["url"])

        # Assign shards based on hostname+path hash (stable when new logs added)
        # Exception: if include_logs targets specific logs (not domains), use
        # entry-level sharding instead of URL-based sharding
        use_entry_sharding = (
            self.include_logs and
            all(".com" not in p and ".org" not in p for p in self.include_logs)
        )

        # shard_id always passed for log prefix display
        # total_shards only passed for entry-level sharding (controls filtering)
        client_shard_id = self.shard_id
        client_total_shards = self.total_shards if use_entry_sharding else None

        clients: List[Union[TiledLogClient, ClassicLogClient]] = []
        for hostname, logs in by_host.items():
            for log in logs:
                # Skip if sharding enabled and not our shard (unless entry-sharding)
                if self.shard_id is not None and self.total_shards is not None:
                    if not use_entry_sharding:
                        shard = self._get_shard_for_url(log["url"])
                        if shard != self.shard_id:
                            continue

                log_meta = LogMeta(
                    url=log["url"],
                    name=log["description"],
                    operator=log["operator"],
                )

                if log["type"] == "classic":
                    client = ClassicLogClient(
                        log_meta=log_meta,
                        timeout=self.timeout,
                        user_agent=self.user_agent,
                        transport=self._transport,
                        shard_id=client_shard_id,
                        total_shards=client_total_shards,
                        executor=self._executor,
                        log_prefix=self.log_prefix,
                        parallel_fetches=self.parallel_fetches,
                    )
                else:
                    client = TiledLogClient(
                        log_meta=log_meta,
                        timeout=self.timeout,
                        user_agent=self.user_agent,
                        transport=self._transport,
                        shard_id=client_shard_id,
                        total_shards=client_total_shards,
                        executor=self._executor,
                        log_prefix=self.log_prefix,
                        parallel_fetches=self.parallel_fetches,
                    )
                clients.append(client)

        return clients

    async def _fetch_log_list(self) -> Dict[str, Any]:
        """Fetch the list of all CT logs."""
        headers = {"User-Agent": self.user_agent or self.DEFAULT_USER_AGENT}
        async with httpx.AsyncClient(headers=headers, transport=self._transport) as client:
            response = await client.get(LOG_LIST_URL, timeout=10.0)
            response.raise_for_status()
            return cast(Dict[str, Any], response.json())

    async def _watch_log(
        self, client: Union[TiledLogClient, ClassicLogClient], initial_delay: float = 0
    ) -> None:
        """Watch a single log with retry logic."""
        # Apply staggered start delay
        if initial_delay > 0:
            await asyncio.sleep(initial_delay)

        retries = 0
        log_url = client.log_meta.url

        # Get or create LogState for this log
        log_state = self._state.get(log_url)
        if log_state is None:
            log_state = LogState()
            self._state[log_url] = log_state

        # For backwards compat: start_index only used for non-raw mode
        start_index = log_state.current_index if log_state.current_index > 0 else None

        # Use raw mode if raw_callback is set (skips parsing)
        use_raw_mode = self.raw_callback is not None

        while self._running:
            try:
                if use_raw_mode:
                    # Raw mode: fetch without parsing, call raw_callback
                    # Pass log_state which is updated in-place by watch_raw
                    async for raw_entry in client.watch_raw(
                        poll_interval=self.poll_interval,
                        state=log_state,
                    ):
                        if not self._running:
                            break

                        # Update stats (state is updated in-place by watch_raw)
                        async with self._state_lock:
                            self._stats.total_entries_processed += 1
                            self._stats.entries_per_log[raw_entry.log_url] = (
                                self._stats.entries_per_log.get(raw_entry.log_url, 0) + 1
                            )

                        # Reset retries on successful entry processing
                        if retries > 0:
                            logger.info(
                                f"Log {raw_entry.log_url} recovered after {retries} failed attempt(s)"
                            )
                            retries = 0

                        # Call raw callback
                        try:
                            if asyncio.iscoroutinefunction(self.raw_callback):
                                await self.raw_callback(raw_entry)
                            else:
                                self.raw_callback(raw_entry)
                        except Exception as e:
                            logger.error(
                                f"Error in raw_callback for {raw_entry.log_url}: {e}", exc_info=True
                            )
                else:
                    # Normal mode: fetch with parsing, call callback
                    async for entry in client.watch(
                        start_index=start_index, poll_interval=self.poll_interval
                    ):
                        if not self._running:
                            break

                        # Update state (non-raw mode uses simple index tracking)
                        async with self._state_lock:
                            log_state.current_index = entry.source.index
                            log_state.highest_fetched = entry.source.index
                            self._stats.total_entries_processed += 1
                            self._stats.entries_per_log[entry.source.log.url] = (
                                self._stats.entries_per_log.get(entry.source.log.url, 0) + 1
                            )

                        start_index = entry.source.index

                        # Reset retries on successful entry processing
                        if retries > 0:
                            logger.info(
                                f"Log {log_url} recovered after {retries} failed attempt(s)"
                            )
                            retries = 0

                        # Call user callback
                        try:
                            if asyncio.iscoroutinefunction(self.callback):
                                await self.callback(entry)
                            else:
                                self.callback(entry)
                        except Exception as e:
                            logger.error(
                                f"Error in callback for {entry.source.log.url}: {e}", exc_info=True
                            )

            except asyncio.CancelledError:
                break
            except Exception as e:
                retries += 1

                # Update error stats
                async with self._state_lock:
                    self._stats.errors_per_log[client.log_meta.url] = (
                        self._stats.errors_per_log.get(client.log_meta.url, 0) + 1
                    )

                # Strip verbose httpx error info
                err_msg = str(e).split('\n')[0]
                logger.warning(
                    f"{int(time.time())}:{client._get_group_prefix()}Error watching {client.log_meta.url} (retry {retries}/{self.max_retries}): {err_msg}"
                )

                if retries >= self.max_retries:
                    logger.error(f"Max retries reached for {client.log_meta.url}, giving up")
                    break

                await asyncio.sleep(self.retry_delay)

    async def _periodic_refresh(self) -> None:
        """
        Periodically refresh the log list and restart clients.

        This task runs in the background and refreshes the log list at the
        specified interval. If the log list fetch fails, it logs the error
        and continues with the existing clients.
        """
        while self._running:
            try:
                await asyncio.sleep(self.refresh_interval * 3600)

                if not self._running:
                    break

                logger.info("Refreshing CT log list...")

                try:
                    new_clients = await self._create_clients()
                    logger.info(f"Fetched updated log list: {len(new_clients)} logs available")

                    await self._restart_clients(new_clients)

                    logger.info(f"Successfully restarted with {len(new_clients)} CT logs")

                except Exception as e:
                    logger.error(
                        f"Failed to fetch updated log list, continuing with existing clients: {e}"
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic refresh task: {e}", exc_info=True)

    async def _restart_clients(
        self, new_clients: List[Union[TiledLogClient, ClassicLogClient]]
    ) -> None:
        """
        Stop all current clients and start new ones.

        Args:
            new_clients: List of new clients to start monitoring
        """
        await self._stop_watch_tasks()

        self._clients = new_clients
        self._stats.active_logs = len(new_clients)

        self._start_watch_tasks()

    async def _stop_watch_tasks(self) -> None:
        """
        Stop all watch tasks and close clients.

        Cancels all running watch tasks, waits for them to finish,
        closes all clients, and clears the task list.
        """
        for task in self._tasks:
            task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        for client in self._clients:
            await client.close()

        self._tasks.clear()

    def _start_watch_tasks(self) -> None:
        """
        Start watch tasks for all clients with staggered delays.

        Creates watch tasks with evenly distributed initial delays to avoid
        request bursts when polling logs.
        """
        for i, client in enumerate(self._clients):
            delay = i * self.poll_interval / len(self._clients)
            task = asyncio.create_task(self._watch_log(client, initial_delay=delay))
            self._tasks.append(task)

    @staticmethod
    async def fetch_all_logs(user_agent: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fetch the list of all CT logs from Google's log list.

        Args:
            user_agent: Custom user agent string to use for the request

        Returns:
            Dictionary containing operators and their logs
        """
        headers = {"User-Agent": user_agent or CTMoniteur.DEFAULT_USER_AGENT}
        async with httpx.AsyncClient(headers=headers, transport=RateLimitedTransport()) as client:
            response = await client.get(LOG_LIST_URL, timeout=10.0)
            response.raise_for_status()
            return cast(Dict[str, List[Dict[str, Any]]], response.json())
