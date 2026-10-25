"""Rate limiting transport for httpx."""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional
import logging

import httpx

logger = logging.getLogger("ct_moniteur")


@dataclass
class HostData:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    first_request_time: Optional[float] = None
    request_count: int = 0
    rate_limit: Optional[float] = None
    last_request_time: float = 0.0
    last_reduced: float = 0.0


# A burst of parallel requests gets a burst of 429s for the same overload;
# reducing on each one collapsed the rate to ~0 and it never recovered.
# AIMD instead: cut at most once per window, probe back up while healthy.
REDUCE_WINDOW = 10.0
RATE_INCREASE = 1.1
MIN_RATE = 1.0


class RateLimitedTransport(httpx.AsyncHTTPTransport):
    """httpx transport that learns and enforces rate limits from 429 responses."""

    def __init__(
        self,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
        shard_id: Optional[int] = None,
        **kwargs
    ):
        super().__init__(
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_keepalive_connections,
            ),
            **kwargs
        )
        self._host_data: dict[str, HostData] = {}
        self._shard_id = shard_id
        self._shard_prefix = f"shard{shard_id}:" if shard_id is not None else ""

    def _get_host_data(self, host: str) -> HostData:
        """Get or create host tracking data."""
        if host not in self._host_data:
            self._host_data[host] = HostData()
        return self._host_data[host]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        attempt = 0
        host = request.url.host

        while True:
            attempt += 1

            host_data = self._get_host_data(host)

            # Proactive rate limiting: calculate wait outside lock
            wait_time = 0.0
            async with host_data.lock:
                if host_data.rate_limit is not None:
                    min_interval = 1.0 / host_data.rate_limit
                    elapsed = time.monotonic() - host_data.last_request_time
                    if elapsed < min_interval:
                        wait_time = min_interval - elapsed
                        host_data.last_request_time += min_interval
                    else:
                        host_data.last_request_time = time.monotonic()
                else:
                    host_data.last_request_time = time.monotonic()

                if host_data.first_request_time is None:
                    host_data.first_request_time = time.monotonic()
                host_data.request_count += 1

                if host_data.request_count % 1_000 == 0:
                    elapsed = time.monotonic() - host_data.first_request_time
                    if elapsed > 0:
                        actual_rate = host_data.request_count / elapsed
                        logger.info(
                            f"{int(time.time())}:{self._shard_prefix}[{host}] Rate stats: "
                            f"{host_data.request_count} reqs in {elapsed:.2f}s ({actual_rate:.2f} req/s)"
                        )
                    if host_data.rate_limit is not None:
                        host_data.rate_limit *= RATE_INCREASE
                    host_data.first_request_time = None
                    host_data.request_count = 0

            # Sleep outside lock
            if wait_time > 0:
                await asyncio.sleep(wait_time)

            response = await super().handle_async_request(request)

            if response.status_code == 429:
                host_data = self._get_host_data(host)
                async with host_data.lock:
                    now = time.monotonic()
                    recently_reduced = (
                        host_data.rate_limit is not None
                        and now - host_data.last_reduced < REDUCE_WINDOW
                    )
                    if recently_reduced:
                        default_retry_after = min(
                            1.0 / host_data.rate_limit, 10.0
                        )
                    elif host_data.first_request_time:
                        elapsed = time.monotonic() - host_data.first_request_time
                        if elapsed > 0 and host_data.request_count > 1:
                            # Use 50% of observed rate as safety margin
                            raw_rate = (host_data.request_count - 1) / elapsed
                            host_data.rate_limit = max(raw_rate * 0.5, MIN_RATE)
                            host_data.last_reduced = now
                            logger.info(
                                f"{int(time.time())}:{self._shard_prefix}[{host}] "
                                f"Rate limit learned: {host_data.rate_limit:.2f} req/s "
                                f"(raw: {raw_rate:.2f})"
                            )
                            default_retry_after = min(1.0 / host_data.rate_limit, 10.0)
                        else:
                            default_retry_after = 5.0
                    elif host_data.rate_limit is not None:
                        # Already rate limited but still got 429 - halve the rate
                        host_data.rate_limit = max(
                            host_data.rate_limit * 0.5, MIN_RATE
                        )
                        host_data.last_reduced = now
                        logger.info(
                            f"{int(time.time())}:{self._shard_prefix}[{host}] "
                            f"Rate limit reduced to: {host_data.rate_limit:.2f} req/s"
                        )
                        default_retry_after = min(1.0 / host_data.rate_limit, 10.0)
                    else:
                        default_retry_after = 5.0

                    host_data.first_request_time = None
                    host_data.request_count = 0

                    retry_after = response.headers.get("Retry-After", default_retry_after)
                    try:
                        wait_time = float(retry_after)
                    except ValueError:
                        wait_time = default_retry_after

                    if attempt > 1:
                        logger.warning(
                            f"{int(time.time())}:{self._shard_prefix}[{host}] Rate limited (429): "
                            f"attempt {attempt}, retrying after {wait_time}s"
                        )
                    else:
                        logger.info(
                            f"{int(time.time())}:{self._shard_prefix}[{host}] Rate limited (429): "
                            f"attempt {attempt}, retrying after {wait_time}s"
                        )
                    await asyncio.sleep(wait_time)
            else:
                return response
