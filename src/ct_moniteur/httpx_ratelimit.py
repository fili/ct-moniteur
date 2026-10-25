"""Rate limiting transport for httpx."""

import asyncio
import itertools
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
    last_raised: float = 0.0


# A burst of parallel requests gets a burst of 429s for the same overload;
# reducing on each one collapsed the rate to ~0 and it never recovered.
# AIMD instead: cut at most once per window, probe back up while healthy.
# Recovery is time-based: per-request recovery barely moved a collapsed
# rate (1 req/s needs 1000s per +10%), so a log stayed throttled for days.
REDUCE_WINDOW = 10.0
RAISE_INTERVAL = 30.0
RATE_INCREASE = 1.1
# Halving on every cut outran the +10% raises and pinned shared-IP logs
# at MIN_RATE; a gentler cut lets the rate hover near the real limit.
RATE_DECREASE = 0.7
# Retry-After is often absent and 1/rate is ~0 at high rates, so retries
# spun at sub-millisecond intervals. Back off per attempt instead.
RETRY_BASE = 0.5
RETRY_MAX = 60.0
MIN_RATE = 1.0


class RateLimitedTransport(httpx.AsyncHTTPTransport):
    """httpx transport that learns and enforces rate limits from 429 responses."""

    def __init__(
        self,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
        shard_id: Optional[int] = None,
        min_rate: float = MIN_RATE,
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
        # Logs that shed load at random (TrustAsia: ~50% 429 even at
        # 0.3 req/s from idle IPs) drive any limiter to the floor without
        # reducing their 429s, so such fetchers set a higher floor.
        self._min_rate = min_rate
        self._shard_prefix = f"shard{shard_id}:" if shard_id is not None else ""
        # Limits are per egress IP, so say which one a message is about
        if kwargs.get("proxy"):
            node = httpx.URL(kwargs["proxy"]).host.split(".")[0]
            self._shard_prefix += f"via {node}:"

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
                now = time.monotonic()
                if (host_data.rate_limit is not None
                        and now - max(host_data.last_reduced,
                                      host_data.last_raised)
                        >= RAISE_INTERVAL):
                    host_data.rate_limit *= RATE_INCREASE
                    host_data.last_raised = now
                    logger.info(
                        f"{int(time.time())}:{self._shard_prefix}[{host}] "
                        f"Rate limit raised to: "
                        f"{host_data.rate_limit:.2f} req/s"
                    )
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
                    host_data.first_request_time = None
                    host_data.request_count = 0

            # Sleep outside lock
            if wait_time > 0:
                await asyncio.sleep(wait_time)

            response = await super().handle_async_request(request)

            if response.status_code == 429:
                # Unread 429 bodies keep their pooled connection checked
                # out; retries then queue behind them.
                await response.aclose()
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
                            host_data.rate_limit = max(raw_rate * 0.5, self._min_rate)
                            host_data.last_reduced = now
                            logger.warning(
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
                            host_data.rate_limit * RATE_DECREASE, self._min_rate
                        )
                        host_data.last_reduced = now
                        logger.warning(
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
                    wait_time = max(
                        wait_time,
                        min(RETRY_BASE * 2 ** (attempt - 1), RETRY_MAX),
                    )

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


class PooledTransport(httpx.AsyncBaseTransport):
    """Round-robins requests over transports with different egress IPs.

    Some logs (Cloudflare) limit per source IP, so one IP caps a fetcher no
    matter how well it paces. Each child learns its own per-IP limit.
    """

    def __init__(self, transports: list[httpx.AsyncBaseTransport]):
        self._transports = transports
        self._next = itertools.cycle(transports)

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        return await next(self._next).handle_async_request(request)

    async def aclose(self) -> None:
        for transport in self._transports:
            await transport.aclose()
