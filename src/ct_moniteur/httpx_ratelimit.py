"""Rate limiting transport for httpx."""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional
import logging

import httpx

logger = logging.getLogger(__name__)


@dataclass
class HostData:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    first_request_time: Optional[float] = None
    request_count: int = 0
    rate_limit: Optional[float] = None


class RateLimitedTransport(httpx.AsyncHTTPTransport):
    """httpx transport that learns and enforces rate limits from 429 responses."""

    def __init__(
        self,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
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
            async with host_data.lock:
                if host_data.first_request_time is None:
                    host_data.first_request_time = time.monotonic()
                host_data.request_count += 1

                if host_data.request_count % 1_000 == 0:
                    elapsed = time.monotonic() - host_data.first_request_time
                    if elapsed > 0:
                        actual_rate = host_data.request_count / elapsed
                        logger.info(
                            f"[{host}] Rate stats: {host_data.request_count} reqs "
                            f"in {elapsed:.2f}s ({actual_rate:.2f} req/s)"
                        )
                    host_data.first_request_time = None
                    host_data.request_count = 0

            response = await super().handle_async_request(request)

            if response.status_code == 429:
                host_data = self._get_host_data(host)
                async with host_data.lock:
                    if host_data.first_request_time:
                        elapsed = time.monotonic() - host_data.first_request_time
                        if elapsed > 0 and host_data.request_count > 1:
                            host_data.rate_limit = (host_data.request_count - 1) / elapsed
                            logger.info(
                                f"[{host}] Rate limit learned: {host_data.rate_limit:.2f} req/s"
                            )
                            default_retry_after = min(1.0 / host_data.rate_limit, 10.0)
                        else:
                            default_retry_after = 5.0
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
                            f"[{host}] Rate limited (429): attempt {attempt}, retrying after {wait_time}s"
                        )
                    else:
                        logger.info(
                            f"[{host}] Rate limited (429): attempt {attempt}, retrying after {wait_time}s"
                        )
                    await asyncio.sleep(wait_time)
            else:
                return response
