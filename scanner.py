#!/usr/bin/env python3
"""
Cloudflare Relay IP Scanner – Robust Edition for Iran & Filtered Networks (v10)
================================================================================
Designed to find the fastest, clean Cloudflare edge IPs that can be used as
egress relays in Cloudflare Workers, even when direct access to many IPs is
blocked (e.g., in Iran).

Key improvements over previous versions:
- Pre‑flight proxy test to ensure the proxy works before scanning.
- Automatic fallback: if HTTP CONNECT fails, the scanner tries SOCKS5.
- Exponential backoff & smart retry for TCP pings.
- Cleanliness test with configurable test URLs and automatic fallback
  (if the test URL is unreachable, the scanner can skip the cleanliness
  check and warn the user).
- Detailed logging per IP to help diagnose why an IP was rejected.
- Safe atomic file writes, graceful interruption, and rich console output.

Usage:
  python cf_relay_scanner.py -p socks5://127.0.0.1:10808 --top 50
  (or http://127.0.0.1:8080, or without a proxy if you have direct access)
"""

import asyncio
import argparse
import base64
import ipaddress
import json
import logging
import math
import os
import random
import re
import signal
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Union, Any
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientTimeout, TCPConnector, ClientSession
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"
IPAPI_BATCH_URL = "http://ip-api.com/batch"

DEFAULT_PROXY = "http://127.0.0.1:10809"
DEFAULT_TIMEOUT = 3.0
DEFAULT_MAX_PING_MS = 300
DEFAULT_MIN_SUCCESS = 2
DEFAULT_PING_COUNT = 4
DEFAULT_MAX_JITTER_MS = 50
DEFAULT_CONCURRENCY = 150
DEFAULT_OUTPUT_DIR = "Result"
API_BATCH_SIZE = 100
API_TIMEOUT = 12
FETCH_TIMEOUT = 15

# Cleanliness test defaults
DEFAULT_TEST_URLS = [
    "https://www.cloudflare.com/robots.txt",
    "https://cloudflare.com/cdn-cgi/trace",
]

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Patterns indicating a Cloudflare challenge page
CF_CHALLENGE_PATTERNS = [
    "cf-chl-bypass",
    "cf_chl_opt",
    "Checking your browser",
    "cf-browser-verification",
    "Just a moment...",
    "Please complete the security check",
]

# Well‑known test IP used for proxy validation
PROXY_TEST_IP = "1.1.1.1"
PROXY_TEST_PORT = 443

# ----------------------------------------------------------------------
# Logging & console
# ----------------------------------------------------------------------
console = Console()
logger = logging.getLogger("relay-scanner")


# ----------------------------------------------------------------------
# Custom exceptions
# ----------------------------------------------------------------------
class ScannerError(Exception):
    """Base exception for scanner-related errors."""


class ProxyError(ScannerError):
    """Raised when the proxy cannot be used or fails validation."""


class CleanlinessCheckError(ScannerError):
    """Raised when a cleanliness check cannot be completed."""


# ----------------------------------------------------------------------
# Utility helpers
# ----------------------------------------------------------------------
def sanitize_filename(name: str) -> str:
    """Replace spaces with underscores and remove invalid filename characters."""
    name = name.replace(" ", "_")
    return re.sub(r'[\\/*?:"<>|]', "", name)


def parse_proxy_url(
    proxy_url: str,
) -> Tuple[str, str, int, Optional[str], Optional[str]]:
    """
    Decompose a proxy URL into (scheme, host, port, user, password).
    Supports http, https, and socks5 schemes.
    """
    parsed = urlparse(proxy_url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname
    if not host:
        raise ScannerError(f"Invalid proxy URL: {proxy_url}")
    port = parsed.port or (1080 if scheme == "socks5" else 10809)
    user = parsed.username
    password = parsed.password
    return scheme, host, port, user, password


def build_proxy_auth(
    user: Optional[str], pwd: Optional[str]
) -> Optional[aiohttp.BasicAuth]:
    """Create aiohttp BasicAuth if credentials are provided."""
    if user and pwd:
        return aiohttp.BasicAuth(user, pwd)
    return None


def generate_cf_headers() -> Dict[str, str]:
    """Return a set of realistic browser headers to reduce blocking."""
    return {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }


def contains_challenge(html: str) -> bool:
    """Check if the HTML content contains known Cloudflare challenge patterns."""
    lower = html.lower()
    return any(pattern.lower() in lower for pattern in CF_CHALLENGE_PATTERNS)


async def sleep_backoff(
    attempt: int, base: float = 0.5, max_sleep: float = 5.0
) -> None:
    """Exponential backoff sleep."""
    sleep_time = min(base * (2**attempt), max_sleep)
    await asyncio.sleep(sleep_time)


# ----------------------------------------------------------------------
# Session factories
# ----------------------------------------------------------------------
def create_direct_session(timeout: float = 15) -> ClientSession:
    """Create an aiohttp session without any proxy."""
    return aiohttp.ClientSession(
        timeout=ClientTimeout(total=timeout),
        trust_env=False,
        connector=TCPConnector(ssl=False),
    )


def create_proxy_session(proxy_url: str, timeout: float = 15) -> ClientSession:
    """
    Create an aiohttp session that routes all traffic through the given proxy.
    Supports HTTP/HTTPS and SOCKS5 (if aiohttp-socks is installed).
    """
    scheme, host, port, user, pwd = parse_proxy_url(proxy_url)
    if scheme in ("http", "https"):
        proxy_auth = build_proxy_auth(user, pwd)
        return aiohttp.ClientSession(
            timeout=ClientTimeout(total=timeout),
            proxy=proxy_url,
            proxy_auth=proxy_auth,
            trust_env=False,
        )
    elif scheme == "socks5":
        try:
            from aiohttp_socks import ProxyConnector, ProxyType
        except ImportError:
            raise ScannerError(
                "SOCKS5 proxy requires aiohttp-socks. Install it with: pip install aiohttp-socks"
            )
        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS5,
            host=host,
            port=port,
            username=user,
            password=pwd,
            rdns=True,
        )
        return aiohttp.ClientSession(
            timeout=ClientTimeout(total=timeout),
            connector=connector,
            trust_env=False,
        )
    else:
        raise ScannerError(f"Unsupported proxy scheme: {scheme}")


# ----------------------------------------------------------------------
# Proxy auto‑detection and validation
# ----------------------------------------------------------------------
async def test_http_proxy_connect(
    host: str,
    port: int,
    user: Optional[str],
    pwd: Optional[str],
    test_ip: str = PROXY_TEST_IP,
    test_port: int = PROXY_TEST_PORT,
    timeout: float = 5.0,
) -> bool:
    """
    Attempt an HTTP CONNECT through the proxy to a known IP.
    Returns True on success.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except Exception:
        return False

    try:
        connect_request = f"CONNECT {test_ip}:{test_port} HTTP/1.0\r\n"
        if user and pwd:
            credentials = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            connect_request += f"Proxy-Authorization: Basic {credentials}\r\n"
        connect_request += "\r\n"
        writer.write(connect_request.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.readline(), timeout=timeout)
        response = response.decode(errors="ignore").strip()
        if not response.startswith("HTTP/1.") or "200" not in response.split()[0:2]:
            return False
        # Drain headers
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if line == b"\r\n" or line == b"\n" or not line:
                break
        return True
    except Exception:
        return False
    finally:
        writer.close()
        await writer.wait_closed()


async def test_socks5_proxy_connect(
    host: str,
    port: int,
    user: Optional[str],
    pwd: Optional[str],
    test_ip: str = PROXY_TEST_IP,
    test_port: int = PROXY_TEST_PORT,
    timeout: float = 5.0,
) -> bool:
    """
    Attempt a SOCKS5 connection through the proxy to a known IP.
    Returns True on success.
    """
    try:
        from aiohttp_socks import ProxyConnector, ProxyType
    except ImportError:
        return False  # SOCKS not available
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except Exception:
        return False

    try:
        # SOCKS5 handshake
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp != b"\x05\x00":
            return False
        # Connection request
        addr = ipaddress.ip_address(test_ip)
        atyp = b"\x01" if addr.version == 4 else b"\x04"
        writer.write(
            b"\x05\x01\x00" + atyp + addr.packed + test_port.to_bytes(2, "big")
        )
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(10), timeout=timeout)
        if resp[1] != 0x00:
            return False
        return True
    except Exception:
        return False
    finally:
        writer.close()
        await writer.wait_closed()


class ProxyValidator:
    """
    Validates the user's proxy settings.
    Attempts HTTP CONNECT first; if that fails, tries SOCKS5.
    Updates the proxy scheme accordingly.
    """

    def __init__(self, proxy_url: str):
        self.original = proxy_url
        self.scheme, self.host, self.port, self.user, self.pwd = parse_proxy_url(
            proxy_url
        )
        self.working_scheme: Optional[str] = None

    async def validate(self) -> str:
        """
        Returns a valid proxy URL with the correct scheme.
        Raises ProxyError if no scheme works.
        """
        # First try HTTP(S)
        if self.scheme in ("http", "https"):
            ok = await test_http_proxy_connect(
                self.host, self.port, self.user, self.pwd
            )
            if ok:
                self.working_scheme = self.scheme
                return self.original

        # Try SOCKS5 as a fallback (or if the scheme is already SOCKS5)
        ok_socks = await test_socks5_proxy_connect(
            self.host, self.port, self.user, self.pwd
        )
        if ok_socks:
            self.working_scheme = "socks5"
            # Build a new proxy URL with socks5 scheme
            auth = f"{self.user}:{self.pwd}@" if self.user and self.pwd else ""
            return f"socks5://{auth}{self.host}:{self.port}"

        raise ProxyError(
            "Proxy validation failed. Neither HTTP CONNECT nor SOCKS5 worked. "
            "Please check that the proxy is running and reachable."
        )


# ----------------------------------------------------------------------
# TCP ping implementation with retry and backoff
# ----------------------------------------------------------------------
class TCPPing:
    """
    Measures TCP connect latency through a proxy.
    Handles HTTP CONNECT and SOCKS5, with retry logic.
    """

    def __init__(self, proxy_url: str, timeout: float = DEFAULT_TIMEOUT):
        self.proxy_url = proxy_url
        self.scheme, self.proxy_host, self.proxy_port, self.user, self.pwd = (
            parse_proxy_url(proxy_url)
        )
        self.timeout = timeout

    async def ping(self, ip: str, port: int = 443, retries: int = 2) -> Optional[float]:
        """
        Returns latency in ms, or None after all retries.
        """
        last_exc = None
        for attempt in range(retries + 1):
            try:
                if self.scheme in ("http", "https"):
                    latency = await self._http_connect_ping(ip, port)
                elif self.scheme == "socks5":
                    latency = await self._socks5_connect_ping(ip, port)
                else:
                    raise ScannerError(f"Unsupported scheme: {self.scheme}")
                if latency is not None:
                    return latency
            except Exception as e:
                last_exc = e
            if attempt < retries:
                await sleep_backoff(attempt)
        return None

    async def _http_connect_ping(self, ip: str, port: int) -> Optional[float]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.proxy_host, self.proxy_port),
                timeout=self.timeout,
            )
        except Exception:
            return None

        start = time.monotonic()
        try:
            connect_request = f"CONNECT {ip}:{port} HTTP/1.0\r\n"
            if self.user and self.pwd:
                credentials = base64.b64encode(
                    f"{self.user}:{self.pwd}".encode()
                ).decode()
                connect_request += f"Proxy-Authorization: Basic {credentials}\r\n"
            connect_request += "\r\n"
            writer.write(connect_request.encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            response = response.decode(errors="ignore").strip()
            if not response.startswith("HTTP/1.") or "200" not in response.split()[0:2]:
                return None
            # Drain remaining headers
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
                if line == b"\r\n" or line == b"\n" or not line:
                    break
            return (time.monotonic() - start) * 1000
        except Exception:
            return None
        finally:
            writer.close()
            await writer.wait_closed()

    async def _socks5_connect_ping(self, ip: str, port: int) -> Optional[float]:
        try:
            from aiohttp_socks import ProxyConnector, ProxyType
        except ImportError:
            logger.error("SOCKS5 ping requires aiohttp-socks")
            return None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.proxy_host, self.proxy_port),
                timeout=self.timeout,
            )
        except Exception:
            return None

        start = time.monotonic()
        try:
            # Handshake
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
            if resp != b"\x05\x00":
                return None
            # Connection request
            addr = ipaddress.ip_address(ip)
            atyp = b"\x01" if addr.version == 4 else b"\x04"
            writer.write(b"\x05\x01\x00" + atyp + addr.packed + port.to_bytes(2, "big"))
            await writer.drain()
            resp = await asyncio.wait_for(reader.readexactly(10), timeout=self.timeout)
            if resp[1] != 0x00:
                return None
            return (time.monotonic() - start) * 1000
        except Exception:
            return None
        finally:
            writer.close()
            await writer.wait_closed()


# ----------------------------------------------------------------------
# Cleanliness tester with fallback and multi‑URL support
# ----------------------------------------------------------------------
class CleanlinessTester:
    """
    Verifies that an IP (accessed via proxy) is not flagged by Cloudflare.
    Tries several test URLs; if all are unreachable, can optionally skip
    the check.
    """

    def __init__(
        self,
        proxy_url: str,
        test_urls: List[str] = None,
        timeout: float = 10.0,
        skip_on_network_error: bool = True,
    ):
        self.proxy_url = proxy_url
        self.test_urls = test_urls or DEFAULT_TEST_URLS
        self.timeout = timeout
        self.skip_on_network_error = skip_on_network_error
        self._session: Optional[ClientSession] = None

    async def _get_session(self) -> ClientSession:
        if self._session is None:
            self._session = create_proxy_session(self.proxy_url, self.timeout)
        return self._session

    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None

    async def is_clean(self, ip: str) -> bool:
        """
        Returns True if the IP passes the cleanliness test.
        If all test URLs are unreachable and skip_on_network_error is True,
        the IP is considered clean (with a warning).
        """
        session = await self._get_session()
        headers = generate_cf_headers()
        network_error = False
        for url in self.test_urls:
            try:
                async with session.get(
                    url, headers=headers, allow_redirects=True, timeout=self.timeout
                ) as resp:
                    if resp.status in (403, 503):
                        logger.debug(f"IP {ip} blocked by {url} (status {resp.status})")
                        return False
                    body = await resp.text()
                    if len(body) > 65536:
                        body = body[:65536]
                    if contains_challenge(body):
                        logger.debug(f"IP {ip} triggered challenge on {url}")
                        return False
                    # If we get a normal response, the IP is clean
                    return True
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"Cleanliness test for {ip} on {url} failed: {e}")
                network_error = True
                continue
            except Exception as e:
                logger.debug(f"Unexpected error on cleanliness test: {e}")
                network_error = True
                continue

        # If we reach here, all test URLs failed
        if self.skip_on_network_error:
            logger.warning(
                f"All cleanliness URLs unreachable for {ip}. "
                "Skipping cleanliness check (IP assumed clean)."
            )
            return True
        else:
            return False


# ----------------------------------------------------------------------
# IP quality tester
# ----------------------------------------------------------------------
class IPQualityTester:
    """
    Combines TCP latency/jitter measurements with an optional cleanliness
    check. Only IPs that pass both are considered 'working'.
    """

    def __init__(
        self,
        proxy_url: str,
        port: int = 443,
        timeout: float = DEFAULT_TIMEOUT,
        ping_count: int = DEFAULT_PING_COUNT,
        min_success: int = DEFAULT_MIN_SUCCESS,
        max_ping_ms: float = DEFAULT_MAX_PING_MS,
        max_jitter_ms: float = DEFAULT_MAX_JITTER_MS,
        test_clean: bool = True,
        clean_tester: Optional[CleanlinessTester] = None,
    ):
        self.pinger = TCPPing(proxy_url, timeout)
        self.port = port
        self.timeout = timeout
        self.ping_count = ping_count
        self.min_success = min_success
        self.max_ping_ms = max_ping_ms
        self.max_jitter_ms = max_jitter_ms
        self.test_clean = test_clean
        self.clean_tester = clean_tester

    async def test(self, ip: str) -> Optional[Tuple[float, float]]:
        """Returns (avg_latency, jitter) or None if the IP is rejected."""
        # Latency phase
        latencies = []
        for _ in range(self.ping_count):
            lat = await self.pinger.ping(ip, self.port)
            if lat is not None:
                latencies.append(lat)
            if len(latencies) >= self.min_success:
                break

        if len(latencies) < self.min_success:
            return None

        avg = sum(latencies) / len(latencies)
        if avg > self.max_ping_ms:
            return None

        if len(latencies) > 1:
            variance = sum((x - avg) ** 2 for x in latencies) / (len(latencies) - 1)
            jitter = math.sqrt(variance)
        else:
            jitter = 0.0

        if jitter > self.max_jitter_ms:
            return None

        # Cleanliness phase (optional)
        if self.test_clean and self.clean_tester is not None:
            if not await self.clean_tester.is_clean(ip):
                return None

        return (avg, jitter)


# ----------------------------------------------------------------------
# Country classifier
# ----------------------------------------------------------------------
class OnlineClassifier:
    """Classifies IPs by country using ip‑api.com."""

    def __init__(self, proxy_url: Optional[str], timeout: float = API_TIMEOUT):
        self.proxy_url = proxy_url
        self.timeout = timeout
        self._session_direct: Optional[ClientSession] = None
        self._session_proxy: Optional[ClientSession] = None

    async def close(self):
        if self._session_direct:
            await self._session_direct.close()
        if self._session_proxy:
            await self._session_proxy.close()

    async def _get_session(self, use_proxy: bool) -> ClientSession:
        if use_proxy and self.proxy_url:
            if self._session_proxy is None:
                self._session_proxy = create_proxy_session(self.proxy_url, self.timeout)
            return self._session_proxy
        if self._session_direct is None:
            self._session_direct = create_direct_session(self.timeout)
        return self._session_direct

    async def _classify_batch(
        self, session: ClientSession, ips: List[str]
    ) -> Optional[Dict[str, str]]:
        payload = [{"query": ip} for ip in ips]
        try:
            async with session.post(
                IPAPI_BATCH_URL,
                json=payload,
                headers={"User-Agent": "CloudflareRelayScanner/10.0"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result = {}
                    for entry in data:
                        ip_ret = entry.get("query", "")
                        country = entry.get("country", "") or "Unknown"
                        result[ip_ret] = country
                    # Fill missing IPs
                    for ip in ips:
                        if ip not in result:
                            result[ip] = "Unknown"
                    return result
        except Exception as e:
            logger.debug(f"Batch classification failed: {e}")
            return None

    async def classify_batch(self, ips: List[str]) -> Dict[str, str]:
        # Try direct
        session_direct = await self._get_session(use_proxy=False)
        res = await self._classify_batch(session_direct, ips)
        if res is not None:
            return res

        # Try proxy
        if self.proxy_url:
            session_proxy = await self._get_session(use_proxy=True)
            res = await self._classify_batch(session_proxy, ips)
            if res is not None:
                return res

        # All failed
        return {ip: "Unknown" for ip in ips}

    async def classify_all(
        self, ips: List[str], progress: Progress, task_id
    ) -> Dict[str, str]:
        mapping = {}
        total = len(ips)
        for i in range(0, total, API_BATCH_SIZE):
            batch = ips[i : i + API_BATCH_SIZE]
            batch_result = await self.classify_batch(batch)
            mapping.update(batch_result)
            progress.update(task_id, advance=len(batch))
            await asyncio.sleep(0.25)
        return mapping


# ----------------------------------------------------------------------
# Result writer (atomic, per‑country + All.txt + JSON)
# ----------------------------------------------------------------------
class ResultWriter:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.country_ips: Dict[str, List[str]] = defaultdict(list)
        self.locks: Dict[str, asyncio.Lock] = {}
        self.all_ips: List[str] = []
        self.all_lock = asyncio.Lock()
        self._all_file_path = self.output_dir / "All.txt"
        self._json_file_path = self.output_dir / "All.json"

    def _format(self, ips: List[str]) -> str:
        return ", ".join(ips) if ips else ""

    async def add_ip(self, ip: str, country_name: str):
        filename_key = sanitize_filename(country_name)
        if filename_key not in self.locks:
            self.locks[filename_key] = asyncio.Lock()

        async with self.locks[filename_key]:
            self.country_ips[filename_key].append(ip)
            await self._write_country_file(filename_key)

        async with self.all_lock:
            self.all_ips.append(ip)
            await self._write_all_txt()
            await self._write_all_json()

    async def _write_country_file(self, filename_key: str):
        file_path = self.output_dir / f"{filename_key}.txt"
        content = self._format(self.country_ips[filename_key])
        await self._atomic_write(file_path, content)

    async def _write_all_txt(self):
        content = self._format(self.all_ips)
        await self._atomic_write(self._all_file_path, content)

    async def _write_all_json(self):
        # Write IPs grouped by country as JSON
        data = {
            "scan_time": datetime.now().isoformat(),
            "total_ips": len(self.all_ips),
            "countries": {},
        }
        for country, ips in self.country_ips.items():
            data["countries"][country] = ips
        content = json.dumps(data, indent=2)
        await self._atomic_write(self._json_file_path, content)

    async def _atomic_write(self, file_path: Path, content: str):
        """Write content to a temporary file, then atomically replace target."""
        loop = asyncio.get_running_loop()

        def write():
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=self.output_dir, prefix=".tmp_", suffix=".tmp"
            )
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                    f.write(content)
                if os.name == "nt" and file_path.exists():
                    file_path.unlink()
                os.replace(tmp_path, file_path)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

        await loop.run_in_executor(None, write)

    def get_summary(self) -> Dict[str, int]:
        return {fname: len(ips) for fname, ips in self.country_ips.items()}


# ----------------------------------------------------------------------
# Main Scanner
# ----------------------------------------------------------------------
class CloudflareRelayScanner:
    """
    Orchestrates fetching, scanning, classifying, and saving.
    """

    def __init__(
        self,
        proxy: str,
        timeout: float,
        max_ping_ms: int,
        ping_count: int,
        min_success: int,
        max_jitter_ms: float,
        concurrency: int,
        output_dir: str,
        include_ipv6: bool = False,
        test_port: int = 443,
        max_ips: Optional[int] = None,
        top_n: Optional[int] = None,
        skip_clean: bool = False,
        test_urls: Optional[List[str]] = None,
        skip_clean_on_network_error: bool = True,
    ):
        self.proxy = proxy
        self.timeout = timeout
        self.concurrency = concurrency
        self.include_ipv6 = include_ipv6
        self.max_ips = max_ips
        self.top_n = top_n
        self.skip_clean = skip_clean
        self.output_dir = Path(output_dir)

        self.stats = {"total": 0, "tested": 0, "working": 0}
        self.working_ips: List[Tuple[str, float, float]] = []
        self.stop_requested = False
        self.semaphore = asyncio.Semaphore(concurrency)

        # Cleanliness tester
        self.clean_tester = None
        if not skip_clean:
            self.clean_tester = CleanlinessTester(
                proxy_url=proxy,
                test_urls=test_urls,
                timeout=10.0,
                skip_on_network_error=skip_clean_on_network_error,
            )

        # Quality tester
        self.tester = IPQualityTester(
            proxy_url=proxy,
            port=test_port,
            timeout=timeout,
            ping_count=ping_count,
            min_success=min_success,
            max_ping_ms=max_ping_ms,
            max_jitter_ms=max_jitter_ms,
            test_clean=not skip_clean,
            clean_tester=self.clean_tester,
        )

        self.classifier = OnlineClassifier(proxy)
        self.writer = ResultWriter(self.output_dir)

    async def fetch_ip_list(self) -> List[str]:
        """Download Cloudflare's IP ranges, optionally sample them."""
        console.print("[bold cyan]Fetching Cloudflare IP ranges...[/bold cyan]")

        # We use adaptive fetch with proxy fallback (same as v8)
        async def _fetch(url: str) -> Optional[str]:
            for attempt in range(3):
                try:
                    async with create_direct_session(FETCH_TIMEOUT) as session:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                return await resp.text()
                except Exception:
                    pass
                await asyncio.sleep(0.5 * (attempt + 1))
            # fallback to proxy
            try:
                async with create_proxy_session(self.proxy, FETCH_TIMEOUT) as session:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            return await resp.text()
            except Exception:
                return None

        ipv4_text = await _fetch(CLOUDFLARE_IPV4_URL)
        ipv6_text = await _fetch(CLOUDFLARE_IPV6_URL) if self.include_ipv6 else None

        if not ipv4_text:
            console.print("[red]Failed to fetch Cloudflare IPv4 ranges.[/red]")
            return []

        ranges = [line.strip() for line in ipv4_text.splitlines() if line.strip()]
        if ipv6_text:
            ranges.extend(
                line.strip() for line in ipv6_text.splitlines() if line.strip()
            )

        all_ips = []
        for net_str in ranges:
            try:
                net = ipaddress.ip_network(net_str, strict=False)
                if net.num_addresses > 2:
                    all_ips.extend(str(ip) for ip in net.hosts())
                else:
                    all_ips.extend(str(ip) for ip in net)
            except ValueError:
                logger.warning(f"Skipping invalid network: {net_str}")

        if self.max_ips and self.max_ips < len(all_ips):
            all_ips = random.sample(all_ips, self.max_ips)
            console.print(f"  Limited to {self.max_ips} random IPs.")
        console.print(f"  Total IPs to scan: {len(all_ips)}")
        return all_ips

    async def scan_ip(self, ip: str, progress: Progress, task_id):
        if self.stop_requested:
            return
        async with self.semaphore:
            result = await self.tester.test(ip)
            self.stats["tested"] += 1
            if result is not None:
                avg, jitter = result
                self.working_ips.append((ip, avg, jitter))
                self.stats["working"] += 1
                progress.update(
                    task_id,
                    advance=1,
                    description=f"[bold green]Scanned[/] (good: {self.stats['working']})",
                )
                progress.console.log(
                    f"[green]✓ {ip}[/] avg={avg:.1f}ms jitter={jitter:.1f}ms"
                )
            else:
                progress.update(task_id, advance=1)

    async def classify_and_save(self):
        if not self.working_ips:
            console.print("[red]No working IPs found.[/red]")
            return

        # Sort and possibly keep top N
        self.working_ips.sort(key=lambda x: (x[1], x[2]))
        selected = self.working_ips
        if self.top_n and self.top_n < len(selected):
            selected = selected[: self.top_n]
            console.print(f"[yellow]Keeping top {self.top_n} IPs.[/yellow]")

        ips_to_classify = [ip for ip, _, _ in selected]
        console.print(f"[cyan]Classifying {len(ips_to_classify)} IPs...[/cyan]")

        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
        )
        with progress:
            task = progress.add_task(
                "[magenta]Classification", total=len(ips_to_classify)
            )
            mapping = await self.classifier.classify_all(
                ips_to_classify, progress, task
            )

        for ip in ips_to_classify:
            country = mapping.get(ip, "Unknown")
            await self.writer.add_ip(ip, country)

        console.print("[green]Classification and saving complete.[/green]")

    async def run(self):
        # Pre‑flight proxy validation
        try:
            validator = ProxyValidator(self.proxy)
            validated_proxy = await validator.validate()
            if validated_proxy != self.proxy:
                console.print(
                    f"[bold yellow]Proxy scheme corrected to: {validated_proxy}[/bold yellow]"
                )
                # Update internal proxy references
                self.proxy = validated_proxy
                # Re‑create testers with new proxy
                self.tester.pinger = TCPPing(self.proxy, self.timeout)
                if self.clean_tester:
                    await self.clean_tester.close()
                    self.clean_tester = CleanlinessTester(
                        proxy_url=self.proxy,
                        test_urls=self.clean_tester.test_urls,
                        timeout=10.0,
                        skip_on_network_error=self.clean_tester.skip_on_network_error,
                    )
                    self.tester.clean_tester = self.clean_tester
        except ProxyError as e:
            console.print(f"[red]Proxy validation error: {e}[/red]")
            return

        all_ips = await self.fetch_ip_list()
        if not all_ips:
            return
        self.stats["total"] = len(all_ips)

        console.print("\n[bold magenta]Starting scan...[/bold magenta]")
        clean_status = "OFF" if self.skip_clean else "ON"
        console.print(
            Panel.fit(
                f"Proxy:             [cyan]{self.proxy}[/]\n"
                f"Max ping:          [cyan]{self.tester.max_ping_ms}ms[/]\n"
                f"Max jitter:        [cyan]{self.tester.max_jitter_ms}ms[/]\n"
                f"Min success:       [cyan]{self.tester.min_success}/{self.tester.ping_count}[/]\n"
                f"Concurrency:       [cyan]{self.concurrency}[/]\n"
                f"Cleanliness test:  [cyan]{clean_status}[/]\n"
                f"Output:            [cyan]{self.output_dir.resolve()}[/]",
                title="Scan Parameters",
                border_style="blue",
            )
        )

        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
        )
        scan_task = progress.add_task("[yellow]Scanning IPs...", total=len(all_ips))

        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def signal_handler():
            console.print(
                "\n[bold yellow]Interrupted! Saving current results...[/bold yellow]"
            )
            self.stop_requested = True
            stop_event.set()

        try:
            loop.add_signal_handler(signal.SIGINT, signal_handler)
            loop.add_signal_handler(signal.SIGTERM, signal_handler)
        except NotImplementedError:
            pass

        with progress:
            tasks = [
                asyncio.create_task(self.scan_ip(ip, progress, scan_task))
                for ip in all_ips
            ]
            done, pending = await asyncio.wait(
                tasks,
                return_when=asyncio.FIRST_COMPLETED
                if stop_event.is_set()
                else asyncio.ALL_COMPLETED,
            )
            if stop_event.is_set():
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)

        console.print(
            f"\n[bold]Scan finished. {len(self.working_ips)} IPs passed.[/bold]"
        )
        await self.classify_and_save()

        # Final summary
        final_count = len(self.writer.all_ips)
        summary = Table(title="Results")
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", style="green")
        summary.add_row("IPs tested", str(self.stats["tested"]))
        summary.add_row("Passed quality", str(len(self.working_ips)))
        summary.add_row("Final IPs saved", str(final_count))
        summary.add_row("Output", str(self.output_dir.resolve()))
        console.print(summary)

        country_summary = self.writer.get_summary()
        if country_summary:
            ctable = Table(title="IPs per Country")
            ctable.add_column("Country File", style="cyan")
            ctable.add_column("Count", style="green")
            for fname, cnt in sorted(country_summary.items()):
                ctable.add_row(f"{fname}.txt", str(cnt))
            console.print(ctable)

        # Cleanup
        if self.clean_tester:
            await self.clean_tester.close()
        await self.classifier.close()


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Cloudflare Relay IP Scanner – Robust Edition",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-p", "--proxy", default=DEFAULT_PROXY, help="Proxy URL (http, https, socks5)"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="TCP timeout (s)"
    )
    parser.add_argument(
        "-m",
        "--max-ping",
        type=int,
        default=DEFAULT_MAX_PING_MS,
        help="Max avg latency (ms)",
    )
    parser.add_argument(
        "--min-success",
        type=int,
        default=DEFAULT_MIN_SUCCESS,
        help="Min successful pings",
    )
    parser.add_argument(
        "--ping-count", type=int, default=DEFAULT_PING_COUNT, help="Total ping attempts"
    )
    parser.add_argument(
        "--max-jitter",
        type=float,
        default=DEFAULT_MAX_JITTER_MS,
        help="Max jitter (ms)",
    )
    parser.add_argument(
        "-C",
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="Max concurrent tasks",
    )
    parser.add_argument(
        "-o", "--output-dir", default=DEFAULT_OUTPUT_DIR, help="Output directory"
    )
    parser.add_argument("--include-ipv6", action="store_true", help="Scan IPv6 ranges")
    parser.add_argument(
        "--port", type=int, default=443, help="TCP port for latency test"
    )
    parser.add_argument("--max-ips", type=int, help="Limit total IPs to test")
    parser.add_argument("--top", type=int, help="Keep top N IPs")
    parser.add_argument(
        "--skip-clean", action="store_true", help="Disable cleanliness check"
    )
    parser.add_argument(
        "--test-urls",
        nargs="+",
        default=DEFAULT_TEST_URLS,
        help="URLs used for cleanliness test",
    )
    parser.add_argument(
        "--no-skip-on-network-error",
        action="store_true",
        help="Fail cleanliness test if test URLs are unreachable",
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    return parser.parse_args()


async def main():
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    console.print(
        Text(
            r"""
   ____ _                 _  __ _           _____           _
  / ___| | ___  _   _  __| |/ _| | __ _ _ _|  ___|__ _ __  / |
 | |   | |/ _ \| | | |/ _` | |_| |/ _` | '__| |_ / _ \ '_ \ | |
 | |___| | (_) | |_| | (_| |  _| | (_| | |  |  _|  __/ |_) || |
  \____|_|\___/ \__,_|\__,_|_| |_|\__,_|_|  |_|  \___| .__/ |_|
                                                      |_|
   Relay IP Scanner – Robust Edition for Iran & Filtered Networks
        """,
            style="bold cyan",
        )
    )

    scanner = CloudflareRelayScanner(
        proxy=args.proxy,
        timeout=args.timeout,
        max_ping_ms=args.max_ping,
        ping_count=args.ping_count,
        min_success=args.min_success,
        max_jitter_ms=args.max_jitter,
        concurrency=args.concurrency,
        output_dir=args.output_dir,
        include_ipv6=args.include_ipv6,
        test_port=args.port,
        max_ips=args.max_ips,
        top_n=args.top,
        skip_clean=args.skip_clean,
        test_urls=args.test_urls,
        skip_clean_on_network_error=not args.no_skip_on_network_error,
    )
    await scanner.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]Aborted.[/bold red]")
        sys.exit(0)
