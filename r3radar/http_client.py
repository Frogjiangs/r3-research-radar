from __future__ import annotations

import email.utils
import gzip
import ipaddress
import json
import os
import socket
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urljoin, urlsplit

import httpx

from .utils import JsonlAuditLog, redact_url, safe_slug, sha256_bytes, utc_now


class FetchError(RuntimeError):
    pass


class NonRetryableFetchError(FetchError):
    pass


class CircuitOpenError(FetchError):
    pass


class ResponseTooLargeError(FetchError):
    pass


class RetryDeferredError(FetchError):
    def __init__(self, message: str, retry_after_seconds: float):
        super().__init__(message)
        self.retry_after_seconds = max(0.0, retry_after_seconds)


@dataclass(frozen=True, slots=True)
class RawReceipt:
    sha256: str
    path: str
    byte_count: int
    status_code: int
    final_url: str
    fetched_at: str


def _retry_after_seconds(value: str | None, now: float) -> float | None:
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0.0, parsed.timestamp() - now)
        except (TypeError, ValueError, OverflowError):
            return None


def validate_public_http_url(
    url: str,
    *,
    resolver: Callable[..., Any] = socket.getaddrinfo,
    allow_rfc2544_proxy_fake_ip: bool = False,
) -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise FetchError(f"unsupported URL scheme: {parts.scheme or '[missing]'}")
    hostname = (parts.hostname or "").rstrip(".").lower()
    if not hostname:
        raise FetchError("URL has no hostname")
    if parts.username is not None or parts.password is not None:
        raise FetchError("URL user information is not allowed")
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        raise FetchError("local hostname is not allowed")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError as exc:
            raise FetchError("URL has an invalid port") from exc
        try:
            resolved = resolver(hostname, port, type=socket.SOCK_STREAM)
        except (OSError, socket.error) as exc:
            raise FetchError("hostname could not be resolved safely") from exc
        addresses = {
            str(item[4][0])
            for item in resolved
            if len(item) >= 5 and item[4]
        }
        if not addresses:
            raise FetchError("hostname resolved to no addresses")
        for value in addresses:
            try:
                resolved_address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise FetchError("hostname returned an invalid address") from exc
            if (
                allow_rfc2544_proxy_fake_ip
                and resolved_address.version == 4
                and resolved_address
                in ipaddress.ip_network("198.18.0.0/15")
            ):
                continue
            if not resolved_address.is_global:
                raise FetchError(
                    "hostname resolves to a non-public IP address"
                )
    else:
        if not address.is_global:
            raise FetchError("non-public IP address is not allowed")


class RawResponseStore:
    _path_locks_guard = threading.Lock()
    _path_locks: dict[str, tuple[threading.Lock, int]] = {}
    _permission_validation_delays = (0.0, 0.01, 0.02, 0.04, 0.08)

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    @classmethod
    @contextmanager
    def _lock_path(cls, path: Path) -> Iterator[None]:
        key = os.path.normcase(str(path.resolve(strict=False)))
        with cls._path_locks_guard:
            entry = cls._path_locks.get(key)
            if entry is None:
                path_lock = threading.Lock()
                users = 1
            else:
                path_lock, users = entry
                users += 1
            cls._path_locks[key] = (path_lock, users)

        acquired = False
        try:
            path_lock.acquire()
            acquired = True
            yield
        finally:
            if acquired:
                path_lock.release()
            with cls._path_locks_guard:
                registered_lock, users = cls._path_locks[key]
                if registered_lock is not path_lock or users < 1:
                    raise RuntimeError("raw response path lock registry is inconsistent")
                if users == 1:
                    del cls._path_locks[key]
                else:
                    cls._path_locks[key] = (path_lock, users - 1)

    @staticmethod
    def _matches_body(path: Path, body: bytes, digest: str) -> bool:
        try:
            with gzip.open(path, "rb") as handle:
                stored_body = handle.read(len(body) + 1)
                trailing = handle.read(1)
        except (EOFError, OSError):
            return False
        return (
            not trailing
            and len(stored_body) == len(body)
            and sha256_bytes(stored_body) == digest
        )

    @staticmethod
    def _write_atomic(path: Path, body: bytes, digest: str) -> None:
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=path.parent,
                prefix=".raw-response-",
                suffix=".tmp",
                delete=False,
            ) as raw_handle:
                temporary_path = Path(raw_handle.name)
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    compresslevel=6,
                    fileobj=raw_handle,
                    mtime=0,
                ) as gzip_handle:
                    gzip_handle.write(body)
                raw_handle.flush()
                os.fsync(raw_handle.fileno())
            try:
                os.replace(temporary_path, path)
            except PermissionError:
                # A different process or a short-lived Windows file handle may
                # have won the publication race. Accept only a fully matching
                # final body, and keep the validation window strictly bounded.
                for delay_seconds in (
                    RawResponseStore._permission_validation_delays
                ):
                    if delay_seconds:
                        time.sleep(delay_seconds)
                    if RawResponseStore._matches_body(path, body, digest):
                        break
                else:
                    raise
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def save(self, source: str, body: bytes, suffix: str) -> tuple[str, Path]:
        digest = sha256_bytes(body)
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        directory = self.root / safe_slug(source) / day
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{digest}.{safe_slug(suffix, 16)}.gz"
        with self._lock_path(path):
            if not self._matches_body(path, body, digest):
                self._write_atomic(path, body, digest)
        return digest, path


class SafeHttpClient:
    RESPONSE_CHUNK_BYTES = 64 * 1024

    def __init__(
        self,
        *,
        source: str,
        delay_seconds: float,
        raw_store: RawResponseStore,
        audit: JsonlAuditLog,
        run_id: str | None,
        timeout_seconds: float = 60,
        max_attempts: int = 4,
        circuit_failure_threshold: int = 5,
        max_inline_retry_seconds: float = 30,
        transport: httpx.BaseTransport | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        resolver: Callable[..., Any] = socket.getaddrinfo,
        slot_reserver: Callable[[str, float], float] | None = None,
        byte_consumer: Callable[[int], None] | None = None,
        observation_chunk_bytes: int | None = None,
        deadline_monotonic: float | None = None,
    ):
        contact = os.getenv("R3_RADAR_CONTACT_EMAIL", "").strip()
        user_agent = "R3ResearchRadar/0.1 (single-user academic research)"
        if contact:
            user_agent = f"R3ResearchRadar/0.1 (mailto:{contact})"
        self.source = source
        self.delay_seconds = max(0.0, float(delay_seconds))
        self.raw_store = raw_store
        self.audit = audit
        self.run_id = run_id
        self.max_attempts = max(1, int(max_attempts))
        self.circuit_failure_threshold = max(1, int(circuit_failure_threshold))
        self.max_inline_retry_seconds = max(0.0, float(max_inline_retry_seconds))
        self._sleeper = sleeper
        self._monotonic = monotonic
        self._resolver = resolver
        self._slot_reserver = slot_reserver
        self._byte_consumer = byte_consumer
        self._observation_chunk_bytes = max(
            1,
            int(observation_chunk_bytes or self.RESPONSE_CHUNK_BYTES),
        )
        self.timeout_seconds = max(0.001, float(timeout_seconds))
        self.deadline_monotonic = deadline_monotonic
        self._last_request_started: dict[str, float] = {}
        self._consecutive_failures = 0
        self._circuit_open = False
        self._retry_deferred_seconds: float | None = None
        self._client = httpx.Client(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": user_agent, "Accept-Encoding": "gzip, deflate"},
        )

    def _remaining_runtime_seconds(self) -> float | None:
        if self.deadline_monotonic is None:
            return None
        return self.deadline_monotonic - self._monotonic()

    def _request_timeout_seconds(self) -> float:
        remaining = self._remaining_runtime_seconds()
        if remaining is not None and remaining <= 0:
            raise RetryDeferredError(
                f"{self.source} run runtime budget reached before request",
                0,
            )
        return max(
            0.001,
            min(self.timeout_seconds, remaining)
            if remaining is not None
            else self.timeout_seconds,
        )

    def _sleep_for_retry(self, wait: float) -> None:
        remaining = self._remaining_runtime_seconds()
        if remaining is not None:
            if remaining <= 0:
                raise RetryDeferredError(
                    f"{self.source} run runtime budget reached before retry",
                    0,
                )
            if wait >= remaining:
                raise RetryDeferredError(
                    f"{self.source} retry does not fit the remaining run budget",
                    wait,
                )
        self._sleeper(wait)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SafeHttpClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _wait_for_slot(self, url: str) -> None:
        hostname = (urlsplit(url).hostname or "").rstrip(".").casefold()
        slot_key = f"http:{hostname}"
        if self._slot_reserver is not None:
            wait = max(
                0.0,
                float(self._slot_reserver(slot_key, self.delay_seconds)),
            )
            if wait > 0:
                self._sleep_for_retry(wait)
            return
        now = self._monotonic()
        last_started = self._last_request_started.get(slot_key)
        if last_started is not None:
            wait = self.delay_seconds - (now - last_started)
            if wait > 0:
                self._sleep_for_retry(wait)
        self._last_request_started[slot_key] = self._monotonic()

    def _read_response_body(
        self,
        response: httpx.Response,
        *,
        max_bytes: int,
        capture_bytes: int | None = None,
    ) -> tuple[bytes, int]:
        capture_limit = max_bytes if capture_bytes is None else max(0, capture_bytes)
        chunks: list[bytes] = []
        captured = 0
        observed = 0
        for chunk in response.iter_bytes(
            chunk_size=self._observation_chunk_bytes
        ):
            chunk_size = len(chunk)
            if self._byte_consumer is not None:
                self._byte_consumer(chunk_size)
            observed += chunk_size
            if observed > max_bytes:
                raise ResponseTooLargeError(
                    f"response exceeded {max_bytes} bytes while streaming"
                )
            remaining = capture_limit - captured
            if remaining > 0:
                value = chunk[:remaining]
                chunks.append(value)
                captured += len(value)
        return b"".join(chunks), observed

    @contextmanager
    def _stream_get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None,
        headers: dict[str, str],
        allowed_hosts: set[str] | None,
        max_bytes: int,
    ):
        current_url = url
        current_params = params
        normalized_allowed = (
            {value.rstrip(".").casefold() for value in allowed_hosts}
            if allowed_hosts
            else None
        )
        for redirect_count in range(6):
            request_host = (urlsplit(current_url).hostname or "").rstrip(".").casefold()
            if normalized_allowed and request_host not in normalized_allowed:
                raise NonRetryableFetchError(
                    f"request target is outside the allowed hosts: {request_host}"
                )
            try:
                validate_public_http_url(
                    current_url,
                    resolver=self._resolver,
                    allow_rfc2544_proxy_fake_ip=bool(normalized_allowed),
                )
            except FetchError as exc:
                raise NonRetryableFetchError(str(exc)) from exc
            self._wait_for_slot(current_url)
            try:
                validate_public_http_url(
                    current_url,
                    resolver=self._resolver,
                    allow_rfc2544_proxy_fake_ip=bool(normalized_allowed),
                )
            except FetchError as exc:
                raise NonRetryableFetchError(str(exc)) from exc
            with self._client.stream(
                "GET",
                current_url,
                params=current_params,
                headers=headers,
                follow_redirects=False,
                timeout=httpx.Timeout(self._request_timeout_seconds()),
            ) as response:
                if response.status_code not in {301, 302, 303, 307, 308}:
                    yield response
                    return
                self._read_response_body(
                    response,
                    max_bytes=max_bytes,
                    capture_bytes=0,
                )
                location = response.headers.get("Location")
                if not location:
                    raise NonRetryableFetchError(
                        f"HTTP {response.status_code} redirect has no Location header"
                    )
                if redirect_count >= 5:
                    raise NonRetryableFetchError("redirect limit exceeded")
                next_url = urljoin(str(response.url), location)
                next_host = (urlsplit(next_url).hostname or "").rstrip(".").casefold()
                if normalized_allowed and next_host not in normalized_allowed:
                    raise NonRetryableFetchError(
                        f"redirect target is outside the allowed hosts: {next_host}"
                    )
                try:
                    validate_public_http_url(
                        next_url,
                        resolver=self._resolver,
                        allow_rfc2544_proxy_fake_ip=bool(normalized_allowed),
                    )
                except FetchError as exc:
                    raise NonRetryableFetchError(str(exc)) from exc
                if (
                    urlsplit(current_url).scheme == "https"
                    and urlsplit(next_url).scheme != "https"
                ):
                    raise NonRetryableFetchError(
                        "HTTPS redirect downgrade is not allowed"
                    )
                current_url = next_url
                current_params = None
        raise NonRetryableFetchError("redirect limit exceeded")

    def request_bytes(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        max_bytes: int,
        raw_suffix: str,
        allowed_hosts: set[str] | None = None,
    ) -> tuple[bytes, RawReceipt, httpx.Headers]:
        if self._circuit_open:
            raise CircuitOpenError(f"{self.source} circuit is open")
        if self._retry_deferred_seconds is not None:
            raise RetryDeferredError(
                f"{self.source} remains deferred for this invocation",
                self._retry_deferred_seconds,
            )
        safe_headers = dict(headers or {})
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            started = self._monotonic()
            try:
                with self._stream_get(
                    url,
                    params=params,
                    headers=safe_headers,
                    allowed_hosts=allowed_hosts,
                    max_bytes=max_bytes,
                ) as response:
                    rate_limited = response.status_code in {401, 403, 429}
                    server_error = 500 <= response.status_code < 600
                    if rate_limited or server_error:
                        error_body_limit = min(max_bytes, 1024 * 1024)
                        body, observed_error_bytes = self._read_response_body(
                            response,
                            max_bytes=max_bytes,
                            capture_bytes=error_body_limit,
                        )
                        retry_after = _retry_after_seconds(
                            response.headers.get("Retry-After"), time.time()
                        )
                        if retry_after is None and rate_limited:
                            reset = response.headers.get("X-RateLimit-Reset")
                            try:
                                if reset and self.source == "openalex":
                                    retry_after = max(0.0, float(reset))
                                else:
                                    retry_after = (
                                        max(0.0, float(reset) - time.time())
                                        if reset
                                        else None
                                    )
                            except ValueError:
                                retry_after = None
                        if retry_after is not None:
                            wait = retry_after
                        elif response.status_code == 401:
                            wait = 3600.0
                        elif response.status_code == 403:
                            wait = 60.0
                        else:
                            wait = min(60.0, 2 ** (attempt - 1))
                        digest, raw_path = self.raw_store.save(
                            self.source, body, "rate-limit" if rate_limited else "retry"
                        )
                        self.audit.write(
                            "http_retry",
                            component="http",
                            run_id=self.run_id,
                            severity="warning",
                            details={
                                "source": self.source,
                                "url": redact_url(str(response.url)),
                                "status_code": response.status_code,
                                "attempt": attempt,
                                "wait_seconds": wait,
                                "response_bytes": observed_error_bytes,
                                "captured_response_bytes": len(body),
                                "response_sha256": digest,
                                "response_path": str(raw_path),
                            },
                        )
                        if wait > self.max_inline_retry_seconds:
                            self._retry_deferred_seconds = wait
                            self.audit.write(
                                "http_retry_deferred",
                                component="http",
                                run_id=self.run_id,
                                severity="warning",
                                details={
                                    "source": self.source,
                                    "url": redact_url(str(response.url)),
                                    "status_code": response.status_code,
                                    "retry_after_seconds": wait,
                                },
                            )
                            raise RetryDeferredError(
                                f"HTTP {response.status_code} deferred for {wait:.1f} seconds",
                                wait,
                            )
                        if attempt < self.max_attempts:
                            self._sleep_for_retry(wait)
                            continue
                        raise FetchError(f"HTTP {response.status_code} after {attempt} attempts")
                    if not 200 <= response.status_code < 300:
                        body, observed_terminal_bytes = self._read_response_body(
                            response,
                            max_bytes=max_bytes,
                            capture_bytes=min(max_bytes, 1024 * 1024),
                        )
                        digest, raw_path = self.raw_store.save(
                            self.source,
                            body,
                            "terminal",
                        )
                        self.audit.write(
                            "http_terminal_status",
                            component="http",
                            run_id=self.run_id,
                            severity="warning",
                            details={
                                "source": self.source,
                                "url": redact_url(str(response.url)),
                                "status_code": response.status_code,
                                "attempt": attempt,
                                "response_bytes": observed_terminal_bytes,
                                "captured_response_bytes": len(body),
                                "response_sha256": digest,
                                "response_path": str(raw_path),
                            },
                        )
                        raise NonRetryableFetchError(
                            f"HTTP {response.status_code} is not a successful response"
                        )
                    declared = response.headers.get("Content-Length")
                    if declared:
                        try:
                            if int(declared) > max_bytes:
                                raise ResponseTooLargeError(
                                    f"declared response length exceeds {max_bytes} bytes"
                                )
                        except ValueError:
                            pass
                    body, total = self._read_response_body(
                        response,
                        max_bytes=max_bytes,
                    )
                    digest, raw_path = self.raw_store.save(self.source, body, raw_suffix)
                    receipt = RawReceipt(
                        sha256=digest,
                        path=str(raw_path),
                        byte_count=len(body),
                        status_code=response.status_code,
                        final_url=str(response.url),
                        fetched_at=utc_now(),
                    )
                    self._consecutive_failures = 0
                    self.audit.write(
                        "http_success",
                        component="http",
                        run_id=self.run_id,
                        details={
                            "source": self.source,
                            "url": redact_url(str(response.url)),
                            "status_code": response.status_code,
                            "attempt": attempt,
                            "elapsed_seconds": round(self._monotonic() - started, 3),
                            "byte_count": len(body),
                            "sha256": digest,
                        },
                    )
                    return body, receipt, response.headers
            except (RetryDeferredError, ResponseTooLargeError, NonRetryableFetchError):
                raise
            except (httpx.HTTPError, OSError, FetchError, socket.error) as exc:
                last_error = exc
                self._consecutive_failures += 1
                self.audit.write(
                    "http_error",
                    component="http",
                    run_id=self.run_id,
                    severity="error",
                    details={
                        "source": self.source,
                        "url": redact_url(url),
                        "attempt": attempt,
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:500],
                    },
                )
                if self._consecutive_failures >= self.circuit_failure_threshold:
                    self._circuit_open = True
                    raise CircuitOpenError(
                        f"{self.source} circuit opened after consecutive failures"
                    ) from exc
                if attempt < self.max_attempts:
                    self._sleep_for_retry(min(60.0, 2 ** (attempt - 1)))
                    continue
                break
        raise FetchError(f"{self.source} request failed: {last_error}") from last_error

    def request_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        max_bytes: int = 20 * 1024 * 1024,
        allowed_hosts: set[str] | None = None,
    ) -> tuple[Any, RawReceipt, httpx.Headers]:
        body, receipt, response_headers = self.request_bytes(
            url,
            params=params,
            headers=headers,
            max_bytes=max_bytes,
            raw_suffix="json",
            allowed_hosts=allowed_hosts,
        )
        try:
            return json.loads(body), receipt, response_headers
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FetchError(f"{self.source} returned invalid JSON") from exc
