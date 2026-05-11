#!/usr/bin/env python3
"""Concurrent SOCKS5 validation helper for a live TeamServer SOCKS route."""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import http.server
import select
import socket
import ssl
import statistics
import sys
import threading
import time
import urllib.parse
from collections import Counter
from typing import Iterable


DEFAULT_URL = "http://example.com/"


@dataclasses.dataclass(frozen=True)
class StressConfig:
    proxy_host: str
    proxy_port: int
    url: str
    scheme: str
    target_host: str
    target_port: int
    socks_host: str
    path: str
    host_header: str
    method: str
    requests: int
    concurrency: int
    timeout: float
    expect_statuses: frozenset[int]
    read_limit: int
    progress_every: int
    quiet: bool


@dataclasses.dataclass(frozen=True)
class RequestResult:
    ok: bool
    index: int
    latency_ms: float
    status: int | None = None
    bytes_read: int = 0
    error: str = ""


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if port <= 0 or port > 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _parse_expected_statuses(values: list[str] | None, no_status_check: bool) -> frozenset[int]:
    if no_status_check:
        return frozenset()
    if not values:
        return frozenset({200})

    statuses: set[int] = set()
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                status = int(part)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"invalid HTTP status: {part}") from exc
            if status < 100 or status > 599:
                raise argparse.ArgumentTypeError(f"invalid HTTP status: {status}")
            statuses.add(status)
    return frozenset(statuses)


def _parse_url(url: str) -> tuple[str, str, int, str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise argparse.ArgumentTypeError("url scheme must be http or https")
    if not parsed.hostname:
        raise argparse.ArgumentTypeError("url must include a host")

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.scheme, parsed.hostname, port, path


def _host_header(host: str, port: int, scheme: str) -> str:
    default_port = 443 if scheme == "https" else 80
    if ":" in host and not host.startswith("["):
        host_text = f"[{host}]"
    else:
        host_text = host
    if port == default_port:
        return host_text
    return f"{host_text}:{port}"


def _recv_exact(sock: socket.socket, size: int, context: str = "") -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            suffix = f" while reading {context}" if context else ""
            raise RuntimeError(f"unexpected EOF{suffix}")
        data.extend(chunk)
    return bytes(data)


def _resolve_ipv4(host: str, port: int) -> str:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass

    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise RuntimeError(f"could not resolve IPv4 address for {host}")
    return str(infos[0][4][0])


def _socks_address(host: str) -> bytes:
    try:
        return b"\x01" + socket.inet_pton(socket.AF_INET, host)
    except OSError:
        pass

    try:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass

    encoded = host.encode("idna")
    if len(encoded) > 255:
        raise RuntimeError("target host is too long for SOCKS5 domain encoding")
    return b"\x03" + bytes([len(encoded)]) + encoded


def _read_socks_reply(sock: socket.socket) -> None:
    header = _recv_exact(sock, 4, "SOCKS CONNECT reply header")
    if header[0] != 5:
        raise RuntimeError(f"invalid SOCKS version in reply: {header[0]}")
    reply_code = header[1]
    atyp = header[3]

    if atyp == 1:
        _recv_exact(sock, 4, "SOCKS IPv4 bind address")
    elif atyp == 3:
        length = _recv_exact(sock, 1, "SOCKS domain length")[0]
        _recv_exact(sock, length, "SOCKS domain bind address")
    elif atyp == 4:
        _recv_exact(sock, 16, "SOCKS IPv6 bind address")
    else:
        raise RuntimeError(f"invalid SOCKS address type in reply: {atyp}")
    _recv_exact(sock, 2, "SOCKS bind port")

    if reply_code != 0:
        raise RuntimeError(f"SOCKS CONNECT failed with reply 0x{reply_code:02x}")


def _connect_via_socks(config: StressConfig) -> socket.socket:
    sock = socket.create_connection((config.proxy_host, config.proxy_port), timeout=config.timeout)
    sock.settimeout(config.timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        greeting = _recv_exact(sock, 2, "SOCKS method selection")
        if greeting != b"\x05\x00":
            raise RuntimeError(f"SOCKS no-auth negotiation failed: {greeting.hex()}")

        request = (
            b"\x05\x01\x00"
            + _socks_address(config.socks_host)
            + config.target_port.to_bytes(2, byteorder="big")
        )
        sock.sendall(request)
        _read_socks_reply(sock)

        if config.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=config.target_host)
            sock.settimeout(config.timeout)
        return sock
    except Exception:
        sock.close()
        raise


def _build_http_request(config: StressConfig) -> bytes:
    lines = [
        f"{config.method} {config.path} HTTP/1.1",
        f"Host: {config.host_header}",
        "User-Agent: c2-socks-stress/1.0",
        "Accept: */*",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


def _read_http_response(sock: socket.socket, read_limit: int) -> bytes:
    response = bytearray()
    while len(response) < read_limit:
        chunk = sock.recv(min(8192, read_limit - len(response)))
        if not chunk:
            break
        response.extend(chunk)
        if b"\r\n\r\n" in response:
            break
    return bytes(response)


def _status_from_response(response: bytes) -> int | None:
    first_line = response.split(b"\r\n", 1)[0]
    parts = first_line.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def run_one(index: int, config: StressConfig) -> RequestResult:
    started = time.monotonic()
    sock: socket.socket | None = None
    try:
        sock = _connect_via_socks(config)
        sock.sendall(_build_http_request(config))
        response = _read_http_response(sock, config.read_limit)
        status = _status_from_response(response)
        if status is None:
            raise RuntimeError("HTTP response status could not be parsed")
        if config.expect_statuses and status not in config.expect_statuses:
            expected = ",".join(str(value) for value in sorted(config.expect_statuses))
            raise RuntimeError(f"unexpected HTTP status {status}, expected {expected}")

        elapsed_ms = (time.monotonic() - started) * 1000.0
        return RequestResult(True, index, elapsed_ms, status=status, bytes_read=len(response))
    except Exception as exc:
        elapsed_ms = (time.monotonic() - started) * 1000.0
        return RequestResult(False, index, elapsed_ms, error=str(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _summarize(results: list[RequestResult], elapsed_s: float) -> bool:
    successes = [result for result in results if result.ok]
    failures = [result for result in results if not result.ok]
    latencies = [result.latency_ms for result in successes]
    status_counts = Counter(result.status for result in successes)
    error_counts = Counter(result.error for result in failures)

    print("\nSOCKS5 stress summary")
    print(f"  total:      {len(results)}")
    print(f"  passed:     {len(successes)}")
    print(f"  failed:     {len(failures)}")
    print(f"  elapsed:    {elapsed_s:.2f}s")
    if elapsed_s > 0:
        print(f"  throughput: {len(results) / elapsed_s:.2f} req/s")
    if status_counts:
        statuses = ", ".join(f"{status}:{count}" for status, count in sorted(status_counts.items()))
        print(f"  statuses:   {statuses}")
    if latencies:
        print(
            "  latency:    "
            f"min={min(latencies):.1f}ms "
            f"p50={statistics.median(latencies):.1f}ms "
            f"p95={_percentile(latencies, 0.95):.1f}ms "
            f"p99={_percentile(latencies, 0.99):.1f}ms "
            f"max={max(latencies):.1f}ms"
        )
    if error_counts:
        print("  errors:")
        for error, count in error_counts.most_common(10):
            print(f"    {count}x {error}")

    return not failures


def run_stress(config: StressConfig) -> bool:
    if not config.quiet:
        expected = "any" if not config.expect_statuses else ",".join(str(v) for v in sorted(config.expect_statuses))
        print(
            "SOCKS5 stress: "
            f"proxy={config.proxy_host}:{config.proxy_port} "
            f"url={config.url} "
            f"socks_target={config.socks_host}:{config.target_port} "
            f"requests={config.requests} "
            f"concurrency={config.concurrency} "
            f"method={config.method} "
            f"expect={expected}"
        )

    started = time.monotonic()
    results: list[RequestResult] = []
    completed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=config.concurrency) as executor:
        futures = [executor.submit(run_one, index, config) for index in range(config.requests)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1
            if (
                not config.quiet
                and config.progress_every > 0
                and (completed % config.progress_every == 0 or completed == config.requests)
            ):
                failures = sum(1 for item in results if not item.ok)
                print(f"  progress: {completed}/{config.requests}, failures={failures}")

    elapsed_s = time.monotonic() - started
    return _summarize(results, elapsed_s)


class _SelfTestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib hook name
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        body = b"c2-socks-self-test\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _MiniSocksProxy:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(128)
        self._server.settimeout(0.2)
        self.port = int(self._server.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._handlers: list[threading.Thread] = []

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._server.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)
        for handler in self._handlers:
            handler.join(timeout=0.2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            handler = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
            self._handlers.append(handler)
            handler.start()

    def _handle_client(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            client.settimeout(5.0)
            greeting = _recv_exact(client, 2)
            if greeting[0] != 5:
                return
            methods = _recv_exact(client, greeting[1])
            if 0 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")

            header = _recv_exact(client, 4)
            if header[:3] != b"\x05\x01\x00":
                return
            host = self._read_request_host(client, header[3])
            port = int.from_bytes(_recv_exact(client, 2), byteorder="big")
            upstream = socket.create_connection((host, port), timeout=5.0)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            self._pipe(client, upstream)
        except OSError:
            return
        finally:
            try:
                client.close()
            except OSError:
                pass
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass

    @staticmethod
    def _read_request_host(client: socket.socket, atyp: int) -> str:
        if atyp == 1:
            return socket.inet_ntop(socket.AF_INET, _recv_exact(client, 4))
        if atyp == 3:
            length = _recv_exact(client, 1)[0]
            return _recv_exact(client, length).decode("idna")
        if atyp == 4:
            return socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
        raise OSError(f"unsupported address type {atyp}")

    def _pipe(self, client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        for sock in sockets:
            sock.setblocking(False)
        while not self._stop.is_set():
            readable, _, exceptional = select.select(sockets, [], sockets, 0.2)
            if exceptional:
                return
            for source in readable:
                try:
                    data = source.recv(65536)
                except BlockingIOError:
                    continue
                if not data:
                    return
                target = upstream if source is client else client
                target.sendall(data)


def run_self_test() -> int:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SelfTestHandler)
    http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    proxy = _MiniSocksProxy()

    try:
        http_thread.start()
        proxy.start()
        http_port = int(httpd.server_address[1])
        config = StressConfig(
            proxy_host="127.0.0.1",
            proxy_port=proxy.port,
            url=f"http://127.0.0.1:{http_port}/",
            scheme="http",
            target_host="127.0.0.1",
            target_port=http_port,
            socks_host="127.0.0.1",
            path="/",
            host_header=f"127.0.0.1:{http_port}",
            method="HEAD",
            requests=24,
            concurrency=6,
            timeout=3.0,
            expect_statuses=frozenset({200}),
            read_limit=8192,
            progress_every=12,
            quiet=False,
        )
        if not run_stress(config):
            return 1
        hostname_config = dataclasses.replace(
            config,
            url=f"http://localhost:{http_port}/",
            target_host="localhost",
            socks_host="localhost",
            host_header=f"localhost:{http_port}",
        )
        if not run_stress(hostname_config):
            return 1
        print("self-test passed")
        return 0
    finally:
        proxy.stop()
        httpd.shutdown()
        httpd.server_close()


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Stress-test a SOCKS5 endpoint with concurrent HTTP(S) requests.",
    )
    parser.add_argument("--self-test", action="store_true", help="Run an in-process HTTP+SOCKS self-test.")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="SOCKS5 proxy host.")
    parser.add_argument("--proxy-port", default=1080, type=_port, help="SOCKS5 proxy port.")
    parser.add_argument("--url", default=DEFAULT_URL, help="HTTP(S) URL to request through the proxy.")
    parser.add_argument(
        "--socks-hostname",
        action="store_true",
        help="Send the URL hostname to SOCKS instead of resolving it locally to IPv4. This validates remote hostname resolution from the beacon context.",
    )
    parser.add_argument("--method", choices=("HEAD", "GET"), default="HEAD", help="HTTP method to send.")
    parser.add_argument("--requests", default=100, type=_positive_int, help="Total request count.")
    parser.add_argument("--concurrency", default=10, type=_positive_int, help="Concurrent worker count.")
    parser.add_argument("--timeout", default=8.0, type=_positive_float, help="Per-request timeout in seconds.")
    parser.add_argument(
        "--expect-status",
        action="append",
        help="Expected HTTP status. Can be repeated or comma-separated. Defaults to 200.",
    )
    parser.add_argument("--no-status-check", action="store_true", help="Accept any parseable HTTP status.")
    parser.add_argument("--read-limit", default=65536, type=_positive_int, help="Maximum bytes to read per response.")
    parser.add_argument("--progress-every", default=25, type=int, help="Print progress every N completions; 0 disables.")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output.")
    return parser.parse_args(list(argv))


def config_from_args(args: argparse.Namespace) -> StressConfig:
    scheme, target_host, target_port, path = _parse_url(args.url)
    socks_host = target_host if args.socks_hostname else _resolve_ipv4(target_host, target_port)
    expect_statuses = _parse_expected_statuses(args.expect_status, args.no_status_check)
    return StressConfig(
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        url=args.url,
        scheme=scheme,
        target_host=target_host,
        target_port=target_port,
        socks_host=socks_host,
        path=path,
        host_header=_host_header(target_host, target_port, scheme),
        method=args.method,
        requests=args.requests,
        concurrency=args.concurrency,
        timeout=args.timeout,
        expect_statuses=expect_statuses,
        read_limit=args.read_limit,
        progress_every=max(args.progress_every, 0),
        quiet=args.quiet,
    )


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        return run_self_test()
    config = config_from_args(args)
    return 0 if run_stress(config) else 1


if __name__ == "__main__":
    raise SystemExit(main())
