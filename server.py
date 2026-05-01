from __future__ import annotations

import argparse
import hmac
import html
import ipaddress
import json
import os
import queue
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
ASSET_DIR = APP_DIR / "assets"
DB_PATH = DATA_DIR / "dashboard.sqlite3"
DEFAULT_DIR_WORDLIST = APP_DIR / "wordlists" / "directories.txt"
DEFAULT_SUBDOMAIN_WORDLIST = APP_DIR / "wordlists" / "subdomains.txt"
USER_AGENT = "AllowedScopeMapper/1.0 (+authorized-testing-only)"
MAX_WORDS = 2000
DEFAULT_WORKERS = 8
MAX_WORKERS = 16
REQUEST_TIMEOUT = 4
BODY_READ_LIMIT = 65536
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'",
}

scan_lock = threading.Lock()
scans: dict[str, dict[str, Any]] = {}
scan_events: dict[str, "queue.Queue[dict[str, Any]]"] = {}


def now() -> float:
    return round(time.time(), 3)


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def admin_token() -> str:
    return os.environ.get("ASM_ADMIN_TOKEN") or os.environ.get("DRAKESCOPE_ADMIN_TOKEN", "")


def require_allowlist() -> bool:
    return env_bool("DRAKESCOPE_REQUIRE_ALLOWLIST", True)


def allow_private_targets() -> bool:
    return env_bool("DRAKESCOPE_ALLOW_PRIVATE_TARGETS", False)


def is_loopback_host(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value.lower() in {"localhost", "::1"}


def is_local_bind(value: str) -> bool:
    if value in {"", "localhost"}:
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value.lower() == "localhost"
    return address.is_loopback


def init_db() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS allowed_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL DEFAULT '',
                allow_subdomains INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            )
            """
        )
        conn.commit()


def db_rows(sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(sql, args).fetchall()]


def normalize_host(value: str) -> str:
    raw = value.strip().lower()
    if not raw:
        raise ValueError("Target is required.")
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        raw = parsed.hostname or ""
    else:
        raw = raw.split("/", 1)[0]
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            raw = raw.split(":", 1)[0]
    raw = raw.strip(".")
    if not raw:
        raise ValueError("Target host is invalid.")
    if len(raw) > 253:
        raise ValueError("Target host is too long.")
    if any(part == "" for part in raw.split(".")):
        raise ValueError("Target host is invalid.")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        for part in raw.split("."):
            if len(part) > 63 or part.startswith("-") or part.endswith("-"):
                raise ValueError("Target host contains an invalid label.")
        if not all(part.replace("-", "").isalnum() for part in raw.split(".")):
            raise ValueError("Target host contains unsupported characters.")
    return raw


def normalize_url(value: str) -> tuple[str, str]:
    raw = value.strip()
    if not raw:
        raise ValueError("URL is required.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only http and https URLs are supported.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not supported.")
    if parsed.query or parsed.fragment:
        raise ValueError("Target URLs must not include query strings or fragments.")
    host = normalize_host(parsed.hostname)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    base = urllib.parse.urlunparse((parsed.scheme, parsed.netloc.lower(), path.rstrip("/") or "/", "", "", ""))
    return base, host


def allowed_for(host: str) -> dict[str, Any] | None:
    host = normalize_host(host)
    rows = db_rows("SELECT * FROM allowed_targets ORDER BY length(host) DESC")
    for row in rows:
        allowed_host = row["host"]
        if host == allowed_host:
            return row
        if row["allow_subdomains"] and host.endswith("." + allowed_host):
            return row
    return None


def add_allowed_target(host: str, label: str, allow_subdomains: bool) -> dict[str, Any]:
    normalized = normalize_host(host)
    label = label.strip()[:120]
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO allowed_targets (host, label, allow_subdomains, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(host) DO UPDATE SET
                label = excluded.label,
                allow_subdomains = excluded.allow_subdomains
            """,
            (normalized, label, int(allow_subdomains), now()),
        )
        conn.commit()
    return db_rows("SELECT * FROM allowed_targets WHERE host = ?", (normalized,))[0]


def read_wordlist(path: Path, custom_words: list[str] | None = None) -> list[str]:
    words: list[str] = []
    if path.exists():
        words.extend(path.read_text(encoding="utf-8").splitlines())
    if custom_words:
        words.extend(custom_words)
    cleaned: list[str] = []
    seen: set[str] = set()
    for word in words:
        item = word.strip().strip("/")
        if not item or item.startswith("#") or item in seen:
            continue
        seen.add(item)
        cleaned.append(item)
        if len(cleaned) >= MAX_WORDS:
            break
    return cleaned


def parse_threads(value: Any) -> int:
    if value in (None, ""):
        return DEFAULT_WORKERS
    try:
        threads = int(value)
    except (TypeError, ValueError):
        raise ValueError("threads must be a number.")
    if threads < 1:
        raise ValueError("threads must be at least 1.")
    return min(threads, MAX_WORKERS)


def normalize_proxy(value: Any) -> str | None:
    proxy = str(value or "").strip()
    if not proxy:
        return None
    parsed = urllib.parse.urlparse(proxy)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Proxy must be an http or https proxy URL.")
    if parsed.username or parsed.password:
        raise ValueError("Proxy URLs must not include credentials.")
    proxy_host = normalize_host(parsed.hostname)
    ensure_public_target(proxy_host, "Proxy")
    return proxy


def addresses_for_host(host: str) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)]
    except socket.gaierror:
        return []


def address_is_public(address: ipaddress._BaseAddress) -> bool:
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def ensure_public_target(host: str, label: str = "Target") -> None:
    if allow_private_targets():
        return
    try:
        address = ipaddress.ip_address(host)
        addresses = [address]
    except ValueError:
        addresses = addresses_for_host(host)
    if addresses and not all(address_is_public(address) for address in addresses):
        raise ValueError(f"{label} resolves to a private or reserved network. Set DRAKESCOPE_ALLOW_PRIVATE_TARGETS=true for local lab scans.")


def scan_allowed(host: str) -> dict[str, Any] | None:
    row = allowed_for(host)
    if row:
        return row
    if not require_allowlist():
        return {
            "id": 0,
            "host": host,
            "label": "Local unrestricted mode",
            "allow_subdomains": 1,
            "created_at": now(),
        }
    return None


def publish(scan_id: str, event: dict[str, Any]) -> None:
    event = {"ts": now(), **event}
    with scan_lock:
        scan = scans.get(scan_id)
        if scan:
            scan["events"].append(event)
            scan["events"] = scan["events"][-500:]
    if scan_id in scan_events:
        scan_events[scan_id].put(event)


def update_scan(scan_id: str, **updates: Any) -> None:
    with scan_lock:
        if scan_id in scans:
            scans[scan_id].update(updates)


def probe_url(url: str, proxy: str | None = None) -> dict[str, Any]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    started = time.time()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy})) if proxy else None
        response = opener.open(req, timeout=REQUEST_TIMEOUT) if opener else urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT)
        with response as resp:
            body = resp.read(BODY_READ_LIMIT) or b""
            elapsed = int((time.time() - started) * 1000)
            return {
                "url": url,
                "status": resp.status,
                "length": int(resp.headers.get("content-length") or 0),
                "bytes": len(body),
                "elapsed_ms": elapsed,
            }
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(BODY_READ_LIMIT) or b""
        except Exception:
            body = b""
        elapsed = int((time.time() - started) * 1000)
        return {"url": url, "status": exc.code, "length": 0, "bytes": len(body), "elapsed_ms": elapsed}
    except Exception as exc:  # Network scanners need per-probe fault isolation.
        elapsed = int((time.time() - started) * 1000)
        return {"url": url, "status": None, "error": str(exc), "elapsed_ms": elapsed}


def parse_int(value: Any, *, field: str, min_value: int | None = None, max_value: int | None = None) -> int | None:
    if value in (None, ""):
        return None
    try:
        num = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a number.")
    if min_value is not None and num < min_value:
        raise ValueError(f"{field} must be at least {min_value}.")
    if max_value is not None and num > max_value:
        raise ValueError(f"{field} must be at most {max_value}.")
    return num


def parse_status_list(value: Any, *, field: str) -> list[int]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        items = value
    else:
        items = [part.strip() for part in str(value).split(",")]
    out: set[int] = set()
    for item in items:
        if item in (None, ""):
            continue
        try:
            code = int(item)
        except (TypeError, ValueError):
            raise ValueError(f"{field} must contain only status codes.")
        if code < 100 or code > 599:
            raise ValueError(f"{field} contains an invalid status code.")
        out.add(code)
    return sorted(out)


def parse_dir_filters(data: dict[str, Any]) -> dict[str, Any]:
    filters = data.get("filters") if isinstance(data.get("filters"), dict) else {}
    wildcard = filters.get("wildcard")
    return {
        "min_bytes": parse_int(filters.get("min_bytes"), field="min_bytes", min_value=0, max_value=10_000_000),
        "max_bytes": parse_int(filters.get("max_bytes"), field="max_bytes", min_value=0, max_value=10_000_000),
        "max_ms": parse_int(filters.get("max_ms"), field="max_ms", min_value=1, max_value=60_000),
        "status_include": parse_status_list(filters.get("status_include"), field="status_include"),
        "status_exclude": parse_status_list(filters.get("status_exclude"), field="status_exclude"),
        "wildcard": True if wildcard in (None, "") else bool(wildcard),
    }


def dir_result_passes_filters(result: dict[str, Any], filters: dict[str, Any], wildcard_signature: dict[str, Any] | None) -> bool:
    status = result.get("status")
    if status is None:
        return False
    include_list = filters.get("status_include") or []
    exclude_list = filters.get("status_exclude") or []
    include = set(include_list)
    exclude = set(exclude_list)
    if include and status not in include:
        return False
    if status in exclude:
        return False
    if filters.get("wildcard") and wildcard_signature:
        if status == wildcard_signature.get("status") and int(result.get("bytes") or 0) == int(wildcard_signature.get("bytes") or 0):
            return False
    bytes_count = int(result.get("bytes") or 0)
    min_bytes = filters.get("min_bytes")
    max_bytes = filters.get("max_bytes")
    if min_bytes is not None and bytes_count < int(min_bytes):
        return False
    if max_bytes is not None and bytes_count > int(max_bytes):
        return False
    max_ms = filters.get("max_ms")
    if max_ms is not None and int(result.get("elapsed_ms") or 0) > int(max_ms):
        return False
    return True


def run_directory_scan(
    scan_id: str, base_url: str, words: list[str], workers: int, proxy: str | None, filters: dict[str, Any] | None
) -> None:
    filters = filters or {"wildcard": True}
    wildcard_signature: dict[str, Any] | None = None
    if filters.get("wildcard"):
        nonce = f"asm-wildcard-{int(time.time() * 1000)}"
        wild_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", nonce + "/")
        wild = probe_url(wild_url, proxy)
        if wild.get("status") is not None:
            wildcard_signature = {"url": wild_url, "status": wild.get("status"), "bytes": int(wild.get("bytes") or 0)}

    update_scan(
        scan_id,
        status="running",
        started_at=now(),
        total=len(words),
        workers=workers,
        proxy=bool(proxy),
        filters=filters,
        wildcard_signature=wildcard_signature,
    )
    proxy_note = " through proxy" if proxy else ""
    wild_note = " (wildcard filter)" if wildcard_signature else ""
    publish(
        scan_id,
        {
            "type": "status",
            "message": f"Directory scan started with {len(words)} candidates and {workers} threads{proxy_note}{wild_note}.",
        },
    )
    found: list[dict[str, Any]] = []
    checked = 0
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(words)))) as executor:
        futures = {}
        for word in words:
            path = urllib.parse.quote(word.strip("/"))
            url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path + "/")
            futures[executor.submit(probe_url, url, proxy)] = word
        for future in as_completed(futures):
            result = future.result()
            checked += 1
            status = result.get("status")
            if status and status not in {400, 401, 403, 404, 410, 429, 500, 502, 503, 504}:
                if dir_result_passes_filters(result, filters, wildcard_signature):
                    found.append(result)
                    publish(scan_id, {"type": "found", "kind": "directory", "result": result})
            if checked % 10 == 0 or checked == len(words):
                update_scan(scan_id, checked=checked, found=found)
                publish(scan_id, {"type": "progress", "checked": checked, "total": len(words)})
            time.sleep(0.03)
    update_scan(scan_id, status="complete", finished_at=now(), checked=checked, found=found)
    publish(scan_id, {"type": "status", "message": f"Directory scan complete. Found {len(found)} interesting responses."})


def resolve_host(host: str) -> list[str]:
    addresses: set[str] = set()
    try:
        for item in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
            addresses.add(item[4][0])
    except socket.gaierror:
        pass
    return sorted(addresses)


def run_subdomain_scan(scan_id: str, base_host: str, words: list[str], workers: int) -> None:
    update_scan(scan_id, status="running", started_at=now(), total=len(words), workers=workers)
    publish(scan_id, {"type": "status", "message": f"Subdomain scan started with {len(words)} candidates and {workers} threads."})
    found: list[dict[str, Any]] = []
    checked = 0
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(words)))) as executor:
        futures = {}
        for word in words:
            host = f"{word}.{base_host}"
            futures[executor.submit(resolve_host, host)] = host
        for future in as_completed(futures):
            host = futures[future]
            addresses = future.result()
            checked += 1
            if addresses:
                result = {"host": host, "addresses": addresses}
                found.append(result)
                publish(scan_id, {"type": "found", "kind": "subdomain", "result": result})
            if checked % 10 == 0 or checked == len(words):
                update_scan(scan_id, checked=checked, found=found)
                publish(scan_id, {"type": "progress", "checked": checked, "total": len(words)})
    update_scan(scan_id, status="complete", finished_at=now(), checked=checked, found=found)
    publish(scan_id, {"type": "status", "message": f"Subdomain scan complete. Found {len(found)} records."})


class Handler(BaseHTTPRequestHandler):
    server_version = "AllowedScopeMapper/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def send_security_headers(self) -> None:
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        if length > 1024 * 1024:
            raise ValueError("Request body too large.")
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        return json.loads(raw or "{}")

    def send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_security_headers()
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_security_headers()
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def send_asset(self, path: Path, content_type: str) -> None:
        if not path.exists() or not path.is_file():
            self.send_json({"error": "Asset not found."}, 404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("cache-control", "public, max-age=3600")
        self.send_security_headers()
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self.send_html(INDEX_HTML)
            return
        if parsed.path == "/assets/dragon-logo.jpg":
            self.send_asset(ASSET_DIR / "dragon-logo.jpg", "image/jpeg")
            return
        if parsed.path == "/api/targets":
            self.send_json(db_rows("SELECT * FROM allowed_targets ORDER BY host"))
            return
        if parsed.path == "/api/scans":
            with scan_lock:
                summary = [{k: v for k, v in scan.items() if k != "events"} for scan in scans.values()]
            self.send_json(sorted(summary, key=lambda item: item["created_at"], reverse=True))
            return
        if parsed.path.startswith("/api/scans/") and parsed.path.endswith("/events"):
            scan_id = parsed.path.split("/")[3]
            self.stream_events(scan_id)
            return
        if parsed.path.startswith("/api/scans/"):
            scan_id = parsed.path.rsplit("/", 1)[-1]
            with scan_lock:
                scan = scans.get(scan_id)
            if not scan:
                self.send_json({"error": "Scan not found."}, 404)
                return
            self.send_json(scan)
            return
        self.send_json({"error": "Not found."}, 404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path == "/api/targets":
                self.handle_add_target()
                return
            if parsed.path == "/api/check":
                self.handle_check()
                return
            if parsed.path == "/api/scan":
                self.handle_scan()
                return
            self.send_json({"error": "Not found."}, 404)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 400)
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON."}, 400)

    def handle_add_target(self) -> None:
        token = admin_token()
        supplied = self.headers.get("x-admin-token", "")
        if token and not hmac.compare_digest(supplied, token):
            self.send_json({"error": "Admin token required."}, HTTPStatus.UNAUTHORIZED)
            return
        data = self.read_json()
        row = add_allowed_target(
            str(data.get("host", "")),
            str(data.get("label", "")),
            bool(data.get("allow_subdomains", False)),
        )
        self.send_json(row, 201)

    def handle_check(self) -> None:
        data = self.read_json()
        target = str(data.get("target", ""))
        if data.get("mode") == "directory":
            _, host = normalize_url(target)
        else:
            host = normalize_host(target)
        row = scan_allowed(host)
        self.send_json({"allowed": bool(row), "target": host, "matched": row})

    def handle_scan(self) -> None:
        data = self.read_json()
        mode = str(data.get("mode", "directory"))
        custom_words = data.get("words")
        if custom_words is not None and not isinstance(custom_words, list):
            raise ValueError("words must be an array when supplied.")
        dir_filters = parse_dir_filters(data)
        sub_words = data.get("sub_words")
        if sub_words is not None and not isinstance(sub_words, list):
            raise ValueError("sub_words must be an array when supplied.")
        workers = parse_threads(data.get("threads"))
        proxy = normalize_proxy(data.get("proxy"))
        if mode == "directory":
            base_url, host = normalize_url(str(data.get("target", "")))
            ensure_public_target(host)
            matched = scan_allowed(host)
            if not matched:
                self.send_json({"error": f"{host} is not in the authorized testing database."}, 403)
                return
            words = read_wordlist(DEFAULT_DIR_WORDLIST, custom_words)
            scan_id = create_scan("directory", base_url, matched)
            thread = threading.Thread(
                target=run_directory_scan, args=(scan_id, base_url, words, workers, proxy, dir_filters), daemon=True
            )
        elif mode == "subdomain":
            if proxy:
                raise ValueError("Proxy is only supported for directory HTTP probes.")
            host = normalize_host(str(data.get("target", "")))
            ensure_public_target(host)
            matched = scan_allowed(host)
            if not matched or (require_allowlist() and matched["host"] != host):
                self.send_json({"error": f"{host} must be explicitly present in the authorized testing database for subdomain enumeration."}, 403)
                return
            words = read_wordlist(DEFAULT_SUBDOMAIN_WORDLIST, custom_words)
            scan_id = create_scan("subdomain", host, matched)
            thread = threading.Thread(target=run_subdomain_scan, args=(scan_id, host, words, workers), daemon=True)
        elif mode == "both":
            # Parallel mode runs BOTH scans. For safety and clarity, require the base host to be explicitly allowlisted.
            base_url, host = normalize_url(str(data.get("target", "")))
            ensure_public_target(host)
            matched = scan_allowed(host)
            if not matched or (require_allowlist() and matched["host"] != host):
                self.send_json({"error": f"{host} must be explicitly present in the authorized testing database to run parallel scans."}, 403)
                return
            dir_words = read_wordlist(DEFAULT_DIR_WORDLIST, custom_words)
            subdomain_words = read_wordlist(DEFAULT_SUBDOMAIN_WORDLIST, sub_words)

            dir_scan_id = create_scan("directory", base_url, matched)
            sub_scan_id = create_scan("subdomain", host, matched)
            dir_thread = threading.Thread(
                target=run_directory_scan, args=(dir_scan_id, base_url, dir_words, workers, proxy, dir_filters), daemon=True
            )
            sub_thread = threading.Thread(target=run_subdomain_scan, args=(sub_scan_id, host, subdomain_words, workers), daemon=True)
            dir_thread.start()
            sub_thread.start()
            self.send_json({"scan_ids": {"directory": dir_scan_id, "subdomain": sub_scan_id}}, 202)
            return
        else:
            raise ValueError("mode must be directory, subdomain, or both.")
        thread.start()
        self.send_json({"scan_id": scan_id}, 202)

    def stream_events(self, scan_id: str) -> None:
        with scan_lock:
            if scan_id not in scans:
                self.send_json({"error": "Scan not found."}, 404)
                return
        events = scan_events.setdefault(scan_id, queue.Queue())
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-store")
        self.send_header("connection", "keep-alive")
        self.send_security_headers()
        self.end_headers()
        with scan_lock:
            backlog = list(scans[scan_id].get("events", []))
        for event in backlog:
            self.wfile.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
        self.wfile.flush()
        while True:
            try:
                event = events.get(timeout=20)
            except queue.Empty:
                self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
                continue
            self.wfile.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
            self.wfile.flush()
            if event.get("type") == "status" and "complete" in event.get("message", "").lower():
                break


def create_scan(mode: str, target: str, matched: dict[str, Any]) -> str:
    scan_id = str(int(time.time() * 1000))
    with scan_lock:
        scans[scan_id] = {
            "id": scan_id,
            "mode": mode,
            "target": target,
            "matched_target": matched,
            "status": "queued",
            "created_at": now(),
            "started_at": None,
            "finished_at": None,
            "checked": 0,
            "total": 0,
            "found": [],
            "events": [],
        }
        scan_events[scan_id] = queue.Queue()
    return scan_id


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DrakeScope Recon</title>
  <style>
    :root {
      color-scheme: dark;
      --ink: #eafff2;
      --muted: #8bad99;
      --line: rgba(45, 255, 122, .22);
      --panel: rgba(6, 18, 11, .88);
      --panel-strong: rgba(8, 28, 14, .96);
      --soft: rgba(19, 60, 31, .48);
      --accent: #2dff7a;
      --accent-2: #00d967;
      --warn: #ff5d5d;
      --ok: #78ffae;
      --focus: #9affc4;
      --shadow: 0 24px 70px rgba(0, 0, 0, .55);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 12% 8%, rgba(45, 255, 122, .22), transparent 30%),
        radial-gradient(circle at 88% 4%, rgba(0, 217, 103, .15), transparent 28%),
        linear-gradient(145deg, #020403 0%, #071209 42%, #000 100%);
      min-height: 100vh;
      overflow-x: hidden;
      position: relative;
    }
    body::before {
      content: "";
      position: absolute;
      inset: 0;
      pointer-events: none;
      background:
        linear-gradient(rgba(45, 255, 122, .035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(45, 255, 122, .025) 1px, transparent 1px);
      background-size: 42px 42px;
      mask-image: linear-gradient(to bottom, rgba(0,0,0,.8), rgba(0,0,0,.18));
    }
    body::after {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      pointer-events: none;
      background: linear-gradient(180deg, transparent, rgba(45, 255, 122, .08), transparent);
      height: 160px;
      animation: scanline 8s linear infinite;
      opacity: .45;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 26px 32px;
      background:
        linear-gradient(135deg, rgba(5, 18, 9, .98), rgba(10, 50, 22, .9) 48%, rgba(0, 0, 0, .96)),
        linear-gradient(90deg, rgba(45, 255, 122, .22), transparent);
      color: var(--ink);
      border-bottom: 1px solid var(--line);
      box-shadow: 0 18px 50px rgba(0, 0, 0, .42);
      position: relative;
      z-index: 1;
      overflow: hidden;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 18px;
      min-width: 0;
      position: relative;
      z-index: 1;
    }
    .dragon-logo {
      width: 118px;
      height: 118px;
      flex: 0 0 118px;
      border: 1px solid rgba(255, 106, 0, .48);
      border-radius: 18px;
      background:
        radial-gradient(circle at 74% 58%, rgba(255, 106, 0, .55), transparent 24%),
        radial-gradient(circle at 50% 50%, rgba(45, 255, 122, .18), transparent 60%),
        rgba(1, 10, 5, .82);
      box-shadow:
        0 0 34px rgba(45, 255, 122, .2),
        0 0 80px rgba(255, 92, 0, .24),
        inset 0 0 32px rgba(255, 92, 0, .1);
      animation: logoFloat 4.8s ease-in-out infinite;
      overflow: hidden;
      position: relative;
    }
    .dragon-logo::after {
      content: "";
      position: absolute;
      inset: 0;
      background:
        linear-gradient(135deg, rgba(45, 255, 122, .16), transparent 28%),
        radial-gradient(circle at 68% 64%, rgba(255, 100, 0, .28), transparent 34%);
      mix-blend-mode: screen;
      pointer-events: none;
    }
    .dragon-logo img {
      width: 100%;
      height: 100%;
      display: block;
      object-fit: cover;
      filter: contrast(1.12) saturate(1.1);
      transform: scale(1.04);
    }
    .brand-copy {
      display: grid;
      gap: 4px;
      min-width: 0;
    }
    h1, h2 { margin: 0; letter-spacing: 0; }
    h1 {
      font-size: clamp(24px, 3vw, 38px);
      font-weight: 850;
      text-shadow: 0 0 18px rgba(45, 255, 122, .42);
    }
    h2 {
      font-size: 16px;
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: .08em;
    }
    main {
      width: min(1180px, calc(100vw - 28px));
      margin: 22px auto 42px;
      display: grid;
      grid-template-columns: 360px 1fr;
      gap: 16px;
      position: relative;
      z-index: 1;
    }
    section, aside {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      min-width: 0;
      box-shadow: var(--shadow), inset 0 1px 0 rgba(154, 255, 196, .08);
      backdrop-filter: blur(16px);
    }
    section { position: relative; overflow: hidden; }
    section::before {
      content: "";
      position: absolute;
      inset: 0 0 auto 0;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--accent), transparent);
      opacity: .75;
    }
    .stack { display: grid; gap: 14px; }
    .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 12px; font-weight: 750; }
    input, textarea, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px 11px;
      font: inherit;
      color: var(--ink);
      background: rgba(0, 0, 0, .48);
      box-shadow: inset 0 0 0 1px rgba(0, 0, 0, .2);
      transition: border-color .18s ease, box-shadow .18s ease, background .18s ease;
    }
    input::placeholder, textarea::placeholder { color: rgba(234, 255, 242, .42); }
    select { color: var(--ink); }
    option { background: #06120b; color: var(--ink); }
    input:hover, textarea:hover, select:hover {
      border-color: rgba(45, 255, 122, .48);
      background: rgba(4, 16, 8, .74);
    }
    textarea { min-height: 96px; resize: vertical; }
    input:focus, textarea:focus, select:focus, button:focus {
      outline: 2px solid rgba(154, 255, 196, .7);
      outline-offset: 1px;
      box-shadow: 0 0 0 4px rgba(45, 255, 122, .13), 0 0 24px rgba(45, 255, 122, .18);
    }
    button {
      border: 1px solid transparent;
      border-radius: 6px;
      padding: 10px 13px;
      font: inherit;
      font-weight: 850;
      cursor: pointer;
      background: linear-gradient(135deg, var(--accent), var(--accent-2) 55%, #0c7f44);
      color: #001b0b;
      min-height: 38px;
      position: relative;
      overflow: hidden;
      box-shadow: 0 12px 28px rgba(45, 255, 122, .2), inset 0 1px 0 rgba(255, 255, 255, .38);
      transform: translateY(0);
      transition: transform .18s ease, box-shadow .18s ease, filter .18s ease;
      animation: buttonGlow 2.9s ease-in-out infinite;
    }
    button::after {
      content: "";
      position: absolute;
      inset: 0;
      background: linear-gradient(110deg, transparent 0%, rgba(255,255,255,.42) 45%, transparent 62%);
      transform: translateX(-120%);
      transition: transform .45s ease;
    }
    button:hover {
      transform: translateY(-2px);
      filter: saturate(1.15);
      box-shadow: 0 18px 38px rgba(45, 255, 122, .32), 0 0 28px rgba(45, 255, 122, .2);
    }
    button:hover::after { transform: translateX(120%); }
    button:active { transform: translateY(0) scale(.99); }
    button.secondary {
      background: rgba(3, 14, 7, .9);
      color: var(--accent);
      border-color: rgba(45, 255, 122, .48);
      box-shadow: inset 0 0 18px rgba(45, 255, 122, .08), 0 10px 22px rgba(0, 0, 0, .25);
    }
    button:disabled { opacity: .55; cursor: not-allowed; }
    .hint { color: var(--muted); font-size: 12px; }
    .status {
      min-height: 36px;
      padding: 9px 10px;
      border-radius: 6px;
      background: var(--soft);
      border: 1px solid var(--line);
      color: var(--muted);
      overflow-wrap: anywhere;
      box-shadow: inset 0 0 24px rgba(45, 255, 122, .06);
    }
    .allowed { color: var(--ok); }
    .blocked { color: var(--warn); }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 9px 7px; vertical-align: top; }
    th { color: var(--muted); font-size: 12px; }
    .results {
      min-height: 340px;
      max-height: 62vh;
      overflow: auto;
      background:
        linear-gradient(rgba(45, 255, 122, .05) 1px, transparent 1px),
        #020504;
      background-size: 100% 28px;
      color: #c9ffdc;
      border-radius: 8px;
      padding: 12px;
      font: 13px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace;
      border: 1px solid rgba(45, 255, 122, .26);
      box-shadow: inset 0 0 32px rgba(45, 255, 122, .08);
    }
    .results table {
      width: 100%;
      border-collapse: collapse;
      font: 13px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace;
    }
    .results th, .results td {
      padding: 8px 8px;
      border-bottom: 1px solid rgba(45, 255, 122, .18);
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    .results th {
      position: sticky;
      top: 0;
      background: rgba(2, 5, 4, .92);
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: .08em;
      font-size: 11px;
      z-index: 1;
    }
    .results .table-title {
      color: var(--accent);
      font-weight: 900;
      text-transform: uppercase;
      letter-spacing: .08em;
      margin: 6px 0 10px;
      font: 12px/1.2 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .result-line { white-space: pre-wrap; overflow-wrap: anywhere; }
    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 2px 8px;
      background: rgba(45, 255, 122, .12);
      border: 1px solid var(--line);
      color: var(--accent);
      font-size: 12px;
      font-weight: 650;
      box-shadow: 0 0 22px rgba(45, 255, 122, .14);
    }
    .split { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    input[type="checkbox"] { accent-color: var(--accent); }
    input[type="file"]::file-selector-button {
      border: 1px solid rgba(45, 255, 122, .45);
      border-radius: 6px;
      background: rgba(45, 255, 122, .12);
      color: var(--accent);
      padding: 8px 10px;
      margin-right: 10px;
      font-weight: 800;
      cursor: pointer;
    }
    @keyframes buttonGlow {
      0%, 100% { box-shadow: 0 12px 28px rgba(45, 255, 122, .18), inset 0 1px 0 rgba(255, 255, 255, .38); }
      50% { box-shadow: 0 15px 36px rgba(45, 255, 122, .32), inset 0 1px 0 rgba(255, 255, 255, .45); }
    }
    @keyframes scanline {
      0% { transform: translateY(-180px); }
      100% { transform: translateY(calc(100vh + 180px)); }
    }
    @keyframes logoFloat {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-8px); }
    }
    @keyframes fireEyes {
      0%, 100% { opacity: .86; transform: scale(1); }
      50% { opacity: 1; transform: scale(1.18); }
    }
    @keyframes flamePulse {
      0%, 100% { opacity: .76; transform: scale(.96); }
      50% { opacity: 1; transform: scale(1.08); }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
    }
    @media (max-width: 860px) {
      header { align-items: flex-start; flex-direction: column; padding: 22px 18px; }
      .brand { gap: 12px; }
      .dragon-logo { width: 78px; height: 78px; flex-basis: 78px; border-radius: 14px; }
      main { grid-template-columns: 1fr; }
      .split { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="dragon-logo" aria-hidden="true">
        <img src="/assets/dragon-logo.jpg" alt="">
      </div>
      <div class="brand-copy">
        <h1>DrakeScope Recon</h1>
        <div class="hint">Directory and subdomain enumeration for explicitly authorized assets.</div>
      </div>
    </div>
    <span class="pill" id="targetCount">0 allowed targets</span>
  </header>
  <main>
    <aside class="stack">
      <section class="stack">
        <h2>Allowed Targets</h2>
        <label>Admin token
          <input id="adminToken" type="password" autocomplete="off" placeholder="Optional unless ASM_ADMIN_TOKEN is set">
        </label>
        <label>Host
          <input id="allowHost" placeholder="example.com">
        </label>
        <label>Label
          <input id="allowLabel" placeholder="Client staging">
        </label>
        <label class="row" style="display:flex; font-size:13px; color:var(--ink);">
          <input id="allowSubs" type="checkbox" style="width:auto;"> Include subdomains for directory scans
        </label>
        <button id="addTarget">Add or update target</button>
        <div id="allowStatus" class="status">Only hosts in this database can be scanned.</div>
        <table>
          <thead><tr><th>Host</th><th>Subdomains</th></tr></thead>
          <tbody id="targets"></tbody>
        </table>
      </section>
    </aside>
    <section class="stack">
      <h2>Scanner</h2>
      <div class="split">
        <label>Mode
          <select id="mode">
            <option value="directory">Hidden directories</option>
            <option value="subdomain">Subdomains</option>
            <option value="both">Both (parallel)</option>
          </select>
        </label>
        <label>Target
          <input id="scanTarget" placeholder="https://example.com or example.com">
        </label>
      </div>
      <div class="split">
        <label>Threads
          <input id="threads" type="number" min="1" max="16" value="8">
        </label>
        <label>Proxy
          <input id="proxy" placeholder="http://127.0.0.1:8080">
        </label>
      </div>
      <label><span id="wordFileLabel">Directory list file</span>
        <input id="wordFile" type="file" accept=".txt,.lst,.list,text/plain">
      </label>
      <label id="subWordFileWrap"><span id="subWordFileLabel">Subdomain list file</span>
        <input id="subWordFile" type="file" accept=".txt,.lst,.list,text/plain">
      </label>
      <label>Extra words
        <textarea id="words" placeholder="Optional newline-separated candidates"></textarea>
      </label>
      <label id="subWordsWrap">Extra subdomain words
        <textarea id="subWords" placeholder="Optional newline-separated candidates"></textarea>
      </label>
      <div id="dirFilters" class="stack">
        <div class="split">
          <label>Min bytes
            <input id="minBytes" type="number" min="0" placeholder="0">
          </label>
          <label>Max bytes
            <input id="maxBytes" type="number" min="0" placeholder="(none)">
          </label>
        </div>
        <div class="split">
          <label>Max ms
            <input id="maxMs" type="number" min="1" placeholder="(none)">
          </label>
          <label>Include status
            <input id="statusInclude" placeholder="200,204,301">
          </label>
        </div>
        <div class="split">
          <label>Exclude status
            <input id="statusExclude" placeholder="403,404,429">
          </label>
          <label class="row" style="display:flex; font-size:13px; color:var(--ink);">
            <input id="wildcard" type="checkbox" style="width:auto;" checked> Wildcard filter
          </label>
        </div>
      </div>
      <div class="row">
        <button id="checkTarget" class="secondary">Check authorization</button>
        <button id="startScan">Start scan</button>
        <button id="clearResults" class="secondary">Clear</button>
      </div>
      <div id="scanStatus" class="status">Ready.</div>
      <div id="results" class="results" aria-live="polite"></div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const results = $("results");

    function line(text, cls = "") {
      const div = document.createElement("div");
      div.className = "result-line " + cls;
      div.textContent = text;
      results.appendChild(div);
      results.scrollTop = results.scrollHeight;
    }

    async function api(path, options = {}) {
      const res = await fetch(path, {
        ...options,
        headers: {"content-type": "application/json", ...(options.headers || {})}
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Request failed");
      return data;
    }

    async function refreshTargets() {
      const rows = await api("/api/targets");
      $("targetCount").textContent = `${rows.length} allowed target${rows.length === 1 ? "" : "s"}`;
      $("targets").innerHTML = rows.map(row => `
        <tr>
          <td>${escapeHtml(row.host)}<div class="hint">${escapeHtml(row.label || "")}</div></td>
          <td>${row.allow_subdomains ? "Yes" : "No"}</td>
        </tr>
      `).join("");
    }

    function escapeHtml(value) {
      return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      }[char]));
    }

    async function customWords() {
      const typed = $("words").value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
      const file = $("wordFile").files[0];
      if (!file) return typed;
      if (file.size > 1024 * 1024) throw new Error("Wordlist file must be 1 MB or smaller.");
      const text = await file.text();
      const fromFile = text.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
      return [...fromFile, ...typed];
    }

    async function customSubWords() {
      const typed = $("subWords").value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
      const file = $("subWordFile").files[0];
      if (!file) return typed;
      if (file.size > 1024 * 1024) throw new Error("Wordlist file must be 1 MB or smaller.");
      const text = await file.text();
      const fromFile = text.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
      return [...fromFile, ...typed];
    }

    function parseStatusCodes(text) {
      const raw = String(text || "").trim();
      if (!raw) return [];
      return raw.split(",").map(x => x.trim()).filter(Boolean).map(x => Number(x)).filter(x => Number.isFinite(x));
    }

    function collectDirFilters() {
      return {
        min_bytes: $("minBytes").value,
        max_bytes: $("maxBytes").value,
        max_ms: $("maxMs").value,
        status_include: parseStatusCodes($("statusInclude").value),
        status_exclude: parseStatusCodes($("statusExclude").value),
        wildcard: $("wildcard").checked
      };
    }

    function syncModeOptions() {
      const mode = $("mode").value;
      const subdomainMode = mode === "subdomain";
      const bothMode = mode === "both";

      $("proxy").disabled = subdomainMode;
      if (subdomainMode) $("proxy").value = "";

      $("wordFileLabel").textContent = "Directory list file";
      $("subWordFileWrap").style.display = (subdomainMode || bothMode) ? "grid" : "none";
      $("subWordsWrap").style.display = (subdomainMode || bothMode) ? "grid" : "none";
      $("dirFilters").style.display = (subdomainMode ? "none" : "grid");
    }

    $("addTarget").onclick = async () => {
      try {
        const row = await api("/api/targets", {
          method: "POST",
          headers: {"x-admin-token": $("adminToken").value},
          body: JSON.stringify({
            host: $("allowHost").value,
            label: $("allowLabel").value,
            allow_subdomains: $("allowSubs").checked
          })
        });
        $("allowStatus").innerHTML = `<span class="allowed">Authorized:</span> ${escapeHtml(row.host)}`;
        await refreshTargets();
      } catch (err) {
        $("allowStatus").innerHTML = `<span class="blocked">Blocked:</span> ${escapeHtml(err.message)}`;
      }
    };

    $("checkTarget").onclick = async () => {
      try {
        const data = await api("/api/check", {
          method: "POST",
          body: JSON.stringify({mode: $("mode").value, target: $("scanTarget").value})
        });
        $("scanStatus").innerHTML = data.allowed
          ? `<span class="allowed">Allowed:</span> matched ${escapeHtml(data.matched.host)}`
          : `<span class="blocked">Blocked:</span> target is not authorized`;
      } catch (err) {
        $("scanStatus").innerHTML = `<span class="blocked">Error:</span> ${escapeHtml(err.message)}`;
      }
    };

    $("mode").onchange = syncModeOptions;

    $("startScan").onclick = async () => {
      results.innerHTML = "";
      $("startScan").disabled = true;
      try {
        const words = await customWords();
        const sub_words = await customSubWords();
        const data = await api("/api/scan", {
          method: "POST",
          body: JSON.stringify({
            mode: $("mode").value,
            target: $("scanTarget").value,
            words,
            sub_words,
            threads: $("threads").value,
            proxy: $("proxy").value,
            filters: collectDirFilters()
          })
        });
        startStreaming(data);
      } catch (err) {
        $("scanStatus").innerHTML = `<span class="blocked">Blocked:</span> ${escapeHtml(err.message)}`;
        $("startScan").disabled = false;
      }
    };

    $("clearResults").onclick = () => {
      results.innerHTML = "";
      $("scanStatus").textContent = "Ready.";
    };

    async function renderFinalTables(scanIds) {
      const entries = Object.entries(scanIds);
      const scans = await Promise.all(entries.map(([kind, id]) => api(`/api/scans/${id}`)));
      results.innerHTML = "";

      for (let i = 0; i < scans.length; i++) {
        const kind = entries[i][0];
        const scan = scans[i];
        const effectiveKind = (kind === "single") ? (scan.mode === "subdomain" ? "subdomain" : "directory") : kind;
        const title = document.createElement("div");
        title.className = "table-title";
        title.textContent = effectiveKind === "subdomain" ? "Subdomain Findings" : "Directory Findings";
        results.appendChild(title);

        const table = document.createElement("table");
        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        const headers = effectiveKind === "subdomain"
          ? ["Host", "Addresses"]
          : ["URL", "Status", "Bytes", "Ms"];
        for (const h of headers) {
          const th = document.createElement("th");
          th.textContent = h;
          headRow.appendChild(th);
        }
        thead.appendChild(headRow);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        const found = Array.isArray(scan.found) ? scan.found : [];
        if (found.length === 0) {
          const tr = document.createElement("tr");
          const td = document.createElement("td");
          td.colSpan = headers.length;
          td.textContent = "No findings.";
          tr.appendChild(td);
          tbody.appendChild(tr);
        } else {
          for (const row of found) {
            const tr = document.createElement("tr");
            if (effectiveKind === "subdomain") {
              const hostTd = document.createElement("td");
              hostTd.textContent = row.host || "";
              const addrTd = document.createElement("td");
              addrTd.textContent = Array.isArray(row.addresses) ? row.addresses.join(", ") : "";
              tr.appendChild(hostTd);
              tr.appendChild(addrTd);
            } else {
              const urlTd = document.createElement("td");
              urlTd.textContent = row.url || "";
              const statusTd = document.createElement("td");
              statusTd.textContent = String(row.status ?? "");
              const bytesTd = document.createElement("td");
              bytesTd.textContent = String(row.bytes ?? "");
              const msTd = document.createElement("td");
              msTd.textContent = String(row.elapsed_ms ?? "");
              tr.appendChild(urlTd);
              tr.appendChild(statusTd);
              tr.appendChild(bytesTd);
              tr.appendChild(msTd);
            }
            tbody.appendChild(tr);
          }
        }
        table.appendChild(tbody);
        results.appendChild(table);
      }
    }

    function startStreaming(data) {
      const streams = [];
      const scanIds = data.scan_ids ? data.scan_ids : {single: data.scan_id};
      const active = new Set(Object.values(scanIds));
      const labelFor = (kind) => kind === "directory" ? "[DIR]" : (kind === "subdomain" ? "[SUB]" : "[SCAN]");

      for (const [kind, scanId] of Object.entries(scanIds)) {
        if (!scanId) continue;
        line(`${labelFor(kind)} scan=${scanId}`);
        const es = new EventSource(`/api/scans/${scanId}/events`);
        streams.push(es);
        es.onmessage = (event) => {
          const item = JSON.parse(event.data);
          if (item.type === "found") {
            line(`${labelFor(kind)} ${JSON.stringify(item.result)}`, "allowed");
          } else if (item.type === "progress") {
            $("scanStatus").textContent = `${labelFor(kind)} Checked ${item.checked}/${item.total}`;
          } else if (item.type === "status") {
            line(`${labelFor(kind)} ${item.message}`);
            if (item.message.toLowerCase().includes("complete")) {
              active.delete(scanId);
              es.close();
              if (active.size === 0) {
                $("scanStatus").textContent = "All scans complete.";
                $("startScan").disabled = false;
                const normalizedIds = data.scan_ids ? data.scan_ids : {single: data.scan_id};
                renderFinalTables(normalizedIds).catch(() => {});
              }
            }
          }
        };
        es.onerror = () => {
          active.delete(scanId);
          es.close();
          if (active.size === 0) $("startScan").disabled = false;
        };
      }
      if (active.size === 0) $("startScan").disabled = false;
      $("scanStatus").textContent = active.size > 1 ? "Parallel scans started." : `Scan started.`;
    }

    syncModeOptions();
    refreshTargets().catch(err => $("allowStatus").textContent = err.message);
  </script>
</body>
</html>
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authorized web directory and subdomain mapper.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host.")
    parser.add_argument("--port", default=8000, type=int, help="Bind port.")
    parser.add_argument("--allow", action="append", default=[], help="Seed an allowed host. Repeatable.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    token = admin_token()
    local_bind = is_local_bind(args.host)
    if not local_bind and not token:
        raise SystemExit("Refusing public bind without ASM_ADMIN_TOKEN or DRAKESCOPE_ADMIN_TOKEN.")
    if not local_bind and len(token) < 16:
        raise SystemExit("Admin token must be at least 16 characters for public binds.")
    if not require_allowlist() and not local_bind:
        raise SystemExit("DRAKESCOPE_REQUIRE_ALLOWLIST=false is only allowed on localhost/loopback binds.")
    init_db()
    for host in args.allow:
        add_allowed_target(host, f"Seeded {html.escape(host)}", True)
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"DrakeScope Recon running at http://{args.host}:{args.port}")
    print("Allowlist required:", require_allowlist())
    print("Private targets allowed:", allow_private_targets())
    print("Set ASM_ADMIN_TOKEN or DRAKESCOPE_ADMIN_TOKEN to protect allowlist changes.")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
