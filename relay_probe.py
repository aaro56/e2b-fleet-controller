#!/usr/bin/env python3

import hashlib
import hmac
import http.client
import json
import os

ACCESS_KEY = os.environ["RELAY_ACCESS_KEY"].encode()
IDENTITY = os.urandom(16).hex()
EVENT_PATH = "/api/v1/metrics/batch"


def xor(data, sequence, direction):
    result = bytearray(len(data))
    seed = f"{IDENTITY}:{sequence}:{direction}:".encode()
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
            result[offset + index] = data[offset + index] ^ block[index]
        offset += count
        counter += 1
    return bytes(result)


def sign(*parts):
    digest = hmac.new(ACCESS_KEY, digestmod=hashlib.sha256)
    for part in parts:
        digest.update(part)
    return digest.hexdigest()


algorithm = os.environ.get("RELAY_ALGORITHM", "rx/0")
if algorithm == "ghostrider":
    messages = [
        {
            "id": 1,
            "method": "mining.subscribe",
            "params": ["XMRig/6.26.0"],
        },
        {
            "id": 2,
            "method": "mining.authorize",
            "params": [f"{os.environ['ACCOUNT']}.relay-probe", "x"],
        },
    ]
else:
    messages = [
        {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "login",
            "params": {
                "login": f"{os.environ['ACCOUNT']}.relay-probe",
                "pass": "x",
                "agent": "XMRig/6.26.0",
                "algo": [algorithm],
            },
        }
    ]
login = b"".join(
    json.dumps(message, separators=(",", ":")).encode() + b"\n"
    for message in messages
)
encoded = xor(login, 0, "upload")
sequence = b"0"
client = http.client.HTTPConnection(
    f"127.0.0.1:{os.environ.get('LOCAL_RELAY_PORT', '8843')}",
    timeout=15,
)
client.request(
    "POST",
    EVENT_PATH,
    body=encoded,
    headers={
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(encoded)),
        "X-Client-Id": IDENTITY,
        "X-Event-Id": sequence.decode(),
        "X-Signature": sign(EVENT_PATH.encode(), IDENTITY.encode(), sequence, encoded),
    },
)
response = client.getresponse()
body = response.read()
print(f"status={response.status} bytes={len(body)}")
if response.status == 200:
    decoded = xor(body, 0, "download")
    for line in decoded.splitlines():
        message = json.loads(line)
        print(
            f"id={message.get('id')} method={message.get('method')} "
            f"has_result={message.get('result') is not None} "
            f"has_error={bool(message.get('error'))}"
        )
        if message.get("error"):
            print(f"error={str(message['error'])[:160]}")
client.close()
