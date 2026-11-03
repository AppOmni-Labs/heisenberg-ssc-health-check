"""Shared test helpers.

Offline tests must never touch the network: every outbound socket connection is
blocked unless the test is marked ``live``. HTTP calls are served by ``fake_http``.
"""

import io
import json
import re
import socket
import tarfile
from pathlib import Path

import pytest
import requests

FIXTURES = Path(__file__).parent / "fixtures"


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, content=b"", text=None):
        self.status_code = status_code
        self._json = json_data
        self.content = content
        self.text = text if text is not None else (json.dumps(json_data) if json_data is not None else "")

    @property
    def ok(self):
        return 200 <= self.status_code < 400

    def json(self):
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json

    def raise_for_status(self):
        if not self.ok:
            raise requests.HTTPError(f"{self.status_code} error")


class FakeHTTP:
    """Routes ``requests.get`` calls to canned responses by regex on the URL."""

    def __init__(self):
        self.routes = []
        self.calls = []

    def add(self, pattern, response=None, **kwargs):
        self.routes.append((re.compile(pattern), response or FakeResponse(**kwargs)))
        return self

    def get(self, url, *args, **kwargs):
        self.calls.append({"url": url, **kwargs})
        for pattern, response in self.routes:
            if pattern.search(url):
                return response
        raise AssertionError(f"Unexpected HTTP GET in test: {url}")

    def urls(self):
        return [c["url"] for c in self.calls]


@pytest.fixture
def fake_http(monkeypatch):
    fake = FakeHTTP()
    monkeypatch.setattr(requests, "get", fake.get)
    return fake


@pytest.fixture(autouse=True)
def _block_network(request, monkeypatch):
    if request.node.get_closest_marker("live"):
        return

    def guard(*args, **kwargs):
        raise RuntimeError("Network access is blocked in offline tests (mark the test 'live' to allow it)")

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket, "create_connection", guard)


def make_tarball(files: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def tarball():
    return make_tarball


@pytest.fixture
def fixtures_dir():
    return FIXTURES
