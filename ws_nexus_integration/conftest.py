import pytest
import requests


@pytest.fixture(autouse=True)
def disable_network_calls(monkeypatch):
    def disable_requests():
        raise RuntimeError("Network access not allowed during testing!")
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: disable_requests())
    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: disable_requests())
