import os
import time

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def wait_for_service(url: str, timeout: int = 30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = requests.get(url, timeout=2, verify="ca.crt")
            if response.ok:
                return response
        except requests.RequestException:
            pass
        time.sleep(1)
    raise RuntimeError(f"Service not available at {url}")


def test_health_endpoint():
    base_url = os.environ.get("BASE_URL", "https://localhost:8000")
    response = wait_for_service(f"{base_url}/health")
    assert response.json()["status"] == "ok"
