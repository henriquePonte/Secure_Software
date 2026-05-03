import os
import time

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def wait_for_service(url: str, timeout: int = 30):
    deadline = time.time() + timeout

    cert_path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "web",
            "certs",
            "ca.crt"
        )
    )

    while time.time() < deadline:
        try:
            response = requests.get(url, timeout=2, verify=cert_path)
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
