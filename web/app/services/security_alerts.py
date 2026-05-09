from collections import deque
from datetime import datetime
from threading import Lock


_MAX_ALERTS = 50
_SECURITY_ALERTS = deque(maxlen=_MAX_ALERTS)
_SECURITY_ALERTS_LOCK = Lock()


def create_security_alert(category, message, severity="warning", **details):
    alert = {
        "timestamp": datetime.utcnow(),
        "category": category,
        "severity": severity,
        "message": message,
        "details": details,
    }

    with _SECURITY_ALERTS_LOCK:
        _SECURITY_ALERTS.appendleft(alert)

    return alert


def get_recent_security_alerts(limit=10):
    with _SECURITY_ALERTS_LOCK:
        return list(_SECURITY_ALERTS)[:limit]


def clear_security_alerts():
    with _SECURITY_ALERTS_LOCK:
        _SECURITY_ALERTS.clear()
