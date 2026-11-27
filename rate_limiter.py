import time
from collections import defaultdict, deque
from threading import Lock

REQUEST_LIMIT = 10
TIME_WINDOW = 1

request_history = defaultdict(deque)
lock = Lock()


def is_rate_limited(ip_address):
    """Check whether an IP address exceeds the request limit."""
    with lock:
        now = time.monotonic()
        timestamps = request_history[ip_address]

        while timestamps and now - timestamps[0] >= TIME_WINDOW:
            timestamps.popleft()

        if len(timestamps) >= REQUEST_LIMIT:
            return True

        timestamps.append(now)
        return False
