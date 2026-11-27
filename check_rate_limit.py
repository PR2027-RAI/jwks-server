import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor


def send_request(i):
    try:
        request = urllib.request.Request(
            "http://127.0.0.1:8080/auth",
            data=b"",
            method="POST"
        )

        with urllib.request.urlopen(request) as response:
            return response.status

    except urllib.error.HTTPError as error:
        return error.code


with ThreadPoolExecutor(max_workers=15) as pool:
    results = list(pool.map(send_request, range(15)))

print("Results:", results)
print("Successful requests:", results.count(200))
print("Rejected requests:", results.count(429))
