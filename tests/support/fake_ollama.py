#!/usr/bin/env python3
"""A scriptable, in-process fake Ollama server for testing detector/scan.py
(Python standard library only — http.server + threading, no third-party deps).

The detector talks to Ollama over HTTP: it POSTs to `{OLLAMA_URL}/api/chat` and
reads back the envelope `{"message": {"content": "<json string>"}}` (see
scan.py:call_model). This fake stands in for that server so tests can drive the
WHOLE detector end-to-end — the transport path, retries, and both fail-safe
branches — without a real model, network, or GPU.

Usage:
    from fake_ollama import FakeOllama

    with FakeOllama() as fake:
        fake.respond([{"risk_score": 85}])          # scripted result(s)
        env = {"OLLAMA_URL": fake.url, ...}
        # ... run scan.py as a subprocess with that env ...
        assert fake.requests                        # inspect what was sent

Modes (each call re-arms the server; the last set mode wins):
    respond(list_of_dicts) - return these results in order, one per call;
                             fewer entries than calls repeats the last one.
    garbage()              - return non-JSON text            -> ContentError
    http_error(code=500)   - return an HTTP error status     -> InfraError
    hang(seconds)          - sleep past REQUEST_TIMEOUT       -> InfraError
    echo()                 - record the request, reply benign (assert what was sent)

`.requests` holds the parsed request body (a dict) of every POST received, so a
test can assert WHICH files reached the model via req["messages"][-1]["content"].
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Benign, schema-shaped result: a clean pass the detector parses without error.
# respond() fills any missing keys from this so callers can pass just a score.
BENIGN_RESULT = {
    "key_changes": [],
    "suspicious_findings": [],
    "reasoning": "benign",
    "risk_score": 0,
}


class _Handler(BaseHTTPRequestHandler):
    """One request handler; reads its behaviour from the owning FakeOllama."""

    # Silence the default per-request stderr logging so test output stays clean.
    def log_message(self, *args):
        pass

    def do_POST(self):
        fake = self.server.fake
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            body = {"_unparsed": raw.decode("utf-8", "replace")}
        fake.requests.append(body)

        if self.path != "/api/chat":
            self._send_json(404, {"error": "not found"})
            return

        mode, payload = fake._next()
        if mode == "hang":
            time.sleep(payload)                      # drive a client read timeout
            self._send_envelope(BENIGN_RESULT)
        elif mode == "http_error":
            self._send_json(payload, {"error": "fake server error"})
        elif mode in ("garbage", "raw"):
            # 200 OK with a verbatim `content` string — non-JSON (garbage) or a
            # caller-chosen JSON string (raw), e.g. valid JSON missing a field.
            self._send_envelope_raw(payload)
        else:                                        # "respond" / "echo"
            self._send_envelope(payload)

    # -- response helpers ---------------------------------------------------

    def _send_json(self, code, obj):
        data = json.dumps(obj).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (ConnectionError, OSError):
            # Client hung up (e.g. it already had its answer, or a retry raced
            # a slow reply) — a benign disconnect, not a test failure.
            pass

    def _send_envelope(self, result):
        """Wrap a result dict as Ollama's `{"message": {"content": "<json>"}}`."""
        self._send_envelope_raw(json.dumps(result))

    def _send_envelope_raw(self, content_str):
        """Send the envelope with an arbitrary `content` string (JSON or not)."""
        self._send_json(200, {"message": {"content": content_str}})


class _Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # Swallow benign client-side disconnects (common on Windows when the
        # client closes as soon as it has its answer); surface anything else.
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


class FakeOllama:
    """Context-managed fake Ollama server on an ephemeral localhost port."""

    def __init__(self):
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.fake = self
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self.requests = []
        self._lock = threading.Lock()
        # Default behaviour before any mode is set: reply benign.
        self._mode = "respond"
        self._script = [BENIGN_RESULT]
        self._calls = 0

    # -- lifecycle ----------------------------------------------------------

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        return False

    @property
    def url(self):
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    # -- modes --------------------------------------------------------------

    def respond(self, list_of_dicts):
        """Return these results in order, one per call; the last entry repeats
        once the script is exhausted. Missing keys are filled from BENIGN_RESULT
        so a caller can pass just `[{"risk_score": 85}]`."""
        script = [{**BENIGN_RESULT, **d} for d in list_of_dicts]
        self._set("respond", script or [dict(BENIGN_RESULT)])

    def garbage(self):
        """Reply 200 with non-JSON content -> drives ContentError in scan.py."""
        self._set("garbage", ["this is not json at all -- {broken"])

    def raw(self, list_of_strings):
        """Reply 200 with each given string as the model `content`, VERBATIM (no
        benign-default merge). Use to script replies that are valid JSON but
        missing/wrong fields — e.g. `['{"reasoning": "x"}']` (no risk_score)."""
        self._set("raw", list(list_of_strings) or [""])

    def http_error(self, code=500):
        """Reply with an HTTP error status -> drives InfraError in scan.py."""
        self._set("http_error", [code])

    def hang(self, seconds):
        """Sleep `seconds` before replying (set REQUEST_TIMEOUT below this) ->
        drives a client read timeout -> InfraError in scan.py."""
        self._set("hang", [seconds])

    def echo(self):
        """Record every request and reply benign, so a test can assert WHAT was
        sent to the model without tripping a fail-safe."""
        self._set("respond", [dict(BENIGN_RESULT)])

    # -- internals ----------------------------------------------------------

    def _set(self, mode, script):
        with self._lock:
            self._mode = mode
            self._script = script
            self._calls = 0

    def _next(self):
        """Return (mode, payload) for this call, repeating the last script entry
        once exhausted."""
        with self._lock:
            i = min(self._calls, len(self._script) - 1)
            self._calls += 1
            return self._mode, self._script[i]
