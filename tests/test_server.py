"""Console server: the streamed run and the static file guard."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from airlock.server import Handler, _scenario_items


def test_scenario_items_show_counterfactual_then_contained_run():
    items = _scenario_items("email", classifier=None)
    assert items[0]["type"] == "counterfactual" and items[0]["leaks"]
    assert any(i["type"] == "verdict" and i["decision"] == "block" for i in items)
    done = items[-1]
    assert done["type"] == "done" and done["leaks"] == []
    assert done["audit"]["verified"] is True


@pytest.fixture()
def server():
    Handler.pace = 0
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.headers, r.read()


def test_index_is_served_with_csp(server):
    status, headers, body = _get(server + "/")
    assert status == 200 and b"Airlock" in body
    assert "default-src 'self'" in headers["Content-Security-Policy"]


@pytest.mark.parametrize("path", ["/../pyproject.toml", "/%2e%2e/pyproject.toml",
                                  "/fonts/../../src/airlock/rules.py"])
def test_static_guard_refuses_paths_outside_console(server, path):
    with pytest.raises(urllib.error.HTTPError) as e:
        _get(server + path)
    assert e.value.code == 404


def test_run_streams_sse_until_done(server):
    status, headers, body = _get(server + "/api/run?scenario=payment")
    assert headers["Content-Type"] == "text/event-stream"
    items = [json.loads(l[6:]) for l in body.decode().splitlines() if l.startswith("data: ")]
    assert items[-1]["type"] == "done" and items[-1]["leaks"] == []


def test_unknown_scenario_is_404(server):
    with pytest.raises(urllib.error.HTTPError) as e:
        _get(server + "/api/run?scenario=nope")
    assert e.value.code == 404
