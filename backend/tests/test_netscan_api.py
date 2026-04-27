"""NetScan backend API tests - covers scan lifecycle, validation, and history."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("EXPO_PUBLIC_BACKEND_URL", "https://nmap-scanner-1.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


# ---------- Health & metadata ----------
class TestRoot:
    def test_root_nmap_installed(self, session):
        r = session.get(f"{API}/", timeout=15)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("nmap_installed") is True
        assert isinstance(body.get("scan_types"), list)
        for k in ["quick", "full", "service", "os", "intense", "custom"]:
            assert k in body["scan_types"]

    def test_scan_types(self, session):
        r = session.get(f"{API}/scan-types", timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 6
        keys = {d["key"] for d in data}
        assert keys == {"quick", "full", "service", "os", "intense", "custom"}
        for d in data:
            assert "label" in d and "flags" in d
            assert isinstance(d["flags"], list)


# ---------- Validation ----------
class TestValidation:
    def test_invalid_target_rejected(self, session):
        r = session.post(f"{API}/scans", json={"target": "rm -rf /;", "scan_type": "quick"}, timeout=15)
        assert r.status_code == 400, r.text

    def test_dangerous_custom_flags_semicolon(self, session):
        r = session.post(
            f"{API}/scans",
            json={"target": "127.0.0.1", "scan_type": "custom", "custom_flags": "-sT ; whoami"},
            timeout=15,
        )
        assert r.status_code == 400

    def test_dangerous_custom_flags_pipe(self, session):
        r = session.post(
            f"{API}/scans",
            json={"target": "127.0.0.1", "scan_type": "custom", "custom_flags": "-sT | id"},
            timeout=15,
        )
        assert r.status_code == 400

    def test_unknown_scan_type(self, session):
        r = session.post(f"{API}/scans", json={"target": "127.0.0.1", "scan_type": "nuke"}, timeout=15)
        assert r.status_code == 400


# ---------- Scan lifecycle ----------
class TestScanLifecycle:
    scan_id = None

    def test_create_quick_scan(self, session):
        r = session.post(f"{API}/scans", json={"target": "127.0.0.1", "scan_type": "quick"}, timeout=20)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "id" in data
        assert data["target"] == "127.0.0.1"
        assert data["scan_type"] == "quick"
        assert data["status"] in ("queued", "running")
        assert "-sT" in data["flags"]
        assert "_id" not in data
        TestScanLifecycle.scan_id = data["id"]

    def test_scan_completes(self, session):
        sid = TestScanLifecycle.scan_id
        assert sid, "no scan id from create"
        deadline = time.time() + 60
        last = None
        while time.time() < deadline:
            r = session.get(f"{API}/scans/{sid}", timeout=15)
            assert r.status_code == 200
            last = r.json()
            if last["status"] in ("completed", "failed"):
                break
            time.sleep(1.5)
        assert last and last["status"] == "completed", f"status={last and last.get('status')} err={last and last.get('error')}"
        assert isinstance(last.get("hosts"), list) and len(last["hosts"]) >= 1
        assert isinstance(last.get("vuln_hints"), list) and len(last["vuln_hints"]) >= 1
        assert "hosts_up" in last.get("summary", {})
        assert "open_ports" in last.get("summary", {})
        assert "_id" not in last

    def test_history_contains_scan_no_id_leak(self, session):
        r = session.get(f"{API}/scans", timeout=15)
        assert r.status_code == 200
        scans = r.json()
        assert isinstance(scans, list)
        for s in scans:
            assert "_id" not in s
        ids = {s["id"] for s in scans}
        assert TestScanLifecycle.scan_id in ids

    def test_custom_flags_valid(self, session):
        r = session.post(
            f"{API}/scans",
            json={"target": "127.0.0.1", "scan_type": "custom", "custom_flags": "-sT -F"},
            timeout=20,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["scan_type"] == "custom"
        assert data["flags"] == ["-sT", "-F"]
        # cleanup
        session.delete(f"{API}/scans/{data['id']}", timeout=15)

    def test_delete_scan_then_404(self, session):
        sid = TestScanLifecycle.scan_id
        d = session.delete(f"{API}/scans/{sid}", timeout=15)
        assert d.status_code == 200
        assert d.json().get("deleted") is True
        g = session.get(f"{API}/scans/{sid}", timeout=15)
        assert g.status_code == 404
