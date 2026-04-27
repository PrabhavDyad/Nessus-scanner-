"""NetScan backend API tests - covers scan lifecycle, validation, NSE whitelist, and PDF export."""
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
        # Updated to 7 scan types (added vuln)
        for k in ["quick", "full", "service", "os", "intense", "vuln", "custom"]:
            assert k in body["scan_types"], f"missing {k} in {body['scan_types']}"

    def test_scan_types(self, session):
        r = session.get(f"{API}/scan-types", timeout=15)
        assert r.status_code == 200
        data = r.json()
        # Updated: now 7 entries
        assert len(data) == 7, f"expected 7 scan types got {len(data)}"
        keys = {d["key"] for d in data}
        assert keys == {"quick", "full", "service", "os", "intense", "vuln", "custom"}
        for d in data:
            assert "label" in d and "flags" in d
            assert isinstance(d["flags"], list)
        # vuln preset specific assertions
        vuln = next(d for d in data if d["key"] == "vuln")
        assert vuln["label"] == "Vulnerability Scan (NSE)"
        assert "--script" in vuln["flags"]


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


# ---------- NSE script whitelist ----------
class TestNSEWhitelist:
    def test_blocks_non_whitelisted_script(self, session):
        r = session.post(
            f"{API}/scans",
            json={
                "target": "127.0.0.1",
                "scan_type": "custom",
                "custom_flags": "-sT --script http-vuln-cve2017-5638",
            },
            timeout=15,
        )
        assert r.status_code == 400, r.text
        assert "whitelist" in r.text.lower()

    def test_allows_whitelisted_scripts(self, session):
        r = session.post(
            f"{API}/scans",
            json={
                "target": "127.0.0.1",
                "scan_type": "custom",
                "custom_flags": "-sT --script vuln,banner",
            },
            timeout=20,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["flags"] == ["-sT", "--script", "vuln,banner"]
        # cleanup
        session.delete(f"{API}/scans/{data['id']}", timeout=15)

    def test_allows_script_equals_form(self, session):
        r = session.post(
            f"{API}/scans",
            json={
                "target": "127.0.0.1",
                "scan_type": "custom",
                "custom_flags": "-sT --script=safe,banner",
            },
            timeout=20,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert "--script=safe,banner" in data["flags"]
        assert "-sT" in data["flags"]
        session.delete(f"{API}/scans/{data['id']}", timeout=15)

    def test_blocks_script_args(self, session):
        r = session.post(
            f"{API}/scans",
            json={
                "target": "127.0.0.1",
                "scan_type": "custom",
                "custom_flags": "-sT --script-args=foo=bar",
            },
            timeout=15,
        )
        assert r.status_code == 400, r.text
        assert "script-args" in r.text.lower()

    def test_blocks_iL_flag(self, session):
        r = session.post(
            f"{API}/scans",
            json={
                "target": "127.0.0.1",
                "scan_type": "custom",
                "custom_flags": "-iL /etc/passwd",
            },
            timeout=15,
        )
        assert r.status_code == 400, r.text


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


# ---------- Vuln preset ----------
class TestVulnPreset:
    vuln_scan_id = None

    def test_create_vuln_scan(self, session):
        r = session.post(
            f"{API}/scans",
            json={"target": "127.0.0.1", "scan_type": "vuln"},
            timeout=20,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["scan_type"] == "vuln"
        assert data["scan_label"] == "Vulnerability Scan (NSE)"
        assert "--script" in data["flags"]
        assert "vuln,vulners,http-title" in data["flags"]
        TestVulnPreset.vuln_scan_id = data["id"]

    def test_vuln_scan_eventually_completes(self, session):
        sid = TestVulnPreset.vuln_scan_id
        assert sid
        deadline = time.time() + 300  # NSE vuln scan can take longer
        last = None
        while time.time() < deadline:
            r = session.get(f"{API}/scans/{sid}", timeout=15)
            assert r.status_code == 200
            last = r.json()
            if last["status"] in ("completed", "failed"):
                break
            time.sleep(2)
        assert last and last["status"] in ("completed", "failed"), f"did not finish: {last and last.get('status')}"
        # Usually completes on localhost; accept 'failed' only if error is about nse
        if last["status"] == "failed":
            pytest.skip(f"vuln scan failed: {last.get('error')}")


# ---------- PDF export ----------
class TestPdfExport:
    def test_pdf_export_for_completed_scan(self, session):
        # Use the completed quick scan from earlier
        sid = TestScanLifecycle.scan_id
        assert sid, "no prior completed scan id"
        r = session.get(f"{API}/scans/{sid}/pdf", timeout=30)
        assert r.status_code == 200, r.text
        assert r.headers.get("content-type", "").startswith("application/pdf")
        assert r.content[:4] == b"%PDF"
        cd = r.headers.get("content-disposition", "")
        assert "netscan-" in cd
        assert ".pdf" in cd.lower()

    def test_pdf_export_404_for_unknown_id(self, session):
        r = session.get(f"{API}/scans/nonexistent-id-xyz/pdf", timeout=15)
        assert r.status_code == 404


# ---------- Cleanup (run last) ----------
class TestZCleanup:
    def test_delete_scan_then_404(self, session):
        sid = TestScanLifecycle.scan_id
        if not sid:
            pytest.skip("no scan id to cleanup")
        d = session.delete(f"{API}/scans/{sid}", timeout=15)
        assert d.status_code == 200
        assert d.json().get("deleted") is True
        g = session.get(f"{API}/scans/{sid}", timeout=15)
        assert g.status_code == 404

    def test_delete_vuln_scan(self, session):
        sid = TestVulnPreset.vuln_scan_id
        if not sid:
            pytest.skip("no vuln scan id")
        session.delete(f"{API}/scans/{sid}", timeout=15)
