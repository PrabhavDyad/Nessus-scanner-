from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import Response
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import io
import os
import re
import asyncio
import logging
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI(title="NetScan - Mini Nessus")
api_router = APIRouter(prefix="/api")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ---------------------- Models ----------------------

SCAN_PRESETS: Dict[str, List[str]] = {
    # -sT (TCP connect) is used because the server runs without raw socket privileges
    "quick": ["-sT", "-T4", "-F"],                          # Top 100 ports
    "full": ["-sT", "-T4", "-p-", "--min-rate=1000"],       # All 65535 ports
    "service": ["-sT", "-T4", "-sV", "--top-ports", "200"], # Service/version detection
    "os": ["-sT", "-T4", "-O", "--top-ports", "100"],       # OS detection (best-effort)
    "intense": ["-sT", "-T4", "-A", "-v", "--top-ports", "200"],  # Aggressive
    "vuln": ["-sT", "-T4", "-sV", "--script", "vuln,vulners,http-title", "--top-ports", "200"],  # NSE vuln scripts
}

SCAN_LABELS = {
    "quick": "Quick Scan",
    "full": "Full Port Scan",
    "service": "Service Detection",
    "os": "OS Detection",
    "intense": "Intense Scan",
    "vuln": "Vulnerability Scan (NSE)",
    "custom": "Custom Flags",
}

# Limit concurrent running scans to prevent resource abuse
MAX_CONCURRENT_SCANS = 3
_scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

# Whitelist of safe-ish NSE scripts that may appear in custom flags
NSE_SCRIPT_WHITELIST = {
    "default", "safe", "discovery", "version", "vuln", "vulners",
    "banner", "http-title", "http-headers", "http-methods",
    "http-server-header", "http-robots.txt", "http-enum",
    "ssl-cert", "ssl-enum-ciphers", "smb-os-discovery",
    "ssh2-enum-algos", "ssh-hostkey", "dns-recursion",
    "ftp-anon", "ftp-bounce", "smtp-commands",
}


class ScanCreate(BaseModel):
    target: str
    scan_type: str = "quick"  # quick | full | service | os | intense | custom
    custom_flags: Optional[str] = None


class PortResult(BaseModel):
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None


class VulnHint(BaseModel):
    severity: str  # critical | high | medium | low | info
    title: str
    description: str
    port: Optional[int] = None


class HostResult(BaseModel):
    address: str
    hostname: Optional[str] = None
    state: str = "up"
    os_guess: Optional[str] = None
    ports: List[PortResult] = Field(default_factory=list)


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    scan_type: str
    scan_label: str
    flags: List[str]
    status: str = "queued"  # queued | running | completed | failed
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_sec: Optional[float] = None
    raw_output: str = ""
    error: Optional[str] = None
    hosts: List[HostResult] = Field(default_factory=list)
    vuln_hints: List[VulnHint] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


# ---------------------- Helpers ----------------------

# Allow letters, digits, dot, dash, underscore, slash (CIDR), colon (IPv6), comma
TARGET_RE = re.compile(r"^[A-Za-z0-9._\-:/,]+$")
# Block dangerous shell metachars in custom flags
DANGEROUS_FLAGS_RE = re.compile(r"[;&|`$<>\\\"']")


def validate_target(target: str) -> bool:
    if not target or len(target) > 200:
        return False
    return bool(TARGET_RE.match(target))


def build_flags(scan_type: str, custom_flags: Optional[str]) -> List[str]:
    if scan_type == "custom":
        if not custom_flags:
            return ["-sT", "-T4", "-F"]
        if DANGEROUS_FLAGS_RE.search(custom_flags):
            raise ValueError("Custom flags contain forbidden characters")
        tokens = custom_flags.split()
        safe: List[str] = []
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if len(t) > 100:
                raise ValueError("Flag token too long")
            # NSE script whitelist enforcement
            if t == "--script" and i + 1 < len(tokens):
                _validate_nse_scripts(tokens[i + 1])
                safe.append(t)
                safe.append(tokens[i + 1])
                i += 2
                continue
            if t.startswith("--script="):
                _validate_nse_scripts(t.split("=", 1)[1])
                safe.append(t)
                i += 1
                continue
            # Block --script-args entirely (can read files, etc.)
            if t.startswith("--script-args"):
                raise ValueError("--script-args is not allowed")
            # Block target file include
            if t in ("-iL", "-iR") or t.startswith("-iL=") or t.startswith("-iR="):
                raise ValueError(f"Flag {t} is not allowed")
            safe.append(t)
            i += 1
        # Always force unprivileged scan
        if not any(x in ("-sT", "-sn", "-sP") for x in safe):
            safe.insert(0, "-sT")
        return safe
    flags = SCAN_PRESETS.get(scan_type)
    if not flags:
        raise ValueError(f"Unknown scan type: {scan_type}")
    return list(flags)


def _validate_nse_scripts(spec: str) -> None:
    # spec like "vuln,vulners,http-title" or a single script name
    for name in spec.split(","):
        clean = name.strip().lower()
        if not clean:
            continue
        # Block path-like or wildcard patterns
        if "/" in clean or "*" in clean or ".." in clean:
            raise ValueError(f"NSE script '{name}' is not allowed")
        if clean not in NSE_SCRIPT_WHITELIST:
            raise ValueError(
                f"NSE script '{name}' is not in the whitelist. "
                f"Allowed: {', '.join(sorted(NSE_SCRIPT_WHITELIST))}"
            )


def parse_nmap_xml(xml_text: str) -> tuple[List[HostResult], Dict[str, Any]]:
    hosts: List[HostResult] = []
    summary: Dict[str, Any] = {"hosts_up": 0, "hosts_down": 0, "open_ports": 0}
    if not xml_text.strip():
        return hosts, summary
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        logger.warning(f"XML parse error: {e}")
        return hosts, summary

    for host in root.findall("host"):
        status_el = host.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"

        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        if not addr:
            a = host.find("address")
            if a is not None:
                addr = a.get("addr", "")

        hostname = None
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        os_guess = None
        os_el = host.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_guess = match.get("name")

        ports: List[PortResult] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                pstate = state_el.get("state", "unknown") if state_el is not None else "unknown"
                service_el = p.find("service")
                service = service_el.get("name") if service_el is not None else None
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None
                extrainfo = service_el.get("extrainfo") if service_el is not None else None
                ports.append(PortResult(
                    port=int(p.get("portid", 0)),
                    protocol=p.get("protocol", "tcp"),
                    state=pstate,
                    service=service,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                ))
                if pstate == "open":
                    summary["open_ports"] += 1

        if state == "up":
            summary["hosts_up"] += 1
        else:
            summary["hosts_down"] += 1

        hosts.append(HostResult(
            address=addr or "unknown",
            hostname=hostname,
            state=state,
            os_guess=os_guess,
            ports=ports,
        ))

    summary["total_hosts"] = len(hosts)
    return hosts, summary


# Simple Nessus-style heuristics for common findings
RISKY_SERVICES = {
    "telnet": ("high", "Telnet enabled", "Telnet transmits credentials in cleartext. Replace with SSH."),
    "ftp": ("medium", "FTP service exposed", "Cleartext FTP. Prefer SFTP/FTPS or restrict access."),
    "rlogin": ("high", "Rlogin exposed", "Insecure remote login service. Disable."),
    "rsh": ("high", "Rsh exposed", "Insecure remote shell. Disable."),
    "vnc": ("medium", "VNC service exposed", "VNC often weakly authenticated. Tunnel over SSH/VPN."),
    "smb": ("medium", "SMB exposed", "SMB on the open network can leak info. Limit access."),
    "microsoft-ds": ("medium", "SMB (microsoft-ds) exposed", "Restrict SMB to trusted networks."),
    "netbios-ssn": ("low", "NetBIOS exposed", "Legacy protocol; restrict access."),
    "http": ("info", "HTTP service detected", "Verify TLS is offered alongside (port 443)."),
    "ssh": ("info", "SSH service detected", "Ensure key-based auth and updated OpenSSH."),
    "mysql": ("medium", "MySQL exposed", "Database should not be reachable from the internet."),
    "postgresql": ("medium", "PostgreSQL exposed", "Database should not be reachable from the internet."),
    "redis": ("high", "Redis exposed", "Open Redis often unauthenticated and abused for RCE."),
    "mongodb": ("high", "MongoDB exposed", "Open MongoDB has been mass-exploited; firewall it."),
    "rdp": ("high", "RDP exposed", "RDP exposed to internet is a top brute-force target."),
    "ms-wbt-server": ("high", "RDP exposed", "RDP exposed to internet is a top brute-force target."),
}


def analyze_findings(hosts: List[HostResult]) -> List[VulnHint]:
    hints: List[VulnHint] = []
    for h in hosts:
        for p in h.ports:
            if p.state != "open":
                continue
            svc = (p.service or "").lower()
            if svc in RISKY_SERVICES:
                sev, title, desc = RISKY_SERVICES[svc]
                version_str = " ".join(filter(None, [p.product, p.version])).strip()
                full_desc = desc
                if version_str:
                    full_desc += f" Detected: {version_str}."
                hints.append(VulnHint(severity=sev, title=f"{title} on {h.address}:{p.port}",
                                     description=full_desc, port=p.port))
            # Outdated version heuristic
            if p.product and p.version:
                if "openssh" in p.product.lower():
                    try:
                        major = int(p.version.split(".")[0])
                        if major < 7:
                            hints.append(VulnHint(severity="medium",
                                                  title=f"Outdated OpenSSH {p.version}",
                                                  description="Pre-7.x OpenSSH has known weaknesses; upgrade.",
                                                  port=p.port))
                    except (ValueError, IndexError):
                        pass
        if not h.ports:
            hints.append(VulnHint(severity="info", title=f"No open ports detected on {h.address}",
                                  description="Either filtered, host down, or scan limited."))
    if not hints:
        hints.append(VulnHint(severity="info", title="No notable findings",
                              description="No risky services detected by heuristics. Manual review recommended."))
    return hints


# ---------------------- Background scan task ----------------------

async def run_scan_task(scan_id: str, target: str, flags: List[str]):
    if not shutil.which("nmap"):
        await db.scans.update_one({"id": scan_id}, {"$set": {
            "status": "failed",
            "error": "nmap is not installed on the server",
            "finished_at": datetime.now(timezone.utc),
        }})
        return

    async with _scan_semaphore:
        started = datetime.now(timezone.utc)
        await db.scans.update_one({"id": scan_id}, {"$set": {
            "status": "running",
            "started_at": started,
        }})

    cmd = ["nmap", *flags, "-oX", "-", target]
    logger.info(f"[scan {scan_id}] running: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise RuntimeError("Scan timed out after 600 seconds")

        xml_out = stdout.decode("utf-8", errors="replace")
        err_out = stderr.decode("utf-8", errors="replace")
        hosts, summary = parse_nmap_xml(xml_out)
        hints = analyze_findings(hosts)

        finished = datetime.now(timezone.utc)
        duration = (finished - started).total_seconds()

        update = {
            "status": "completed" if proc.returncode == 0 else "failed",
            "raw_output": xml_out if xml_out else err_out,
            "error": None if proc.returncode == 0 else (err_out or f"nmap exited with code {proc.returncode}"),
            "hosts": [h.dict() for h in hosts],
            "vuln_hints": [v.dict() for v in hints],
            "summary": summary,
            "finished_at": finished,
            "duration_sec": duration,
        }
        await db.scans.update_one({"id": scan_id}, {"$set": update})
        logger.info(f"[scan {scan_id}] {update['status']} in {duration:.1f}s")
    except Exception as e:  # noqa: BLE001
        logger.exception(f"[scan {scan_id}] error")
        await db.scans.update_one({"id": scan_id}, {"$set": {
            "status": "failed",
            "error": str(e),
            "finished_at": datetime.now(timezone.utc),
        }})


# ---------------------- Routes ----------------------

@api_router.get("/")
async def root():
    return {
        "app": "NetScan - Mini Nessus",
        "nmap_installed": shutil.which("nmap") is not None,
        "scan_types": list(SCAN_LABELS.keys()),
    }


@api_router.get("/scan-types")
async def scan_types():
    return [
        {"key": k, "label": v, "flags": SCAN_PRESETS.get(k, [])}
        for k, v in SCAN_LABELS.items()
    ]


@api_router.post("/scans", response_model=Scan)
async def create_scan(payload: ScanCreate):
    if not validate_target(payload.target):
        raise HTTPException(status_code=400, detail="Invalid target. Allowed: letters, digits, . - _ : / ,")
    try:
        flags = build_flags(payload.scan_type, payload.custom_flags)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan = Scan(
        target=payload.target.strip(),
        scan_type=payload.scan_type,
        scan_label=SCAN_LABELS.get(payload.scan_type, payload.scan_type),
        flags=flags,
    )
    await db.scans.insert_one(scan.dict())
    asyncio.create_task(run_scan_task(scan.id, scan.target, flags))
    return scan


@api_router.get("/scans", response_model=List[Scan])
async def list_scans(limit: int = 50):
    cursor = db.scans.find({}, {"_id": 0}).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    return [Scan(**d) for d in docs]


@api_router.get("/scans/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str):
    doc = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Scan(**doc)


@api_router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    res = await db.scans.delete_one({"id": scan_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True, "id": scan_id}


@api_router.get("/scans/{scan_id}/pdf")
async def export_scan_pdf(scan_id: str):
    doc = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = Scan(**doc)
    pdf_bytes = render_scan_pdf(scan)
    filename = f"netscan-{scan.target.replace('/', '_')}-{scan.id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def render_scan_pdf(scan: Scan) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )

    SEV_COLORS = {
        "critical": colors.HexColor("#EF4444"),
        "high": colors.HexColor("#F97316"),
        "medium": colors.HexColor("#EAB308"),
        "low": colors.HexColor("#3B82F6"),
        "info": colors.HexColor("#6366F1"),
    }
    PRIMARY = colors.HexColor("#10B981")
    DARK = colors.HexColor("#0F172A")
    GREY = colors.HexColor("#475569")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"NetScan Report - {scan.target}",
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], textColor=DARK, fontName="Helvetica-Bold", fontSize=22, spaceAfter=4)
    sub = ParagraphStyle("sub", parent=styles["Normal"], textColor=GREY, fontSize=10, spaceAfter=12)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=PRIMARY, fontName="Helvetica-Bold", fontSize=13, spaceBefore=14, spaceAfter=6)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=10, leading=14)
    mono = ParagraphStyle("mono", parent=styles["Code"], fontName="Courier", fontSize=9, leading=12, textColor=DARK)

    story = []
    story.append(Paragraph("NETSCAN — Mini Nessus Report", h1))
    story.append(Paragraph(
        f"Target: <b>{scan.target}</b> &nbsp;&nbsp; Type: {scan.scan_label} &nbsp;&nbsp; Status: {scan.status.upper()}",
        sub,
    ))

    meta_rows = [
        ["Scan ID", scan.id],
        ["Created", scan.created_at.isoformat() if scan.created_at else "-"],
        ["Finished", scan.finished_at.isoformat() if scan.finished_at else "-"],
        ["Duration", f"{scan.duration_sec:.2f}s" if scan.duration_sec is not None else "-"],
        ["Command", "nmap " + " ".join(scan.flags) + " " + scan.target],
        ["Hosts up", str(scan.summary.get("hosts_up", 0))],
        ["Open ports", str(scan.summary.get("open_ports", 0))],
        ["Findings", str(len(scan.vuln_hints))],
    ]
    meta_table = Table(meta_rows, colWidths=[35 * mm, 130 * mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
        ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
        ("TEXTCOLOR", (0, 0), (-1, -1), DARK),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)

    if scan.error:
        story.append(Paragraph("Error", h2))
        story.append(Paragraph(scan.error.replace("<", "&lt;"), body))

    story.append(Paragraph("Findings", h2))
    if not scan.vuln_hints:
        story.append(Paragraph("No findings recorded.", body))
    else:
        rows = [["Severity", "Title", "Description"]]
        for v in scan.vuln_hints:
            rows.append([v.severity.upper(), v.title, v.description])
        f_table = Table(rows, colWidths=[22 * mm, 60 * mm, 83 * mm], repeatRows=1)
        ts = [
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
            ("FONT", (0, 1), (-1, -1), "Helvetica", 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        for i, v in enumerate(scan.vuln_hints, start=1):
            sev_col = SEV_COLORS.get(v.severity, SEV_COLORS["info"])
            ts.append(("TEXTCOLOR", (0, i), (0, i), sev_col))
            ts.append(("FONT", (0, i), (0, i), "Helvetica-Bold", 8))
        f_table.setStyle(TableStyle(ts))
        story.append(f_table)

    story.append(Paragraph("Hosts &amp; Ports", h2))
    if not scan.hosts:
        story.append(Paragraph("No hosts reported.", body))
    for host in scan.hosts:
        title = f"{host.address}"
        if host.hostname:
            title += f" ({host.hostname})"
        title += f" — {host.state.upper()}"
        if host.os_guess:
            title += f" — OS: {host.os_guess}"
        story.append(Paragraph(title, ParagraphStyle("hostHdr", parent=body, fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=4)))
        if not host.ports:
            story.append(Paragraph("No ports.", body))
            continue
        prows = [["Port", "Proto", "State", "Service", "Product / Version"]]
        for p in host.ports:
            prows.append([
                str(p.port), p.protocol, p.state,
                p.service or "-",
                " ".join(filter(None, [p.product, p.version, p.extrainfo])) or "-",
            ])
        ptable = Table(prows, colWidths=[18 * mm, 16 * mm, 18 * mm, 35 * mm, 78 * mm], repeatRows=1)
        ptable.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
            ("FONT", (0, 1), (-1, -1), "Courier", 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#E2E8F0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(ptable)

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "Generated by NetScan — Mini Nessus. Scan responsibly.",
        ParagraphStyle("footer", parent=body, textColor=GREY, fontSize=8, alignment=1),
    ))

    doc.build(story)
    return buf.getvalue()


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
