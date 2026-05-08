from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from pathlib import Path
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import sqlite3
import hashlib
import secrets
import json
import requests
import xml.etree.ElementTree as ET
import re
import smtplib
from email.mime.text import MIMEText
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from openpyxl import Workbook

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
DB_PATH = DATA_DIR / "cyberwatch.db"
REPORT_DIR = DATA_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

THN_RSS = "https://feeds.feedburner.com/TheHackersNews?format=xml"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
DEFAULT_WATCHLIST = ["Microsoft 365","Palo Alto","Rapid7","CrowdStrike","Azure","Google Workspace","Zoom","Citrix","Salesforce","Snowflake","Netskope","UKG","Concur","Adobe Sign"]
scheduler = BackgroundScheduler(timezone="America/New_York")

app = FastAPI(title="Cyber Watch Suite")
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32), same_site="lax")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

class WatchRequest(BaseModel):
    item: str

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    email: Optional[EmailStr] = None

class UserPasswordChange(BaseModel):
    current_password: str
    new_password: str

class AdminPasswordReset(BaseModel):
    username: str
    new_password: str

class DigestConfig(BaseModel):
    smtp_host: str
    smtp_port: int = 587
    smtp_username: str
    smtp_password: str
    sender_email: EmailStr
    recipient_email: EmailStr
    enabled: bool = True
    schedule_hour: int = 7
    schedule_minute: int = 0

class AliasUpdate(BaseModel):
    canonical_name: str
    aliases: List[str]


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    return hashlib.sha256((salt + password).encode()).hexdigest() == digest


def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            email TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            canonical_name TEXT NOT NULL,
            alias TEXT NOT NULL,
            UNIQUE(canonical_name, alias)
        );
        CREATE TABLE IF NOT EXISTS digest_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            smtp_host TEXT,
            smtp_port INTEGER,
            smtp_username TEXT,
            smtp_password TEXT,
            sender_email TEXT,
            recipient_email TEXT,
            enabled INTEGER NOT NULL DEFAULT 0,
            schedule_hour INTEGER NOT NULL DEFAULT 7,
            schedule_minute INTEGER NOT NULL DEFAULT 0,
            last_sent_at TEXT
        );
        """
    )
    admin = conn.execute("SELECT * FROM users WHERE username='admin'").fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, email, created_at) VALUES (?,?,?,?,?)",
            ("admin", hash_password("ChangeMe123!"), "admin", None, datetime.now(timezone.utc).isoformat())
        )
    count = conn.execute("SELECT COUNT(*) AS c FROM watchlist").fetchone()["c"]
    if count == 0:
        for item in DEFAULT_WATCHLIST:
            conn.execute("INSERT OR IGNORE INTO watchlist (name, created_at) VALUES (?, ?)", (item, datetime.now(timezone.utc).isoformat()))
            conn.execute("INSERT OR IGNORE INTO aliases (canonical_name, alias) VALUES (?, ?)", (item, item))
    conn.execute("INSERT OR IGNORE INTO digest_config (id, enabled, schedule_hour, schedule_minute) VALUES (1, 0, 7, 0)")
    conn.commit()
    conn.close()


def get_user(username: str):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return row


def current_user(request: Request):
    username = request.session.get("user")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = get_user(username)
    if not user or user["active"] != 1:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Invalid session")
    return user


def admin_user(request: Request):
    user = current_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return user


def get_watchlist() -> List[str]:
    conn = db()
    rows = conn.execute("SELECT name FROM watchlist ORDER BY name").fetchall()
    conn.close()
    return [r["name"] for r in rows]


def get_alias_map() -> dict:
    conn = db()
    rows = conn.execute("SELECT canonical_name, alias FROM aliases ORDER BY canonical_name, alias").fetchall()
    conn.close()
    data = {}
    for r in rows:
        data.setdefault(r["canonical_name"], []).append(r["alias"])
    return data


def add_watch(item: str):
    item = item.strip()
    conn = db()
    conn.execute("INSERT OR IGNORE INTO watchlist (name, created_at) VALUES (?, ?)", (item, datetime.now(timezone.utc).isoformat()))
    conn.execute("INSERT OR IGNORE INTO aliases (canonical_name, alias) VALUES (?, ?)", (item, item))
    conn.commit()
    conn.close()


def save_aliases(canonical_name: str, aliases: List[str]):
    conn = db()
    conn.execute("DELETE FROM aliases WHERE canonical_name=?", (canonical_name,))
    for alias in {a.strip() for a in aliases if a.strip()}:
        conn.execute("INSERT OR IGNORE INTO aliases (canonical_name, alias) VALUES (?, ?)", (canonical_name, alias))
    conn.commit()
    conn.close()


def delete_watch(item: str):
    conn = db()
    conn.execute("DELETE FROM watchlist WHERE lower(name)=lower(?)", (item,))
    conn.execute("DELETE FROM aliases WHERE lower(canonical_name)=lower(?)", (item,))
    conn.commit()
    conn.close()


def parse_iso_date(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        try:
            return datetime.strptime(value, "%a, %d %b %Y %H:%M:%S %z").astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)


def strip_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def fetch_rss():
    r = requests.get(THN_RSS, timeout=25, headers={"User-Agent": "CyberWatchSuite/1.0"})
    r.raise_for_status()
    root = ET.fromstring(r.content)
    out = []
    for item in root.findall("./channel/item")[:25]:
        out.append({"type": "news", "source": "The Hacker News", "title": (item.findtext("title") or "").strip(), "link": (item.findtext("link") or "").strip(), "published": item.findtext("pubDate") or "", "summary": strip_html(item.findtext("description") or "")})
    return out


def fetch_nvd(days: int = 14):
    start = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
    r = requests.get(NVD_URL, params={"resultsPerPage": 40, "pubStartDate": start}, timeout=35, headers={"User-Agent": "CyberWatchSuite/1.0"})
    r.raise_for_status()
    data = r.json()
    out = []
    for wrap in data.get("vulnerabilities", []):
        cve = wrap.get("cve", {})
        cve_id = cve.get("id", "Unknown")
        desc = "No summary available"
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value") or desc
                break
        metrics = cve.get("metrics", {})
        severity = "low"
        score = None
        if metrics.get("cvssMetricV31"):
            m = metrics["cvssMetricV31"][0]
            severity = (m.get("cvssData", {}).get("baseSeverity") or "LOW").lower()
            score = m.get("cvssData", {}).get("baseScore")
        elif metrics.get("cvssMetricV30"):
            m = metrics["cvssMetricV30"][0]
            severity = (m.get("cvssData", {}).get("baseSeverity") or "LOW").lower()
            score = m.get("cvssData", {}).get("baseScore")
        elif metrics.get("cvssMetricV2"):
            m = metrics["cvssMetricV2"][0]
            severity = (m.get("baseSeverity") or "LOW").lower()
            score = m.get("cvssData", {}).get("baseScore")
        out.append({"type": "vuln", "source": "NVD", "id": cve_id, "title": cve_id, "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "published": cve.get("published"), "summary": desc, "severity": severity, "cvss": score, "products": json.dumps(cve.get("configurations", []))[:4000]})
    return out


def fetch_kev():
    r = requests.get(KEV_URL, timeout=30, headers={"User-Agent": "CyberWatchSuite/1.0"})
    r.raise_for_status()
    data = r.json()
    out = {}
    for item in data.get("vulnerabilities", []):
        cve = item.get("cveID")
        if cve:
            out[cve] = item
    return out


def fetch_epss(cves: List[str]):
    out = {}
    if not cves:
        return out
    batch = []
    size = 0
    for cve in cves:
        add = len(cve) + (1 if batch else 0)
        if size + add > 1900:
            r = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30, headers={"User-Agent": "CyberWatchSuite/1.0"})
            r.raise_for_status()
            for row in r.json().get("data", []):
                out[row.get("cve")] = {"epss": row.get("epss"), "percentile": row.get("percentile")}
            batch = [cve]
            size = len(cve)
        else:
            batch.append(cve)
            size += add
    if batch:
        r = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30, headers={"User-Agent": "CyberWatchSuite/1.0"})
        r.raise_for_status()
        for row in r.json().get("data", []):
            out[row.get("cve")] = {"epss": row.get("epss"), "percentile": row.get("percentile")}
    return out


def find_matches(text: str, watch: List[str], alias_map: dict):
    lc = (text or "").lower()
    matches = []
    for canonical in watch:
        aliases = alias_map.get(canonical, [canonical])
        if any(alias.lower() in lc for alias in aliases):
            matches.append(canonical)
    return matches


def score_item(item: dict) -> int:
    score = 0
    if item.get("type") == "vuln": score += 30
    if item.get("kev"): score += 30
    score += item.get("matchCount", 0) * 18
    sev = item.get("severity", "low")
    if sev == "critical": score += 30
    elif sev == "high": score += 20
    elif sev == "medium": score += 10
    try: score += int(float(item.get("epss") or 0) * 20)
    except Exception: pass
    age = item.get("ageHours", 999)
    if age <= 24: score += 12
    elif age <= 72: score += 6
    return score


def build_dataset(search: str = ""):
    watch = get_watchlist()
    alias_map = get_alias_map()
    news = fetch_rss()
    vulns = fetch_nvd()
    kev = fetch_kev()
    epss = fetch_epss([v["id"] for v in vulns if v.get("id")])
    news_out, vuln_out = [], []
    for item in news:
        pub = parse_iso_date(item.get("published"))
        age_hours = max(1, int((datetime.now(timezone.utc) - pub.astimezone(timezone.utc)).total_seconds() / 3600))
        matches = find_matches(f"{item['title']} {item['summary']}", watch, alias_map)
        news_out.append({**item, "published": pub.isoformat(), "matches": matches, "matchCount": len(matches), "ageHours": age_hours, "kev": False, "epss": None, "percentile": None, "severity": "low"})
    for item in vulns:
        pub = parse_iso_date(item.get("published"))
        age_hours = max(1, int((datetime.now(timezone.utc) - pub.astimezone(timezone.utc)).total_seconds() / 3600))
        matches = find_matches(f"{item['summary']} {item['products']} {item['id']}", watch, alias_map)
        kev_hit = item["id"] in kev
        epss_meta = epss.get(item["id"], {})
        vuln_out.append({**item, "published": pub.isoformat(), "matches": matches, "matchCount": len(matches), "ageHours": age_hours, "kev": kev_hit, "kevMeta": kev.get(item['id'], {}), "epss": epss_meta.get("epss"), "percentile": epss_meta.get("percentile")})
    if search:
        s = search.lower()
        news_out = [x for x in news_out if s in f"{x['title']} {x['summary']} {' '.join(x['matches'])}".lower()]
        vuln_out = [x for x in vuln_out if s in f"{x['id']} {x['summary']} {' '.join(x['matches'])}".lower()]
    combined = sorted(news_out + vuln_out, key=score_item, reverse=True)[:15]
    for item in combined: item["priority"] = score_item(item)
    return {"watchlist": watch, "aliases": alias_map, "news": sorted(news_out, key=lambda x: (x["matchCount"], x["published"]), reverse=True), "vulns": sorted(vuln_out, key=score_item, reverse=True), "brief": combined, "stats": {"watchHits": len([x for x in news_out + vuln_out if x.get("matchCount", 0) > 0]), "criticalCVEs": len([x for x in vuln_out if x.get("severity") == "critical"]), "kevHits": len([x for x in vuln_out if x.get("kev")]), "freshItems": len([x for x in news_out + vuln_out if x.get("ageHours", 999) <= 24]), "newsCount": len(news_out), "vulnCount": len(vuln_out)}, "updated": datetime.now(timezone.utc).isoformat(), "sources": {"rss": THN_RSS, "nvd": NVD_URL, "kev": KEV_URL, "epss": EPSS_URL}}


def get_digest_config():
    conn = db()
    row = conn.execute("SELECT * FROM digest_config WHERE id=1").fetchone()
    conn.close()
    return dict(row) if row else None


def schedule_digest_job():
    cfg = get_digest_config()
    for job in scheduler.get_jobs():
        if job.id == "daily_digest":
            scheduler.remove_job("daily_digest")
    if cfg and cfg.get("enabled"):
        scheduler.add_job(send_digest_internal, CronTrigger(hour=int(cfg.get("schedule_hour",7)), minute=int(cfg.get("schedule_minute",0))), id="daily_digest", replace_existing=True)


def save_digest_config(cfg: DigestConfig):
    conn = db()
    conn.execute("UPDATE digest_config SET smtp_host=?, smtp_port=?, smtp_username=?, smtp_password=?, sender_email=?, recipient_email=?, enabled=?, schedule_hour=?, schedule_minute=? WHERE id=1", (cfg.smtp_host, cfg.smtp_port, cfg.smtp_username, cfg.smtp_password, cfg.sender_email, cfg.recipient_email, 1 if cfg.enabled else 0, cfg.schedule_hour, cfg.schedule_minute))
    conn.commit()
    conn.close()
    schedule_digest_job()


def send_digest_internal():
    cfg = get_digest_config()
    if not cfg or not cfg.get("enabled"):
        return {"status": "disabled"}
    data = build_dataset()
    lines = ["Cyber Watch Suite Morning Digest", f"Updated: {data['updated']}", "", "Top Brief Items:"]
    for item in data["brief"][:10]:
        lines.append(f"- {item['title']} | type={item['type']} | severity={item.get('severity')} | kev={item.get('kev')} | epss={item.get('epss')} | matches={', '.join(item.get('matches', [])) or 'none'}")
    msg = MIMEText("\n".join(lines))
    msg["Subject"] = "Cyber Watch Suite Morning Digest"
    msg["From"] = cfg["sender_email"]
    msg["To"] = cfg["recipient_email"]
    with smtplib.SMTP(cfg["smtp_host"], int(cfg["smtp_port"])) as server:
        server.starttls()
        server.login(cfg["smtp_username"], cfg["smtp_password"])
        server.send_message(msg)
    conn = db()
    conn.execute("UPDATE digest_config SET last_sent_at=? WHERE id=1", (datetime.now(timezone.utc).isoformat(),))
    conn.commit()
    conn.close()
    return {"status": "sent", "to": cfg["recipient_email"]}


def export_xlsx(data: dict) -> Path:
    path = REPORT_DIR / f"cyberwatch-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.xlsx"
    wb = Workbook()
    ws = wb.active
    ws.title = "Morning Brief"
    ws.append(["Title","Type","Severity","KEV","EPSS","Percentile","Matches","Published","Link"])
    for item in data["brief"]:
        ws.append([item.get("title"), item.get("type"), item.get("severity"), str(item.get("kev")), item.get("epss"), item.get("percentile"), ", ".join(item.get("matches", [])), item.get("published"), item.get("link")])
    ws2 = wb.create_sheet("Vulnerabilities")
    ws2.append(["CVE","Severity","CVSS","KEV","EPSS","Percentile","Matches","Published","Summary"])
    for item in data["vulns"][:50]:
        ws2.append([item.get("id"), item.get("severity"), item.get("cvss"), str(item.get("kev")), item.get("epss"), item.get("percentile"), ", ".join(item.get("matches", [])), item.get("published"), item.get("summary")])
    wb.save(path)
    return path


def export_pdf(data: dict) -> Path:
    path = REPORT_DIR / f"cyberwatch-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
    doc = SimpleDocTemplate(str(path), pagesize=letter)
    styles = getSampleStyleSheet()
    story = [Paragraph("Cyber Watch Suite Report", styles["Title"]), Paragraph(f"Generated: {data['updated']}", styles["Normal"]), Spacer(1, 12)]
    table_data = [["Title","Type","Severity","KEV","EPSS","Matches"]]
    for item in data["brief"][:12]:
        table_data.append([item.get("title","")[:45], item.get("type",""), item.get("severity",""), str(item.get("kev")), str(item.get("epss") or ""), ", ".join(item.get("matches", []))[:30]])
    tbl = Table(table_data, repeatRows=1)
    tbl.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#d9e2f3")), ("GRID", (0,0), (-1,-1), 0.5, colors.grey), ("VALIGN", (0,0), (-1,-1), "TOP")]))
    story += [Paragraph("Morning Brief", styles["Heading2"]), tbl, Spacer(1, 12), Paragraph("Top Vulnerabilities", styles["Heading2"])]
    for item in data["vulns"][:10]:
        story.append(Paragraph(f"{item.get('id')} | severity={item.get('severity')} | kev={item.get('kev')} | epss={item.get('epss')} | matches={', '.join(item.get('matches', [])) or 'none'}", styles["Normal"]))
        story.append(Paragraph(item.get("summary", "")[:300], styles["BodyText"]))
        story.append(Spacer(1, 8))
    doc.build(story)
    return path


@app.on_event("startup")
def startup():
    init_db()
    if not scheduler.running:
        scheduler.start()
    schedule_digest_job()


@app.on_event("shutdown")
def shutdown():
    if scheduler.running:
        scheduler.shutdown(wait=False)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("user"):
        return RedirectResponse(url="/", status_code=302)
    return HTMLResponse((BASE / "templates" / "login.html").read_text(encoding="utf-8"))


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = get_user(username)
    if not user or user["active"] != 1 or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    request.session["user"] = user["username"]
    return RedirectResponse(url="/", status_code=302)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = current_user(request)
    html = (BASE / "templates" / "dashboard.html").read_text(encoding="utf-8")
    return HTMLResponse(html.replace("__USERNAME__", user["username"]).replace("__ROLE__", user["role"]))


@app.get("/api/dashboard")
def api_dashboard(request: Request, search: str = ""):
    current_user(request)
    return JSONResponse(build_dataset(search))


@app.get("/api/watchlist")
def api_watchlist(request: Request):
    current_user(request)
    return {"items": get_watchlist(), "aliases": get_alias_map()}


@app.post("/api/watchlist")
def api_watch_add(request: Request, req: WatchRequest):
    current_user(request)
    if not req.item.strip():
        raise HTTPException(status_code=400, detail="Blank item")
    add_watch(req.item)
    return {"items": get_watchlist()}


@app.delete("/api/watchlist/{name}")
def api_watch_delete(name: str, request: Request):
    current_user(request)
    delete_watch(name)
    return {"items": get_watchlist()}


@app.post("/api/aliases")
def api_aliases(request: Request, body: AliasUpdate):
    current_user(request)
    save_aliases(body.canonical_name, body.aliases)
    return {"aliases": get_alias_map()}


@app.get("/admin/users")
def api_users(request: Request):
    admin_user(request)
    conn = db()
    rows = conn.execute("SELECT username, role, email, active, created_at FROM users ORDER BY username").fetchall()
    conn.close()
    return {"users": [dict(r) for r in rows]}


@app.post("/admin/users")
def api_user_add(request: Request, user: UserCreate):
    admin_user(request)
    if len(user.password) < 10:
        raise HTTPException(status_code=400, detail="Password must be at least 10 characters")
    conn = db()
    try:
        conn.execute("INSERT INTO users (username, password_hash, role, email, created_at) VALUES (?,?,?,?,?)", (user.username, hash_password(user.password), user.role, user.email, datetime.now(timezone.utc).isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")
    finally:
        conn.close()
    return {"status": "created", "username": user.username}


@app.post("/admin/users/{username}/disable")
def api_user_disable(username: str, request: Request):
    admin_user(request)
    if username == "admin":
        raise HTTPException(status_code=400, detail="Do not disable the bootstrap admin until another admin exists")
    conn = db()
    conn.execute("UPDATE users SET active=0 WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return {"status": "disabled", "username": username}


@app.delete("/admin/users/{username}")
def api_user_delete(username: str, request: Request):
    admin_user(request)
    if username == "admin":
        raise HTTPException(status_code=400, detail="Do not delete the bootstrap admin until another admin exists")
    conn = db()
    conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return {"status": "deleted", "username": username}


@app.post("/me/password")
def api_change_password(request: Request, body: UserPasswordChange):
    user = current_user(request)
    if len(body.new_password) < 10:
        raise HTTPException(status_code=400, detail="New password must be at least 10 characters")
    if not verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    conn = db()
    conn.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_password(body.new_password), user["username"]))
    conn.commit()
    conn.close()
    return {"status": "password_changed"}


@app.post("/admin/password-reset")
def api_admin_password_reset(request: Request, body: AdminPasswordReset):
    admin_user(request)
    if len(body.new_password) < 10:
        raise HTTPException(status_code=400, detail="New password must be at least 10 characters")
    conn = db()
    conn.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_password(body.new_password), body.username))
    conn.commit()
    conn.close()
    return {"status": "password_reset", "username": body.username}


@app.post("/admin/digest")
def api_save_digest(request: Request, cfg: DigestConfig):
    admin_user(request)
    save_digest_config(cfg)
    return {"status": "saved"}


@app.post("/admin/digest/send")
def api_send_digest(request: Request):
    admin_user(request)
    return send_digest_internal()


@app.get("/admin/digest/config")
def api_digest_config(request: Request):
    admin_user(request)
    return get_digest_config()


@app.get("/report/xlsx")
def report_xlsx(request: Request):
    current_user(request)
    path = export_xlsx(build_dataset())
    return FileResponse(path, filename=path.name, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.get("/report/pdf")
def report_pdf(request: Request):
    current_user(request)
    path = export_pdf(build_dataset())
    return FileResponse(path, filename=path.name, media_type="application/pdf")
