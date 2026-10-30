import csv
import io
import ipaddress
import json
import math
import os
import re
import sqlite3
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

import streamlit as st
from auth_core import authenticate, init_auth_db, register, validate_registration
from services.reporting import build_pdf_report
from services.scan_store import list_scans

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DATASNIFF_DB_PATH", APP_DIR / "datasniff.sqlite3"))
MAX_BYTES = 5 * 1024 * 1024
AUTH_MODE = os.environ.get("DATASNIFF_AUTH_MODE", "local").strip().lower()
if AUTH_MODE not in {"local", "hosted"}:
    raise RuntimeError("DATASNIFF_AUTH_MODE must be either 'local' or 'hosted'.")
if AUTH_MODE == "hosted" and len(os.environ.get("STREAMLIT_SERVER_COOKIE_SECRET", "")) < 32:
    raise RuntimeError("Hosted mode requires STREAMLIT_SERVER_COOKIE_SECRET to be set to a random value of at least 32 characters.")

st.set_page_config(page_title="DataSniff | Log & Data Detector", page_icon="◈", layout="wide", initial_sidebar_state="expanded")

RULES = [
    ("Private key", "Critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I), "A private-key header was found.", "Remove the key from logs and revoke or rotate it immediately."),
    ("Database connection string", "Critical", re.compile(r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s:'\"]+:([^\s@'\"]+)@[^\s'\"]+", re.I), "A database URI includes embedded credentials.", "Remove the URI from logs and rotate its password."),
    ("Authorization header", "High", re.compile(r"(?i)\b(?:authorization\s*[:=]\s*)(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})"), "An authorization header contains a credential value.", "Redact the header and rotate the credential if it is genuine."),
    ("API token", "High", re.compile(r"(?i)\b(?:sk_(?:live|test)_[A-Za-z0-9]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b"), "A value matches a recognizable API key or token format.", "Remove the token from logs and rotate it if genuine."),
    ("Password-like field", "High", re.compile(r'''(?i)\b(?:password|passwd|pwd|secret)\s*["']?\s*[:=]\s*["']?([^\s"',;}]{4,})'''), "A password or secret field has a non-empty value.", "Avoid logging credentials; redact the field and rotate the value if genuine."),
    ("Email address", "Low", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "An email address may identify a person.", "Remove or pseudonymize personal data if it is not needed."),
    ("IP address", "Low", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"), "An IP address was found; it may identify a device or network.", "Consider masking addresses in logs shared outside the trusted environment."),
    ("Phone number", "Medium", re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}(?!\w)"), "A phone-number-shaped value was found.", "Remove or pseudonymize personal contact data if unnecessary."),
]

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, filename TEXT NOT NULL, scanned_at TEXT NOT NULL, findings_json TEXT NOT NULL, size_bytes INTEGER NOT NULL, owner_id INTEGER)")
        columns = {row[1] for row in con.execute("PRAGMA table_info(scans)")}
        if "owner_id" not in columns:
            con.execute("ALTER TABLE scans ADD COLUMN owner_id INTEGER")
        con.execute("CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner_id)")
    init_auth_db(DB_PATH)

def mask(value):
    value = str(value)
    if len(value) <= 4: return "*" * len(value)
    return value[:3] + "*" * min(12, max(4, len(value)-5)) + value[-2:]

def entropy(s):
    if not s: return 0
    counts = Counter(s); n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in counts.values())

def render_login():
    st.markdown("<div style='font-size:24px;font-weight:800;letter-spacing:-.04em'>◈ Data<span style='color:#45c8ee'>Sniff</span></div>", unsafe_allow_html=True)
    st.markdown("<div class='eyebrow'>Welcome back</div>", unsafe_allow_html=True)
    st.title("Sign in to DataSniff")
    st.markdown("<div class='subtle'>Access your security dashboard.</div>", unsafe_allow_html=True)
    st.write("")
    with st.form("login_form"):
        email = st.text_input("Email address", autocomplete="email")
        show = st.checkbox("Show password", key="login_show_password")
        password = st.text_input("Password", type="default" if show else "password", autocomplete="current-password")
        submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
    if submitted:
        account = authenticate(email, password, DB_PATH)
        if account:
            st.session_state.auth_account = account
            st.session_state.authenticated = True
            st.session_state.auth_notice = "Signed in successfully."
            st.rerun()
        else:
            st.error("Sign-in failed. Check your email and password, or try again later.")
    if st.button("Forgot password?", key="forgot_password"):
        st.info("Password reset is not configured. Ask your DataSniff administrator to provision a reset flow.")
    st.markdown("New to DataSniff?")
    st.page_link(register_page, label="Create an account")

def render_register():
    st.markdown("<div style='font-size:24px;font-weight:800;letter-spacing:-.04em'>◈ Data<span style='color:#45c8ee'>Sniff</span></div>", unsafe_allow_html=True)
    st.markdown("<div class='eyebrow'>Create your workspace access</div>", unsafe_allow_html=True)
    st.title("Create a DataSniff account")
    st.markdown("<div class='subtle'>Your password is stored as a one-way bcrypt hash.</div>", unsafe_allow_html=True)
    st.write("")
    with st.form("register_form"):
        name = st.text_input("Full name", autocomplete="name")
        email = st.text_input("Email address", autocomplete="email")
        show = st.checkbox("Show password", key="register_show_password")
        password = st.text_input("Password", type="default" if show else "password", autocomplete="new-password", help="12–64 characters, including uppercase, lowercase, and a number.")
        confirmation = st.text_input("Confirm password", type="default" if show else "password", autocomplete="new-password")
        if password:
            score = sum((len(password) >= 12, len(password) >= 16, any(c.islower() for c in password) and any(c.isupper() for c in password), any(c.isdigit() for c in password), any(not c.isalnum() for c in password)))
            st.caption("Password strength: " + ("Strong" if score >= 4 else "Good" if score >= 3 else "Needs more strength"))
        accepted = st.checkbox("I accept the terms of use.")
        submitted = st.form_submit_button("Create account", type="primary", use_container_width=True)
    if submitted:
        error = validate_registration(name, email, password, confirmation, accepted)
        if error:
            st.error(error)
        elif not register(name, email, password, DB_PATH):
            st.error("An account with that email may already exist. Try signing in.")
        else:
            st.session_state.auth_notice = "Account created. Sign in with your new credentials."
            st.success(st.session_state.auth_notice)
            st.info("Open Login from the navigation to sign in.")
    st.markdown("Already have an account?")
    st.page_link(login_page, label="Sign in")

def scan_text(text, filename):
    findings=[]
    for line_no, line in enumerate(text.splitlines(), 1):
        for category, severity, pattern, explanation, remediation in RULES:
            for match in pattern.finditer(line):
                raw=match.group(1) if match.lastindex else match.group(0)
                # Validate IPv4 syntax to avoid flagging impossible addresses.
                if category == "IP address":
                    try: ipaddress.ip_address(raw)
                    except ValueError: continue
                # Avoid trivial placeholders / empty-looking assignments.
                if category == "Password-like field" and raw.lower() in {"changeme", "example", "password", "null", "none", "redacted", "placeholder"}: continue
                confidence = {"Critical": 98, "High": 94, "Medium": 83, "Low": 88}[severity]
                if category == "Password-like field": confidence = 91 if entropy(raw) >= 2.5 else 76
                findings.append({"category":category,"severity":severity,"confidence":confidence,"file":filename,"line":line_no,"evidence":mask(raw),"explanation":explanation,"remediation":remediation})
    return findings

def get_scans(owner_id=None):
    return list_scans(DB_PATH, owner_id)

def add_scan(filename, size, findings, owner_id=None):
    with sqlite3.connect(DB_PATH) as con:
        cur=con.execute("INSERT INTO scans(filename,scanned_at,findings_json,size_bytes,owner_id) VALUES(?,?,?,?,?)",(filename,datetime.now().astimezone().isoformat(timespec="seconds"),json.dumps(findings),size,owner_id))
        return cur.lastrowid

def all_findings(scans):
    out=[]
    for s in scans:
        try: out.extend(json.loads(s["findings_json"]))
        except (TypeError,json.JSONDecodeError): pass
    return out

def render_pdf_report_controls(scan, control_key):
    scan_key = str(scan.get("id", "unknown"))
    state_key = "generated_pdf_report"
    if st.button("Generate Security Report", type="primary", key=f"generate-report-{control_key}"):
        try:
            with st.spinner("Preparing the security report…"):
                pdf_bytes, metadata = build_pdf_report(scan)
            st.session_state[state_key] = {
                "scan_id": scan_key,
                "bytes": pdf_bytes,
                "report_id": metadata["report_id"],
                "generated_at": metadata["generated_at"],
                "findings": len(metadata["findings"]),
                "severity_counts": metadata["severity_counts"],
                "filename": metadata["source_file"],
            }
            st.success("Security report generated.")
        except Exception:
            st.error("The report could not be generated. Check the scan record and try again.")
    generated = st.session_state.get(state_key)
    if generated and generated["scan_id"] == scan_key:
        st.markdown("**Report preview**")
        st.caption(f"{generated['filename']} · {generated['findings']} findings · {generated['report_id']} · {generated['generated_at']}")
        counts = "  |  ".join(f"{severity}: {generated['severity_counts'][severity]}" for severity in ("Critical", "High", "Medium", "Low"))
        st.caption(counts)
        st.download_button(
            "Download PDF report",
            data=generated["bytes"],
            file_name=f"datasniff-security-report-scan-{scan_key}.pdf",
            mime="application/pdf",
            key=f"download-report-{control_key}",
        )

init_db()
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
html,body,[class*="css"]{font-family:'Manrope',sans-serif} .stApp{background:radial-gradient(ellipse at 92% -5%,#142d49 0,transparent 36%),#09111d;color:#e8f0f8}
[data-testid="stSidebar"]{background:#0c1725;border-right:1px solid #1b2b3d} [data-testid="stMetric"]{background:#101d2b;border:1px solid #203348;padding:18px 20px;border-radius:12px}
[data-testid="stMetricValue"]{color:#eaf5ff} [data-testid="stMetricLabel"]{color:#9aafc4}
.eyebrow{color:#57c8ec;text-transform:uppercase;letter-spacing:.18em;font:500 11px 'DM Mono',monospace}.subtle{color:#91a5ba;font-size:14px}.panel{background:#101c29;border:1px solid #203348;border-radius:12px;padding:18px 20px;margin-bottom:12px}.mono{font-family:'DM Mono',monospace;color:#b9d5e9}
div[data-testid="stButton"] button[kind="primary"]{background:#1483c7;border:0} div[data-testid="stButton"] button{border-radius:8px}
</style>""",unsafe_allow_html=True)

def render_scanner():
    if AUTH_MODE == "hosted" and not st.session_state.get("authenticated"):
        st.warning("Please sign in to access the dashboard.")
        st.stop()
    notice = st.session_state.pop("auth_notice", None)
    if notice:
        st.success(notice)
    with st.sidebar:
        st.markdown("<div style='font-size:21px;font-weight:800;letter-spacing:-.04em'>◈ Data<span style='color:#45c8ee'>Sniff</span></div><div style='color:#71879d;font-size:12px;margin:5px 0 26px'>LOG & DATA DETECTOR</div>",unsafe_allow_html=True)
        pages=["Dashboard","New Scan","Findings","Scan History","Reports","Settings / About"]
        if "page_jump" in st.session_state:
            st.session_state.nav_page=st.session_state.pop("page_jump")
        if st.session_state.get("nav_page") not in pages: st.session_state.nav_page="Dashboard"
        page=st.radio("Navigation",pages,key="nav_page",label_visibility="collapsed")
        account = st.session_state.get("auth_account")
        if account:
            st.caption(f"Signed in as {account['full_name']}")
            if st.button("Sign out", use_container_width=True):
                st.session_state.pop("authenticated", None)
                st.session_state.pop("auth_account", None)
                st.rerun()
        st.markdown("<div style='position:fixed;bottom:25px;color:#70859a;font-size:11px'>LOCAL SCANNING · MVP 0.1</div>",unsafe_allow_html=True)

        account = st.session_state.get("auth_account")
        owner_id = account["id"] if AUTH_MODE == "hosted" and account else None
        scans=get_scans(owner_id); findings=all_findings(scans)
    if page == "Dashboard":
        st.markdown("<div class='eyebrow'>Security overview</div>",unsafe_allow_html=True)
        st.title("Dashboard")
        st.markdown("<div class='subtle'>Monitor sensitive data exposure across your logs.</div>",unsafe_allow_html=True)
        st.write("")
        c=st.columns([1,1,1,1,1.25]); c[0].metric("FILES SCANNED",len(scans)); c[1].metric("TOTAL FINDINGS",len(findings)); c[2].metric("CRITICAL",sum(f['severity']=='Critical' for f in findings)); c[3].metric("HIGH",sum(f['severity']=='High' for f in findings))
        with c[4]:
            st.write("")
            if st.button("＋  New Scan",type="primary",use_container_width=True): st.session_state.page_jump="New Scan"; st.rerun()
        left,right=st.columns([1.2,1])
        with left:
            st.markdown("### Recent scans")
            if not scans: st.info("No scans yet. Start with a synthetic log to see DataSniff in action.")
            else:
                for s in scans[:5]:
                    fs=json.loads(s['findings_json']); st.markdown(f"<div class='panel'><b>◈ &nbsp;{s['filename']}</b><span style='float:right;color:#91a5ba'>{len(fs)} findings</span><br><span class='subtle'>{s['scanned_at']}</span></div>",unsafe_allow_html=True)
        with right:
            st.markdown("### Findings by severity")
            for sev,col in [("Critical","#ff5e66"),("High","#ff9b54"),("Medium","#f2c75c"),("Low","#53c8a0")]:
                n=sum(f['severity']==sev for f in findings); st.markdown(f"<div style='padding:11px 4px;border-bottom:1px solid #203348'><span style='color:{col}'>●</span> &nbsp;{sev}<span style='float:right;font-family:monospace'>{n}</span></div>",unsafe_allow_html=True)
    elif page == "New Scan":
        st.markdown("<div class='eyebrow'>Local analysis</div>",unsafe_allow_html=True); st.title("New Scan")
        st.markdown("Upload a log, text, or JSON file. It is processed locally by this app and is not sent to an external service.")
        upload=st.file_uploader("Choose a file",type=["log","txt","json"],help="Maximum file size: 5 MB")
        if upload:
            if upload.size > MAX_BYTES: st.error("File exceeds the 5 MB limit. Choose a smaller file.")
            elif st.button("Run detection",type="primary"):
                try:
                    raw=upload.getvalue()
                    content=raw.decode("utf-8-sig")
                    if upload.name.lower().endswith(".json"):
                        parsed=json.loads(content)
                        # Preserve line structure for line references where possible.
                        content=json.dumps(parsed,ensure_ascii=False,indent=2)
                    with st.spinner("Scanning file locally…"):
                        time.sleep(.15)
                        results=scan_text(content,Path(upload.name).name)
                        scan_id=add_scan(Path(upload.name).name,len(raw),results,owner_id)
                    st.success(f"Scan complete · {len(results)} finding(s) · Scan #{scan_id}")
                    st.session_state.last_scan={"filename":Path(upload.name).name,"findings":results,"scan_id":scan_id}
                except UnicodeDecodeError: st.error("Could not read this file as UTF-8 text. Save it as UTF-8 and try again.")
                except json.JSONDecodeError as e: st.error(f"Malformed JSON near line {e.lineno}, column {e.colno}.")
                except Exception: st.error("The file could not be scanned. Check that it is a readable text file and try again.")
        last=st.session_state.get("last_scan")
        if last:
            st.markdown("### Scan results")
            if last['findings']:
                for f in last['findings']:
                    st.markdown(f"<div class='panel'><b>{f['category']}</b> &nbsp; <span style='color:#ff9b54'>{f['severity']}</span><br><span class='mono'>{f['file']} · line {f['line']} · {f['evidence']}</span><br><span class='subtle'>{f['explanation']}</span><br><span class='subtle'>↳ {f['remediation']} · Confidence {f['confidence']}%</span></div>",unsafe_allow_html=True)
            else: st.success("No findings matched the current detection rules.")
            st.markdown("### Security report")
            report_scan = {
                "id": last["scan_id"],
                "filename": last["filename"],
                "scanned_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "findings_json": json.dumps(last["findings"]),
            }
            render_pdf_report_controls(report_scan, f"scan-{last['scan_id']}")
    elif page == "Findings":
        st.markdown("<div class='eyebrow'>Detection results</div>",unsafe_allow_html=True); st.title("Findings")
        if not findings: st.info("No findings to display yet. Upload a file in New Scan.")
        else:
            a,b,c=st.columns([1,1,1.4]); sev=a.selectbox("Severity",["All","Critical","High","Medium","Low"]); cats=["All"]+sorted({f['category'] for f in findings}); cat=b.selectbox("Category",cats); query=c.text_input("Search",placeholder="Search evidence, file, category…")
            shown=[f for f in findings if (sev=="All" or f['severity']==sev) and (cat=="All" or f['category']==cat) and query.lower() in json.dumps(f).lower()]
            st.caption(f"Showing {len(shown)} of {len(findings)} findings")
            for f in shown:
                colors={"Critical":"#ff5e66","High":"#ff9b54","Medium":"#f2c75c","Low":"#53c8a0"}
                st.markdown(f"<div class='panel'><span style='color:{colors[f['severity']]};font-weight:800'>{f['severity'].upper()}</span> &nbsp; <b>{f['category']}</b><span style='float:right;color:#91a5ba'>Confidence {f['confidence']}%</span><br><span class='mono'>{f['file']} · line {f['line']} · {f['evidence']}</span><br><span class='subtle'>{f['explanation']}</span><br><span class='subtle'>↳ {f['remediation']}</span></div>",unsafe_allow_html=True)
    elif page == "Scan History":
        st.markdown("<div class='eyebrow'>Local records</div>",unsafe_allow_html=True); st.title("Scan History")
        if not scans: st.info("Your completed scans will appear here.")
        for s in scans:
            fs=json.loads(s['findings_json']); st.markdown(f"<div class='panel'><b>{s['filename']}</b> <span style='float:right'>{len(fs)} findings</span><br><span class='subtle'>{s['scanned_at']} · {s['size_bytes']:,} bytes</span></div>",unsafe_allow_html=True)
    elif page == "Reports":
        st.markdown("<div class='eyebrow'>Export</div>",unsafe_allow_html=True); st.title("Reports")
        st.markdown("Generate or regenerate a security report from an authorized scan. Reports contain masked evidence and are created locally.")
        if not scans: st.info("Run a scan before exporting a report.")
        else:
            selected_scan = st.selectbox(
                "Choose a scan",
                scans,
                format_func=lambda scan: f"Scan #{scan['id']} · {Path(str(scan['filename']).replace(chr(92), '/')).name} · {scan['scanned_at']}",
                key="report_scan_choice",
            )
            st.caption("The report preview includes the source file, finding count, severity totals, and a unique report ID.")
            render_pdf_report_controls(selected_scan, f"history-{selected_scan['id']}")
            st.markdown("### Data exports")
            st.markdown("JSON and CSV exports also contain masked evidence. CSV fields are escaped against spreadsheet formula injection.")
            report={"generated_at":datetime.now().astimezone().isoformat(timespec="seconds"),"scan_count":len(scans),"findings":findings}
            st.download_button("Download JSON report",json.dumps(report,indent=2),file_name="datasniff-report.json",mime="application/json")
            out=io.StringIO(); fields=["category","severity","confidence","file","line","evidence","explanation","remediation"]; writer=csv.DictWriter(out,fieldnames=fields); writer.writeheader()
            for f in findings:
                safe={k:f.get(k,"") for k in fields}
                for k,v in safe.items():
                    value=str(v)
                    if value.startswith(("=","+","-","@","\t","\r")): safe[k]="'"+value
                writer.writerow(safe)
            st.download_button("Download CSV report",out.getvalue(),file_name="datasniff-findings.csv",mime="text/csv")
    elif page == "Settings / About":
        st.markdown("<div class='eyebrow'>Configuration</div>",unsafe_allow_html=True); st.title("Settings / About")
        st.markdown(f"""<div class='panel'><h3>DataSniff MVP</h3><p class='subtle'>A local-first log scanner using Python regular expressions, validation, context checks, and basic entropy analysis for password-like values.</p><p><b>File size limit</b> &nbsp; 5 MB</p><p><b>Supported formats</b> &nbsp; .log, .txt, .json</p><p><b>Storage</b> &nbsp; Scan metadata and masked findings are stored in <code>{DB_PATH.name}</code> beside the app. Raw uploaded files and unmasked matched values are not stored.</p><p><b>Severity rules</b> &nbsp; Critical: private-key marker or credential-bearing database URI. High: recognizable API token, authorization header, or populated password-like field. Medium: phone-shaped value. Low: email or valid IP address.</p><p><b>Scope</b> &nbsp; Findings are heuristic. False positives and missed formats are possible; confidence is a rule estimate, not proof a value is live.</p></div>""",unsafe_allow_html=True)


dashboard_page = st.Page(render_scanner, title="Dashboard", url_path="dashboard", default=True)
login_page = st.Page(render_login, title="Login", url_path="login")
register_page = st.Page(render_register, title="Register", url_path="register")

if AUTH_MODE == "hosted" and st.session_state.get("authenticated"):
    page_list = [dashboard_page]
elif AUTH_MODE == "hosted":
    page_list = [login_page, register_page]
else:
    page_list = [dashboard_page, login_page, register_page]

current_page = st.navigation(page_list, position="hidden")
current_page.run()
