# DataSniff

DataSniff is a local-first log and data detector. It scans text and JSON logs for common sensitive-data patterns, presents findings with severity and confidence, and creates a masked PDF security analysis and remediation report.

## Project objective

Help developers spot likely sensitive values in application logs before sharing or retaining those logs. Detection is heuristic: a match is a candidate for review, not proof that a credential is valid, active, or exploited.

## Features

- Upload and scan `.log`, `.txt`, and `.json` files up to 5 MB.
- Line-based detection for private-key markers, credential-bearing database URLs, authorization headers, recognizable API tokens, password-like fields, email addresses, IP addresses, and phone-shaped values.
- Findings with severity, confidence, masked evidence, location, explanation, and remediation.
- Search and filter findings; view dashboard counts and local scan history.
- Export masked JSON and CSV, with CSV formula-injection protection.
- Generate local PDF reports with executive summary, calculated risk overview, severity chart, finding details, category-specific remediation, verification guidance, and limitations.
- Optional account registration and login for hosted mode. Accounts use bcrypt hashes; hosted scans are scoped to the signed-in account. Local mode remains usable without an account.
- Synthetic log and JSON fixtures for demonstrations.

## Technology and architecture

The application is a single Python Streamlit process. Streamlit renders the UI and handles file uploads; Python parses and scans the in-memory file using regular expressions, context checks, and basic entropy analysis. SQLite stores scan metadata and masked findings. The report service consumes the stored finding schema and builds PDFs with ReportLab. There is no web frontend framework, external database, cloud AI service, or standalone ingestion API.

In local mode, scanning and report generation happen in the local app process. In hosted mode, the browser sends uploads to the Streamlit server for processing; configure HTTPS and private persistent storage before exposing it publicly. No log contents are sent to an external service by this application.

See [docs/architecture.md](docs/architecture.md) for the data flow and storage details.

## Project structure

```text
app.py                              Streamlit UI, scanner workflow, exports
auth_core.py                        SQLite account creation, bcrypt login, lockout
services/scan_store.py              Account-scoped scan listing
services/reporting/
  pdf_generator.py                  PDF report builder and safe text handling
  remediation_knowledge_base.py     Deterministic category-specific guidance
tests/                              Authentication, report, and UI tests
sample.log                          Synthetic demonstration log
sample-data/                        Synthetic log, clean log, and JSON fixtures
requirements.txt                    Python dependencies
.env.example                        Placeholder configuration values
```

## Installation

Python 3.10 or newer is recommended.

```powershell
python -m pip install -r requirements.txt
```

Copy `.env.example` to `.env` only if you want a local record of configuration. Streamlit does not load `.env` automatically; set environment variables in the shell before launching. The default `DATASNIFF_AUTH_MODE=local` requires no online account or secrets.

## Run the application

```powershell
python -m streamlit run app.py
```

Open http://localhost:8501. Use **New Scan** and upload `sample-data/sample-app.log` or `sample-data/sample-events.json`. The clean fixture is `sample-data/clean-app.log`.

## Authentication modes

- **Local (default):** scan without an account. Local registration and login pages are available but are not required for local scanning.
- **Hosted:** require login and restrict scan history and report selection to the signed-in account. Set a private, stable Streamlit cookie secret of at least 32 characters before starting:

```powershell
$env:DATASNIFF_AUTH_MODE = "hosted"
$env:STREAMLIT_SERVER_COOKIE_SECRET = (python -c "import secrets; print(secrets.token_urlsafe(48))")
python -m streamlit run app.py
```

Keep the cookie secret out of source control. To configure a durable database location, set `DATASNIFF_DB_PATH` to a private writable path. Hosted deployments also require HTTPS at the hosting proxy and persistent private storage.

## Generate a PDF security report

1. Complete a scan from **New Scan**.
2. Under **Security report**, select **Generate Security Report**.
3. Review the source filename, finding count, severity totals, and report ID.
4. Select **Download PDF report**.

To regenerate a report later, open **Reports**, choose a scan available to the current account, then generate and download its report. PDFs are generated locally and held in the current Streamlit session; PDF files are not archived in SQLite. JSON and CSV exports remain available on the Reports page.

## Ingestion API and API keys

There is no separate ingestion API or API-key configuration in this MVP. Uploads use Streamlit's built-in file uploader and are processed by the app server.

## Screenshots

Screenshots are not included yet. Suggested captures: dashboard, scan results with masked evidence, and a PDF report cover/risk page.

## Tests

Run the authentication, report-generation, authorization-filtering, and Streamlit UI tests with:

```powershell
python -m unittest discover -s tests -v
```

The tests use synthetic inputs and check PDF text, masking, page counts, long-text handling, malformed data, and report download controls.

## Current limitations

- Pattern-based detection can miss formats or identify benign values; confidence is a heuristic, not proof.
- JSON is formatted before line-based scanning, so findings refer to formatted line numbers rather than JSONPath from the original file.
- Hosted mode is a small single-process deployment, without email verification, password reset, IP-based throttling, or multi-process session/database coordination.
- PDF reports are generated on demand and are not retained as report history.
- No PDF upload, cloud integrations, SIEM integrations, ingestion API, or AI-generated analysis is implemented.
- No license has been selected for this project yet.

## Roadmap

Planned improvements (not implemented): structured JSONPath locations, broader configurable detectors, persistent report history, email-based password reset, stronger hosted deployment/session controls, and optional PDF previews in the UI.
