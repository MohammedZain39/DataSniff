# Contributing

Thanks for helping improve DataSniff. Keep changes small and focused, preserve the local-first workflow, and do not add external transmission of scanned log contents.

## Development

1. Create a Python 3.10+ environment.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Run the app with `python -m streamlit run app.py`.
4. Run tests with `python -m unittest discover -s tests -v`.

Use synthetic logs and credentials in tests. Do not commit `.env` files, SQLite databases, uploaded logs, generated reports, or real credentials. Keep detector severity and report remediation deterministic and documented. Update the README when user-visible behavior or configuration changes.

## Pull requests

Describe the behavior change, security/privacy implications, and tests run. Include screenshots for meaningful UI changes when available. Do not add a license or change licensing terms without maintainer direction.
