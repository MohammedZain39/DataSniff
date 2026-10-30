"""Deterministic remediation guidance keyed by DataSniff detector category."""

GUIDANCE = {
    "Private key": {
        "problem": "A private-key marker appears in the scanned text. The pattern alone does not show whether a usable key was exposed.",
        "why": "Private keys can authenticate users, services, or sign data when paired with a trusted identity.",
        "impact": ["Unauthorized access to systems that trust the key.", "Impersonation or unauthorized signing, depending on key use."],
        "immediate": ["Treat the key as exposed if actual key material was logged; revoke or replace associated credentials or certificates.", "Identify systems and services that trusted the key and review relevant access activity."],
        "prevention": ["Keep private keys in a secrets manager or protected key store.", "Redact key material in logging pipelines and review logging changes.", "Add secret scanning to code review and CI/CD."],
        "verification": "Rescan newly generated logs and confirm no private-key markers or key material appear. Confirm replacement credentials are used by dependent services.",
    },
    "Database connection string": {
        "problem": "A database connection URI with a password-like component was detected.",
        "why": "A usable connection credential may grant access to databases and the records or operations they contain.",
        "impact": ["Unauthorized database access.", "Exposure or modification of records, depending on the account's permissions."],
        "immediate": ["Rotate the database password if the value is genuine.", "Remove credentials from logs and review database authentication activity.", "Restrict database connectivity and account privileges."],
        "prevention": ["Load credentials from a secrets manager or protected environment configuration.", "Use structured log redaction for URI user-info fields.", "Add secret scanning to CI/CD."],
        "verification": "Rescan newly generated logs and confirm no credential-bearing database URI is emitted. Test the application with rotated credentials.",
    },
    "API token": {
        "problem": "A value matched a recognizable API key or token pattern.",
        "why": "A valid token may allow actions within the scope and permissions assigned by its issuing service.",
        "impact": ["Unauthorized API actions within the token's scope.", "Abuse of quotas or access to data permitted by the token."],
        "immediate": ["Revoke or rotate the key if genuine.", "Review token scope, permissions, and recent use.", "Search for related exposures in logs and source history."],
        "prevention": ["Store keys in a secrets manager and avoid logging authorization values.", "Use narrow scopes and rotation policies.", "Run secret detection in CI/CD."],
        "verification": "Rescan newly generated logs and confirm the token is absent; verify the replacement key is used and the old key is revoked.",
    },
    "Authorization header": {
        "problem": "An authorization header containing a credential-like value was detected.",
        "why": "Bearer and Basic credentials can convey the authority of the associated user or service.",
        "impact": ["Unauthorized access to endpoints reachable by the credential.", "Exposure of account or service data within granted permissions."],
        "immediate": ["Revoke or rotate the credential if genuine.", "Review access logs for unexpected use.", "Redact authorization headers before they reach persistent logs."],
        "prevention": ["Configure HTTP and application logging middleware to omit authorization headers.", "Add regression checks for sensitive header redaction."],
        "verification": "Generate a representative request, inspect its log output, and rescan to confirm the authorization value is omitted or redacted.",
    },
    "Password-like field": {
        "problem": "A populated password or secret field was detected.",
        "why": "If genuine, a password can provide direct account access, especially when reused across services.",
        "impact": ["Account takeover or unauthorized service access.", "Wider compromise if the password is reused."],
        "immediate": ["Change the password if genuine and check for reuse on other services.", "Remove password logging and review relevant authentication activity."],
        "prevention": ["Never log password values; log only a safe status or correlation identifier.", "Add automated field redaction and regression tests."],
        "verification": "Exercise the relevant authentication path and confirm logs contain no password value; rescan newly generated logs.",
    },
    "Email address": {
        "problem": "An email address was detected and may identify a person.",
        "why": "Personal contact information may be subject to privacy, access, and retention requirements.",
        "impact": ["Unnecessary disclosure of personal information.", "Increased exposure to unwanted contact or targeted phishing."],
        "immediate": ["Determine whether the disclosure is permitted under applicable privacy requirements.", "Restrict access to affected logs and redact addresses where they are not needed."],
        "prevention": ["Use pseudonymous identifiers in operational logs where possible.", "Set retention and access controls for logs containing personal data."],
        "verification": "Review a representative log entry and confirm addresses are removed, masked, or retained only for an approved purpose.",
    },
    "Phone number": {
        "problem": "A phone-number-shaped value was detected; the pattern may be a false positive.",
        "why": "A real phone number is personal contact information and can identify or reach an individual.",
        "impact": ["Unnecessary disclosure of personal contact information.", "Potential unwanted contact or targeted social engineering."],
        "immediate": ["Confirm whether the value is a real phone number and whether logging it is necessary.", "Mask or remove it if it is personal data without a documented need."],
        "prevention": ["Apply field-aware redaction to contact data.", "Restrict access and retention for logs that require contact information."],
        "verification": "Inspect newly generated logs and confirm phone values are masked when not required.",
    },
    "IP address": {
        "problem": "A valid IP address was detected; its sensitivity depends on application and network context.",
        "why": "An address can reveal a device or network location in some environments, but routine IP logging may be operationally necessary.",
        "impact": ["Context-dependent disclosure of network or device information.", "Potential exposure of internal network details if private addresses are shared externally."],
        "immediate": ["Assess whether the address is sensitive in this application's context.", "Do not treat an IP match alone as proof of an incident; mask it where policy requires."],
        "prevention": ["Document IP logging purpose, access, and retention.", "Mask addresses in exported or externally shared logs when appropriate."],
        "verification": "Review the logging policy and sample output to confirm addresses are retained or masked according to that policy.",
    },
}

# Existing detector categories and common equivalent names used by imports.
GUIDANCE["API key"] = GUIDANCE["API token"]
GUIDANCE["Access token"] = GUIDANCE["API token"]
GUIDANCE["Session token"] = {
    "problem": "A session-token-shaped value was detected.",
    "why": "A valid session token can act as a temporary bearer credential for a user or service session.",
    "impact": ["Unauthorized use of a session within the permissions granted to its owner.", "Potential access to private data or actions until the session is invalidated."],
    "immediate": ["Invalidate active sessions if the value is genuine.", "Review session activity and remove token logging.", "Require re-authentication where appropriate."],
    "prevention": ["Redact cookies and session headers in logging middleware.", "Use short-lived sessions and protect log access."],
    "verification": "Create a new session, confirm logs omit session credentials, and rescan representative output.",
}

FALLBACK = {
    "problem": "A value matched a DataSniff pattern for potentially sensitive information.",
    "why": "If the match represents real sensitive information, unnecessary logging may expose it to people or systems with log access.",
    "impact": ["Context-dependent privacy or security exposure."],
    "immediate": ["Validate the finding in the source system without copying sensitive values into additional records.", "Remove or redact the value if it is not required."],
    "prevention": ["Use field-aware redaction and least-privilege log access.", "Add regression checks for the relevant logging path."],
    "verification": "Rescan newly generated logs and confirm the candidate value is no longer emitted in an unmasked form.",
}


def guidance_for(category):
    return GUIDANCE.get(str(category), FALLBACK)
