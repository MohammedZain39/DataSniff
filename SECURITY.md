# Security policy

## Reporting a vulnerability

Please do not publish unredacted logs, credentials, or exploit details in a public issue. If GitHub private vulnerability reporting is enabled for the repository, use that channel. Otherwise, contact the repository maintainer privately and include a concise description, affected version or commit, reproduction steps using synthetic data, and any suggested mitigation. Do not include live credentials or confidential log samples.

The maintainer should acknowledge reports, assess severity and affected versions, coordinate a fix, and publish an advisory after affected users have a reasonable opportunity to update. Do not test against systems or data that you do not own or have permission to assess.

## User guidance

- Treat pattern matches as candidates; DataSniff does not verify that credentials are valid or that exploitation occurred.
- Run hosted mode only behind HTTPS with a private cookie secret and private persistent database storage.
- Keep `.env`, local SQLite files, uploaded logs, and generated reports out of source control.
- Rotate exposed credentials through their authorized issuing system when a genuine exposure is confirmed.

DataSniff is an MVP and does not claim complete detection or security coverage.
