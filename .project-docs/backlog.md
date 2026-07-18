This document records planned enhancements, future ideas and technical debt. Items in this document represent potential future work rather than the current implementation priority. The backlog is intentionally broader than the current development roadmap.

# UI

# Features

- External identity providers.
- Advanced session management.
- Audit history.
- Impersonation.
- Advanced reporting.
- SCIM provisioning.
- Federation.

# Identity UI

- Migrate the external-login workflow to the project UI conventions when external identity providers are introduced.

# Identity

- Review registration password validation so password requirements are derived from the configured ASP.NET Core Identity password options rather than duplicated in the Register page model. Consider validation behaviour, user-facing password guidance, and how to keep client/server validation consistent.

# Enhancements
- Review concurrent access-token renewal within the consuming application. If multiple requests detect an expiring access token simultaneously, consider coordinating refresh operations so only a single refresh-token exchange occurs while other requests await the result.

# Technical Debt

# Nice-to-have
