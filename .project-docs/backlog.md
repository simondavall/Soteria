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

- Migrate `PasskeySubmit` to MudBlazor once the surrounding Identity pages have been migrated and common patterns have emerged.
- Migrate `ExternalLoginPicker` to MudBlazor after reviewing its usage across the Identity pages.

# Identity

- Review registration password validation so password requirements are derived from the configured ASP.NET Core Identity password options rather than duplicated in the Register page model. Consider validation behaviour, user-facing password guidance, and how to keep client/server validation consistent.

# Enhancements

# Technical Debt

# Nice-to-have
