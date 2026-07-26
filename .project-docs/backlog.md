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
- Make client application registration defaults configurable
- Allow other grant and consent types (explicit, public, etc.)

# Technical Debt
- Remove bootstrapped application creation in OpenIddictInitializer
- Review Entity Framework Core DbContext lifetime within interactive Blazor. Consider replacing the scoped SoteriaDbContext injection with IDbContextFactory<SoteriaDbContext> and creating a fresh DbContext per service operation to prevent failed tracked entity state leaking between independent administrative operations.

# Nice-to-have



# Expantions

## Define consuming-application behaviour when access-token renewal is unavailable

Context

The Reference Web application normally requests the offline_access scope and receives a refresh token. When an access token expires, the application renews it through Soteria’s token endpoint, persists the replacement access and refresh tokens, and retries the protected API request successfully.

During Phase 2 verification, offline_access was temporarily removed to confirm that refresh tokens are issued only when explicitly requested. In this configuration:

authentication succeeds;
an access token is issued;
protected API access succeeds until the access token expires;
no refresh token is available;
the Reference Web application cannot renew the expired access token;
the local Reference Web session is invalidated;
a subsequent interaction starts a new OpenID Connect authorization flow;
Soteria may complete that flow without showing the login page when its own Identity session remains valid.

The current Reference Web UI does not provide a smooth transition when renewal is unavailable. The first API request after expiry returns an authentication failure and clears the displayed result. A later interaction triggers reauthentication and obtains a new access token.

Issue

A broader consuming-application design decision is required for handling expired access tokens when no usable refresh token is available.

The project should define:

whether the application should immediately initiate an OpenID Connect challenge;
whether internal application endpoints should return 401 Unauthorized or directly issue authentication challenges;
which layer owns interactive reauthentication:
token-management infrastructure;
internal server endpoint;
Blazor page or component;
browser-side JavaScript;
how the current route is preserved through reauthentication;
whether the original operation should be retried after an interactive redirect;
how authentication-state changes are reflected in an existing Interactive Server circuit;
what user feedback should be shown when reauthentication is required;
how consuming applications that intentionally omit offline_access should be configured.

Current position

No change is required for Phase 2.

The Reference Web and Reference API behave correctly for the agreed Phase 2 configuration, in which the Reference Web application requests offline_access and uses rolling refresh-token renewal.

This issue concerns the future guidance and architecture for consuming applications rather than Soteria’s provider functionality.

Expected outcome

Establish and document a recommended consuming-application pattern for:

token renewal with refresh tokens;
fallback reauthentication when renewal is unavailable or fails;
API-style 401 responses versus interactive authentication challenges;
clean user experience during token expiry and session recovery.

This can then be implemented in the Reference Web application and used as guidance for future Soteria consumers.

