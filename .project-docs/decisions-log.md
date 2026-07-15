This document records significant architectural decisions made during the lifetime of the project together with the reasoning behind them. It serves as a historical record to help future developers understand why important changes were made and to avoid revisiting previously resolved discussions.

2026-07-15

Decision:

Phase 2 will prove both OpenID Connect authentication and OAuth-protected API access.

Soteria will authenticate users through ASP.NET Core Identity and use OpenIddict to issue:

- ID tokens to a server-side reference web application.
- Signed JWT access tokens intended for a distinct reference API resource.
- Refresh tokens so the reference application can renew API access without requiring the user to authenticate again whenever an access token expires.

The reference web application will call the reference API from server-side code. The initial reference client will use implicit consent and one explicit API scope. Tokens will initially contain only the claims required for the reference workflow.

Reason:

Authenticating the reference web application alone would not prove the complete architecture required by Soteria. The intended system must also allow consuming applications to call protected APIs using tokens issued by Soteria.

Using a server-side reference client keeps access tokens out of browser storage and reduces the initial browser-security and CORS surface.

A distinct API audience ensures that access tokens are issued for and accepted by the intended resource server rather than being treated as general-purpose credentials.

Starting with one scope, minimal claims and implicit consent keeps the first implementation explicit and narrow while deferring richer permissions, claims and consent policy until client application and access management are introduced.

